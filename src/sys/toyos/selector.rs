use std::io;
use std::os::toyos::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{Interest, Token};
use toyos_abi::RawHandle;
use toyos_abi::inbox::*;

static NEXT_SELECTOR_ID: AtomicUsize = AtomicUsize::new(1);

/// What a registration's handle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Handle,
    /// A stream's bell: watched for reading and reported as writable
    /// (`std::os::toyos::net`).
    Bell,
    /// A [`Waker`](super::Waker)'s event: watched for reading, and taken as
    /// its token is reported, since a watch observes and takes nothing.
    Waker,
}

/// A ToyOS inbox: submission and completion rings mapped into userspace.
struct Inbox {
    handle: OwnedHandle,
    base: *mut u8,
    submission_ring_size: u32,
    completion_ring_size: u32,
}

// Inbox is Send+Sync because:
// - handle is an opaque kernel handle
// - base points to process-local shared memory, accessed under Mutex
unsafe impl Send for Inbox {}
unsafe impl Sync for Inbox {}

impl Inbox {
    fn new(depth: u32) -> io::Result<Self> {
        // The inbox owns its page and the kernel maps it, so there is no second
        // handle and no second lifetime for a mapping only this inbox uses.
        let (handle, base) = unsafe { toyos_abi::syscall::inbox_setup(depth) }
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
        // Read the layout from offset 0
        let layout = unsafe { &*(base as *const RingLayout) };
        // SAFETY: the kernel installed the handle for this call, and this
        // inbox is the only thing that answers for it.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        Ok(Self {
            handle,
            base,
            submission_ring_size: layout.submission_ring_size,
            completion_ring_size: layout.completion_ring_size,
        })
    }

    fn submission_header(&self) -> &RingHeader {
        unsafe { &*(self.base.add(SUBMISSION_RING_OFF as usize) as *const RingHeader) }
    }

    fn completion_header(&self) -> &RingHeader {
        unsafe { &*(self.base.add(COMPLETION_RING_OFF as usize) as *const RingHeader) }
    }

    fn submission_at_mut(&self, index: u32) -> &mut Submission {
        unsafe {
            &mut *(self.base.add(SUBMISSIONS_OFF as usize + index as usize * core::mem::size_of::<Submission>()) as *mut Submission)
        }
    }

    fn completion_at(&self, index: u32) -> &Completion {
        unsafe {
            &*(self.base.add(COMPLETION_RING_OFF as usize + 16 + index as usize * core::mem::size_of::<Completion>()) as *const Completion)
        }
    }

    /// Queue a single submission by writing it into the submission ring.
    fn queue(&self, submission: &Submission) {
        let ring = self.submission_header();
        let tail = ring.tail.load(Ordering::Acquire);
        let idx = tail & (self.submission_ring_size - 1);
        *self.submission_at_mut(idx) = *submission;
        ring.tail.store(tail.wrapping_add(1), Ordering::Release);
    }

    /// Hand every queued submission to the kernel and optionally wait for
    /// completions.
    fn submit(&self, to_submit: u32, min_complete: u32, timeout_nanos: u64) -> io::Result<u32> {
        toyos_abi::syscall::inbox_submit(RawHandle(self.handle.as_raw_handle()), to_submit, min_complete, timeout_nanos)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))
    }

    /// Peek at the next completion without consuming it.
    fn peek_completion(&self) -> Option<Completion> {
        let ring = self.completion_header();
        let head = ring.head.load(Ordering::Acquire);
        let tail = ring.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let idx = head & (self.completion_ring_size - 1);
        Some(*self.completion_at(idx))
    }

    /// Advance the completion ring head (consume one completion).
    fn advance_completion(&self) {
        let ring = self.completion_header();
        let head = ring.head.load(Ordering::Acquire);
        ring.head.store(head.wrapping_add(1), Ordering::Release);
    }

    /// Count submissions queued but not yet handed to the kernel.
    fn pending_submissions(&self) -> u32 {
        let ring = self.submission_header();
        let head = ring.head.load(Ordering::Acquire);
        let tail = ring.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

/// A registration, whose watch is armed again at every select.
#[derive(Clone, Copy, Debug)]
struct Registration {
    handle: RawHandle,
    interest: Interest,
    token: Token,
    kind: Kind,
    /// Its watches' token: new at each register and reregister, so a
    /// completion of a watch armed before either names no registration.
    generation: u64,
}

#[derive(Debug)]
struct SelectorInner {
    registrations: Vec<Registration>,
    /// The next registration's generation.
    next: u64,
}

impl SelectorInner {
    fn add(&mut self, handle: RawHandle, interest: Interest, token: Token, kind: Kind) {
        let generation = self.renew();
        self.registrations.push(Registration { handle, interest, token, kind, generation });
    }

    fn renew(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
}

#[derive(Clone)]
pub struct Event {
    token: usize,
    flags: u8,
}

const FLAG_READABLE: u8 = 1;
const FLAG_WRITABLE: u8 = 2;

pub type Events = Vec<Event>;

#[derive(Debug)]
pub struct Selector {
    inner: Arc<Mutex<SelectorInner>>,
    inbox: Arc<Inbox>,
    id: usize,
}

// Inbox is behind Arc<Mutex>, safe to debug-print the outer struct
impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox").field("handle", &self.handle).finish()
    }
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        let inbox = Inbox::new(64)?;
        Ok(Selector {
            inner: Arc::new(Mutex::new(SelectorInner { registrations: Vec::new(), next: 0 })),
            inbox: Arc::new(inbox),
            id: NEXT_SELECTOR_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn try_clone(&self) -> io::Result<Selector> {
        Ok(Selector {
            inner: Arc::clone(&self.inner),
            inbox: Arc::clone(&self.inbox),
            id: self.id,
        })
    }

    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        // Re-arm a watch for every registration
        let regs: Vec<Registration> = self.inner.lock().unwrap().registrations.clone();

        for reg in &regs {
            let mut submission = Submission::default();
            submission.op = OP_WATCH;
            submission.handle = reg.handle;
            submission.op_flags = interests_to_flags(reg.interest);
            submission.token = reg.generation;
            self.inbox.queue(&submission);
        }

        let pending = self.inbox.pending_submissions();
        let timeout_nanos = match timeout {
            None => u64::MAX,
            Some(d) => d.as_nanos() as u64,
        };

        // Hand over every queued submission and wait for at least 1 completion
        let min_complete = if regs.is_empty() { 0 } else { 1 };
        self.inbox.submit(pending, min_complete, timeout_nanos)?;

        // Drained under the lock `deregister_handle` takes: a completion whose
        // registration is gone, or was made again, is dropped, so no event is
        // reported for a handle once its deregister has returned.
        let inner = self.inner.lock().unwrap();
        while let Some(completion) = self.inbox.peek_completion() {
            let reg = inner.registrations.iter().find(|r| r.generation == completion.token);
            if let (Some(reg), 1..) = (reg, completion.result) {
                let flags = match reg.kind {
                    Kind::Bell => FLAG_WRITABLE,
                    Kind::Handle | Kind::Waker => poll_result_to_flags(completion.result as u32),
                };
                if reg.kind == Kind::Waker {
                    // Taken before the wake is reported, so one raised after
                    // this is still pending at the next select.
                    let _ = toyos_abi::syscall::event_take(reg.handle);
                }
                let token = reg.token.0;
                if let Some(existing) = events.iter_mut().find(|e| e.token == token) {
                    existing.flags |= flags;
                } else {
                    events.push(Event { token, flags });
                }
            }
            self.inbox.advance_completion();
        }

        Ok(())
    }

    pub fn register_handle(&self, handle: RawHandle, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.lock().unwrap().add(handle, interest, token, Kind::Handle);
        Ok(())
    }

    /// A stream's bell: watched for reading, and its event writable.
    pub fn register_bell(&self, bell: RawHandle, token: Token) -> io::Result<()> {
        self.inner.lock().unwrap().add(bell, Interest::READABLE, token, Kind::Bell);
        Ok(())
    }

    /// A [`Waker`](super::Waker)'s event, taken as its token is reported.
    pub fn register_waker(&self, event: RawHandle, token: Token) -> io::Result<()> {
        self.inner.lock().unwrap().add(event, Interest::READABLE, token, Kind::Waker);
        Ok(())
    }

    pub fn reregister_handle(&self, handle: RawHandle, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let generation = inner.renew();
        match inner.registrations.iter_mut().find(|r| r.handle == handle) {
            Some(reg) => {
                reg.interest = interest;
                reg.token = token;
                reg.generation = generation;
            }
            None => inner.registrations.push(Registration { handle, interest, token, kind: Kind::Handle, generation }),
        }
        Ok(())
    }

    pub fn deregister_handle(&self, handle: RawHandle) -> io::Result<()> {
        self.inner.lock().unwrap().registrations.retain(|r| r.handle != handle);
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn id(&self) -> usize {
        self.id
    }
}

fn interests_to_flags(interest: Interest) -> u32 {
    let mut flags = 0;
    if interest.is_readable() { flags |= READABLE; }
    if interest.is_writable() { flags |= WRITABLE; }
    flags
}

fn poll_result_to_flags(result: u32) -> u8 {
    let mut flags = 0u8;
    if result & READABLE != 0 { flags |= FLAG_READABLE; }
    if result & WRITABLE != 0 { flags |= FLAG_WRITABLE; }
    // If we got a result but no specific flags, assume readable
    if flags == 0 { flags = FLAG_READABLE; }
    flags
}

pub mod event {
    use super::*;
    use std::fmt;

    pub fn token(event: &Event) -> Token {
        Token(event.token)
    }

    pub fn is_readable(event: &Event) -> bool {
        event.flags & FLAG_READABLE != 0
    }

    pub fn is_writable(event: &Event) -> bool {
        event.flags & FLAG_WRITABLE != 0
    }

    pub fn is_error(_event: &Event) -> bool {
        false
    }

    pub fn is_read_closed(_event: &Event) -> bool {
        false
    }

    pub fn is_write_closed(_event: &Event) -> bool {
        false
    }

    pub fn is_priority(_event: &Event) -> bool {
        false
    }

    pub fn is_aio(_event: &Event) -> bool {
        false
    }

    pub fn is_lio(_event: &Event) -> bool {
        false
    }

    pub fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        write!(
            f,
            "Event {{ token: {}, readable: {}, writable: {} }}",
            event.token,
            event.flags & FLAG_READABLE != 0,
            event.flags & FLAG_WRITABLE != 0
        )
    }
}
