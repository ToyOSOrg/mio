use std::io;
use std::os::toyos::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// The token the selector's own watch on [`SelectorInner::changed`]'s event
/// carries: no registration's generation, which starts at 1.
const CHANGED: u64 = 0;

#[derive(Debug)]
struct SelectorInner {
    registrations: Vec<Registration>,
    /// The next registration's generation.
    next: u64,
    /// Watched by every select, and signalled when the registrations change
    /// while one waits on its copy of them, so that it arms them again: a
    /// ring has one submitter, so the changing thread cannot arm a watch.
    changed: OwnedEvent,
    /// Whether a select is between taking its copy of the registrations and
    /// draining what it waited for.
    selecting: bool,
    /// Whether `changed` has been signalled since a select last took it.
    signalled: bool,
}

/// An event's two sides, both its holder's: the selector's change, and a
/// [`Waker`](super::Waker)'s wake.
#[derive(Debug)]
pub(super) struct OwnedEvent {
    wait: OwnedHandle,
    signal: OwnedHandle,
}

impl OwnedEvent {
    pub(super) fn new() -> io::Result<OwnedEvent> {
        let event = toyos_abi::syscall::event_create().map_err(refused)?;
        // SAFETY: the kernel installed both sides for this call, and this
        // event is the only thing that answers for them.
        unsafe {
            Ok(OwnedEvent {
                wait: OwnedHandle::from_raw_handle(event.wait.0),
                signal: OwnedHandle::from_raw_handle(event.signal.0),
            })
        }
    }

    /// The side a watch is armed on.
    pub(super) fn wait(&self) -> RawHandle {
        RawHandle(self.wait.as_raw_handle())
    }

    /// Raise it. Never refused while this holds the wait side.
    pub(super) fn signal(&self) -> io::Result<()> {
        toyos_abi::syscall::event_signal(RawHandle(self.signal.as_raw_handle())).map_err(refused)
    }

    /// Take a pending signal. Never refused while one is pending.
    fn take(&self) -> io::Result<()> {
        toyos_abi::syscall::event_take(self.wait()).map_err(refused)
    }
}

fn refused(e: toyos_abi::syscall::SyscallError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e}"))
}

impl SelectorInner {
    fn add(&mut self, handle: RawHandle, interest: Interest, token: Token, kind: Kind) -> io::Result<()> {
        self.change()?;
        let generation = self.renew();
        self.registrations.push(Registration { handle, interest, token, kind, generation });
        Ok(())
    }

    fn renew(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Wake a select waiting on its copy of the registrations, which are
    /// about to change.
    fn change(&mut self) -> io::Result<()> {
        if self.selecting && !self.signalled {
            self.changed.signal()?;
            self.signalled = true;
        }
        Ok(())
    }

    /// The registrations, copied for a select about to wait on them.
    fn to_watch(&mut self) -> io::Result<Vec<Registration>> {
        if self.signalled {
            // Taken with the copy below, under the lock every change takes:
            // a signal after this one is a change the copy does not hold.
            self.changed.take()?;
            self.signalled = false;
        }
        self.selecting = true;
        Ok(self.registrations.clone())
    }
}

#[derive(Clone)]
pub struct Event {
    token: usize,
    flags: u8,
}

const FLAG_READABLE: u8 = 1;
const FLAG_WRITABLE: u8 = 2;
const FLAG_ERROR: u8 = 4;

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
        let changed = OwnedEvent::new()?;
        let inner = SelectorInner { registrations: Vec::new(), next: 0, changed, selecting: false, signalled: false };
        Ok(Selector {
            inner: Arc::new(Mutex::new(inner)),
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
        // A timeout past what an `Instant` holds waits for good, as `None` does.
        let until = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        loop {
            let left = match until {
                None => u64::MAX,
                // `u64::MAX` is the kernel's "for good", so a timeout stops
                // one short of it.
                Some(until) => {
                    let left = until.saturating_duration_since(Instant::now()).as_nanos();
                    u64::try_from(left).map_or(u64::MAX - 1, |left| left.min(u64::MAX - 1))
                }
            };
            self.wait(events, left)?;
            // Nothing to report, as after a change to the registrations: arm
            // them again, and wait out the timeout. A refused watch is
            // reported, and its registration ends, so none is armed again.
            if !events.is_empty() || until.is_some_and(|until| Instant::now() >= until) {
                return Ok(());
            }
        }
    }

    /// Arm a watch for every registration and one for a change to them, wait
    /// up to `timeout_nanos` for any to answer, and add the registrations'
    /// answers to `events`.
    fn wait(&self, events: &mut Events, timeout_nanos: u64) -> io::Result<()> {
        let (regs, changed) = {
            let mut inner = self.inner.lock().unwrap();
            (inner.to_watch()?, inner.changed.wait())
        };
        for reg in &regs {
            self.inbox.queue(&watch(reg.handle, interests_to_flags(reg.interest), reg.generation));
        }
        self.inbox.queue(&watch(changed, READABLE, CHANGED));

        // The watch on `changed` is always one to wait for.
        let pending = self.inbox.pending_submissions();
        let submitted = self.inbox.submit(pending, 1, timeout_nanos);

        // Drained under the lock `deregister_handle` takes: a completion whose
        // registration is gone, or was made again, is dropped, so no event is
        // reported for a handle once its deregister has returned.
        let mut inner = self.inner.lock().unwrap();
        inner.selecting = false;
        submitted?;
        let mut refused = None;
        let mut ended = Vec::new();
        while let Some(completion) = self.inbox.peek_completion() {
            self.inbox.advance_completion();
            if completion.token == CHANGED {
                if completion.result < 1 {
                    refused = Some(refusal(completion.result));
                }
                continue;
            }
            let Some(reg) = inner.registrations.iter().find(|r| r.generation == completion.token) else {
                continue;
            };
            let flags = match (completion.result, reg.kind) {
                // The kernel refuses a watch that can never fire, one on a
                // handle closed under it among them. The registration ends,
                // reported once as an error in the directions it reports, so
                // whoever reads or writes the source meets the refusal.
                (..=0, kind) => {
                    ended.push(reg.generation);
                    FLAG_ERROR | reported(kind, reg.interest)
                }
                (_, Kind::Bell) => FLAG_WRITABLE,
                (result, Kind::Handle | Kind::Waker) => poll_result_to_flags(result as u32),
            };
            if reg.kind == Kind::Waker && completion.result > 0 {
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
        inner.registrations.retain(|r| !ended.contains(&r.generation));
        match refused {
            None => Ok(()),
            Some(why) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("the kernel refused to watch the selector's own event: {why}"),
            )),
        }
    }

    pub fn register_handle(&self, handle: RawHandle, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.lock().unwrap().add(handle, interest, token, Kind::Handle)
    }

    /// A stream's bell: watched for reading, and its event writable.
    pub fn register_bell(&self, bell: RawHandle, token: Token) -> io::Result<()> {
        self.inner.lock().unwrap().add(bell, Interest::READABLE, token, Kind::Bell)
    }

    /// A [`Waker`](super::Waker)'s event, taken as its token is reported.
    pub fn register_waker(&self, event: RawHandle, token: Token) -> io::Result<()> {
        self.inner.lock().unwrap().add(event, Interest::READABLE, token, Kind::Waker)
    }

    pub fn reregister_handle(&self, handle: RawHandle, token: Token, interest: Interest) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.change()?;
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

fn watch(handle: RawHandle, op_flags: u32, token: u64) -> Submission {
    let mut submission = Submission::default();
    submission.op = OP_WATCH;
    submission.handle = handle;
    submission.op_flags = op_flags;
    submission.token = token;
    submission
}

fn interests_to_flags(interest: Interest) -> u32 {
    let mut flags = 0;
    if interest.is_readable() { flags |= READABLE; }
    if interest.is_writable() { flags |= WRITABLE; }
    flags
}

/// The directions a registration of `kind` reports readiness in.
fn reported(kind: Kind, interest: Interest) -> u8 {
    match kind {
        Kind::Bell => FLAG_WRITABLE,
        Kind::Waker => FLAG_READABLE,
        Kind::Handle => {
            let mut flags = 0;
            if interest.is_readable() { flags |= FLAG_READABLE; }
            if interest.is_writable() { flags |= FLAG_WRITABLE; }
            flags
        }
    }
}

/// A refused watch's result, which the kernel writes as its error's number
/// negated.
fn refusal(result: i32) -> toyos_abi::syscall::SyscallError {
    use toyos_abi::syscall::SyscallError;
    SyscallError::from_u64(u64::MAX - u64::from(result.unsigned_abs())).unwrap_or(SyscallError::Unknown)
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

    pub fn is_error(event: &Event) -> bool {
        event.flags & FLAG_ERROR != 0
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
            "Event {{ token: {}, readable: {}, writable: {}, error: {} }}",
            event.token,
            event.flags & FLAG_READABLE != 0,
            event.flags & FLAG_WRITABLE != 0,
            event.flags & FLAG_ERROR != 0
        )
    }
}
