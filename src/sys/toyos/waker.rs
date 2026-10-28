use crate::sys::Selector;
use crate::Token;
use std::io;
use std::os::toyos::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use toyos_abi::RawHandle;

/// An event whose wait side the selector watches: a signal wakes it, and the
/// selector takes it as it reports the waker's token. Wakes before that are
/// one.
#[derive(Debug)]
pub struct Waker {
    selector: Selector,
    wait: OwnedHandle,
    signal: OwnedHandle,
}

impl Waker {
    pub fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
        let event = toyos_abi::syscall::event_create()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
        // SAFETY: the kernel installed both sides for this call, and this
        // waker is the only thing that answers for them.
        let (wait, signal) = unsafe { (OwnedHandle::from_raw_handle(event.wait.0), OwnedHandle::from_raw_handle(event.signal.0)) };
        let selector = selector.try_clone()?;
        selector.register_waker(RawHandle(wait.as_raw_handle()), token)?;
        Ok(Waker { selector, wait, signal })
    }

    pub fn wake(&self) -> io::Result<()> {
        // The wait side is this waker's own, so the signal is never refused.
        toyos_abi::syscall::event_signal(RawHandle(self.signal.as_raw_handle()))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        // Out of the selector before the wait side closes, so no later select
        // watches a number this process no longer holds.
        let _ = self.selector.deregister_handle(RawHandle(self.wait.as_raw_handle()));
    }
}
