use crate::sys::Selector;
use crate::Token;
use std::io;
use std::os::toyos::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use toyos_abi::RawHandle;

/// A pipe whose read end the selector watches: a byte written wakes it.
#[derive(Debug)]
pub struct Waker {
    selector: Selector,
    read: OwnedHandle,
    write: OwnedHandle,
}

impl Waker {
    pub fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
        let pipe = toyos_abi::syscall::pipe()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
        // SAFETY: the kernel installed both ends for this call, and this
        // waker is the only thing that answers for them.
        let (read, write) = unsafe { (OwnedHandle::from_raw_handle(pipe.read.0), OwnedHandle::from_raw_handle(pipe.write.0)) };
        let selector = selector.try_clone()?;
        selector.register_handle(RawHandle(read.as_raw_handle()), token, crate::Interest::READABLE)?;
        Ok(Waker { selector, read, write })
    }

    pub fn wake(&self) -> io::Result<()> {
        let _ = toyos_abi::syscall::write_nonblock(RawHandle(self.write.as_raw_handle()), &[1]);
        Ok(())
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        // Out of the selector before the read end closes, so no later select
        // watches a number this process no longer holds.
        let _ = self.selector.deregister_handle(RawHandle(self.read.as_raw_handle()));
    }
}
