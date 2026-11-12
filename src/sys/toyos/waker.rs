use crate::sys::Selector;
use crate::Token;
use std::io;

use super::selector::OwnedEvent;

/// An event whose wait side the selector watches: a signal wakes it, and the
/// selector takes it as it reports the waker's token. Wakes before that are
/// one.
#[derive(Debug)]
pub struct Waker {
    selector: Selector,
    event: OwnedEvent,
}

impl Waker {
    pub fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
        let event = OwnedEvent::new()?;
        let selector = selector.try_clone()?;
        selector.register_waker(event.wait(), token)?;
        Ok(Waker { selector, event })
    }

    pub fn wake(&self) -> io::Result<()> {
        self.event.signal()
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        // Out of the selector before the wait side closes, so no later select
        // watches a number this process no longer holds.
        let _ = self.selector.deregister_handle(self.event.wait());
    }
}
