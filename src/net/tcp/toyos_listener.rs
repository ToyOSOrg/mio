use std::fmt;
use std::io;
use std::net::{self, SocketAddr};
use std::os::toyos::io::AsRawHandle;

use crate::net::TcpStream;
use crate::{event, Interest, Registry, Token};
use toyos_abi::RawHandle;

/// A non-blocking TCP listener: std's, whose handle is its holder's bell.
/// netstack rings the bell while a connection waits and this holder has not
/// asked since its last ring, so a readable event is answered by accepting
/// until `WouldBlock`, and another holder may take a connection first.
pub struct TcpListener {
    inner: net::TcpListener,
}

impl TcpListener {
    /// Bind a TCP listener to the given address.
    pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
        let inner = net::TcpListener::bind(addr)?;
        inner.set_nonblocking(true)?;
        Ok(TcpListener { inner })
    }

    /// Accept a new connection: std's, which asks netstack only once the bell
    /// rang.
    ///
    /// Returns `WouldBlock` if no connections are pending.
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.inner.accept()?;
        stream.set_nonblocking(true)?;
        Ok((TcpStream::from_std(stream), peer))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    fn bell(&self) -> RawHandle {
        RawHandle(self.inner.as_raw_handle())
    }
}

impl event::Source for TcpListener {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        let _ = interests;
        registry.selector().register_handle(self.bell(), token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        let _ = interests;
        registry.selector().reregister_handle(self.bell(), token, Interest::READABLE)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        registry.selector().deregister_handle(self.bell())
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}
