use std::fmt;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{self, Shutdown, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::toyos::net::TcpStreamExt;

use crate::{event, Interest, Registry, Token};
use toyos_abi::RawHandle;

/// A non-blocking TCP stream: std's, which on ToyOS is a region and a
/// connection to netstack.
///
/// Its readiness is two doorbells: its receive bell, which netstack rings for
/// bytes or their end, and its send bell, which netstack rings for room or a
/// failure. Each says "look", so a source is read and written until
/// `WouldBlock`, which arms the want the next ring answers; a registration
/// arms each named want and rings netstack if its direction is ready already,
/// so the first event comes.
pub struct TcpStream {
    inner: net::TcpStream,
}

impl TcpStream {
    /// A connect, answered once netstack has the handshake's answer.
    pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
        let inner = net::TcpStream::connect(addr)?;
        inner.set_nonblocking(true)?;
        Ok(TcpStream { inner })
    }

    /// A stream std holds; the caller sets it nonblocking.
    pub fn from_std(stream: net::TcpStream) -> TcpStream {
        TcpStream { inner: stream }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
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

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    pub fn try_io<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> io::Result<T>,
    {
        f()
    }

    fn receive_bell(&self) -> io::Result<RawHandle> {
        Ok(RawHandle(self.inner.receive_bell()?))
    }

    fn bell(&self) -> io::Result<RawHandle> {
        Ok(RawHandle(self.inner.bell()?))
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&self.inner).read_vectored(bufs)
    }
}

impl Read for &'_ TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&self.inner).read_vectored(bufs)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.inner).write(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.inner).write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &'_ TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.inner).write(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.inner).write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl event::Source for TcpStream {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        let sel = registry.selector();
        if interests.is_readable() {
            sel.register_handle(self.receive_bell()?, token, Interest::READABLE)?;
        }
        if interests.is_writable() {
            sel.register_bell(self.bell()?, token)?;
        }
        self.inner.register(interests.is_readable(), interests.is_writable())
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.deregister(registry)?;
        self.register(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        let sel = registry.selector();
        sel.deregister_handle(self.receive_bell()?)?;
        sel.deregister_handle(self.bell()?)
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for TcpStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl IntoRawFd for TcpStream {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl FromRawFd for TcpStream {
    /// The caller is responsible for ensuring that the stream is in
    /// non-blocking mode.
    unsafe fn from_raw_fd(fd: RawFd) -> TcpStream {
        TcpStream::from_std(unsafe { FromRawFd::from_raw_fd(fd) })
    }
}

impl From<TcpStream> for OwnedFd {
    fn from(stream: TcpStream) -> Self {
        stream.inner.into()
    }
}

impl From<OwnedFd> for TcpStream {
    fn from(fd: OwnedFd) -> Self {
        TcpStream::from_std(net::TcpStream::from(fd))
    }
}
