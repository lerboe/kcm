use beeper::{MessageBuffer, http1};
use std::{
    future::Future,
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf, unix::AsyncFd},
    net::{TcpListener, ToSocketAddrs},
};
use xbpf::libbpf_rs::skel::{OpenSkel, SkelBuilder};

xbpf::include_bpf!("listener");

const AF_KCM: libc::c_int = 41;
const KCMPROTO_CONNECTED: libc::c_int = 0;
const SIOCKCMATTACH: libc::c_ulong = 0x89E0;

// KCM queues a whole message before it sends any of it, so a write must fit
// into the send buffer
const MAX_WRITE_LEN: usize = 16 * 1024;

const MIN_RX_LEN: usize = 16 * 1024;

#[repr(C)]
struct KcmAttach {
    fd: libc::c_int,
    bpf_fd: libc::c_int,
}

pub struct Listener {
    tcp: TcpListener,
    prog: OwnedFd,
    parser: Arc<http1::AttachedParser>,
}

impl Listener {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Listener> {
        let tcp = TcpListener::bind(addr).await?;

        let mut obj = MaybeUninit::uninit();
        let skel = ListenerSkelBuilder::default()
            .open(&mut obj)
            .and_then(OpenSkel::load)
            .map_err(io::Error::other)?;
        let prog = skel.progs.msg_len.as_fd().try_clone_to_owned()?;

        let mut parser = http1::Parser::new();
        let mid = parser
            .capture_hdr("content-length")
            .map_err(io::Error::other)?;
        assert_eq!(u8::from(mid), 0, "CONTENT_LENGTH_MID of listener.bpf.c");
        let parser = parser
            .parse_fn("parse_http1", MessageBuffer::DynPtr)
            .attach(prog.as_raw_fd())
            .map_err(io::Error::other)?;

        Ok(Listener {
            tcp,
            prog,
            parser: Arc::new(parser),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    // Every connection gets a multiplexor of its own: KCM sends a message on
    // any of the sockets attached to a multiplexor, and does not tell which one
    // a received message came from.
    pub async fn accept(&self) -> io::Result<(Stream, SocketAddr)> {
        let (tcp, addr) = self.tcp.accept().await?;
        let tcp = tcp.into_std()?;

        let kcm = unsafe {
            libc::socket(
                AF_KCM,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                KCMPROTO_CONNECTED,
            )
        };
        if kcm < 0 {
            return Err(io::Error::last_os_error());
        }
        let kcm = unsafe { OwnedFd::from_raw_fd(kcm) };

        let info = KcmAttach {
            fd: tcp.as_raw_fd(),
            bpf_fd: self.prog.as_raw_fd(),
        };
        if unsafe { libc::ioctl(kcm.as_raw_fd(), SIOCKCMATTACH as _, &info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // KCM posts its errors, and the hangup of the peer, on the TCP socket
        // and not on the multiplexor, which would otherwise wait forever
        let interest = Interest::READABLE | Interest::ERROR;
        // SAFETY: the AsyncFd owns the socket, so the fd stays open and unchanged
        let tcp = unsafe { AsyncFd::register_with_interest(tcp, interest)? };
        let closed = Box::pin(async move {
            loop {
                let Ok(mut guard) = tcp.ready(interest).await else {
                    return;
                };
                let ready = guard.ready();
                if ready.is_read_closed() || ready.is_error() {
                    return;
                }
                guard.clear_ready();
            }
        });

        // SAFETY: as above
        let kcm = unsafe { AsyncFd::register(kcm)? };
        let stream = Stream {
            kcm,
            _parser: self.parser.clone(),
            closed: Some(closed),
            rx: Vec::new(),
            rx_pos: 0,
        };

        Ok((stream, addr))
    }
}

pub struct Stream {
    kcm: AsyncFd<OwnedFd>,
    // the program of an attached socket calls into the parser, so it must stay
    // attached for as long as the socket is, even after the listener is gone
    _parser: Arc<http1::AttachedParser>,
    closed: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    rx: Vec<u8>,
    rx_pos: usize,
}

impl Stream {
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(closed) = &mut self.closed else {
            return true;
        };
        if closed.as_mut().poll(cx).is_pending() {
            return false;
        }

        self.closed = None;
        true
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.rx_pos == this.rx.len() {
            let Poll::Ready(guard) = this.kcm.poll_read_ready(cx) else {
                if this.poll_closed(cx) {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Pending;
            };
            let mut guard = guard?;

            this.rx_pos = 0;
            match guard.try_io(|kcm| recv_msg(kcm.as_raw_fd(), &mut this.rx)) {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }

        let len = buf.remaining().min(this.rx.len() - this.rx_pos);
        buf.put_slice(&this.rx[this.rx_pos..this.rx_pos + len]);
        this.rx_pos += len;

        Poll::Ready(Ok(()))
    }
}

fn recv(fd: RawFd, buf: &mut [u8], flags: libc::c_int) -> io::Result<usize> {
    let len = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(len as usize)
}

// KCM drops the rest of a message that does not fit into the buffer of a read,
// even for SOCK_SEQPACKET, so the message is peeked at with a growing buffer
// until it fits
fn recv_msg(fd: RawFd, msg: &mut Vec<u8>) -> io::Result<()> {
    msg.resize(msg.capacity().max(MIN_RX_LEN), 0);
    let len = recv_whole(fd, msg);
    msg.truncate(*len.as_ref().unwrap_or(&0));

    len.map(drop)
}

fn recv_whole(fd: RawFd, msg: &mut Vec<u8>) -> io::Result<usize> {
    while recv(fd, msg, libc::MSG_DONTWAIT | libc::MSG_PEEK)? == msg.len() {
        msg.resize(msg.len() * 2, 0);
    }

    recv(fd, msg, libc::MSG_DONTWAIT)
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let buf = &buf[..buf.len().min(MAX_WRITE_LEN)];
        loop {
            if this.closed.is_none() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let Poll::Ready(guard) = this.kcm.poll_write_ready(cx) else {
                if this.poll_closed(cx) {
                    continue;
                }
                return Poll::Pending;
            };
            let mut guard = guard?;

            // a SOCK_SEQPACKET multiplexor only sends a message once it ends
            let res = guard.try_io(|kcm| {
                let len = unsafe {
                    libc::send(
                        kcm.as_raw_fd(),
                        buf.as_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT | libc::MSG_EOR | libc::MSG_NOSIGNAL,
                    )
                };
                if len < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(len as usize)
            });

            match res {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    // ponytail: closing a multiplexor drops the messages it has not sent yet,
    // so a response the TCP send buffer cannot take at once can be cut. Wait
    // for the TCP send queue (SIOCOUTQ) to drain before closing to avoid it.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
