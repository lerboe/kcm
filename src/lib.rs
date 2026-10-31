use beeper::{MessageBuffer, http1};
use std::{
    io,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};
use xbpf::libbpf_rs::skel::{OpenSkel, SkelBuilder};

xbpf::include_bpf!("listener");

const AF_KCM: libc::c_int = 41;
const KCMPROTO_CONNECTED: libc::c_int = 0;
const SIOCKCMATTACH: libc::c_ulong = 0x89E0;

#[repr(C)]
struct KcmAttach {
    fd: libc::c_int,
    bpf_fd: libc::c_int,
}

pub struct Listener {
    sock: OwnedFd,
    prog: OwnedFd,
    _parser: http1::AttachedParser,
}

impl Listener {
    pub fn new() -> io::Result<Listener> {
        let sock = unsafe {
            libc::socket(
                AF_KCM,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                KCMPROTO_CONNECTED,
            )
        };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };

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
            sock,
            prog,
            _parser: parser,
        })
    }

    pub fn attach<F: AsFd>(&self, tcp: F) -> io::Result<()> {
        let info = KcmAttach {
            fd: tcp.as_fd().as_raw_fd(),
            bpf_fd: self.prog.as_raw_fd(),
        };
        let res = unsafe { libc::ioctl(self.sock.as_raw_fd(), SIOCKCMATTACH as _, &info) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(len as usize)
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sock.as_fd()
    }
}
