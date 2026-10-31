use kcm::Listener;
use std::{
    io::Write,
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

fn attached_pair(listener: &Listener) -> (TcpStream, TcpStream) {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (server, _) = tcp.accept().unwrap();
    listener.attach(&server).unwrap();

    (client, server)
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn messages_are_split_at_content_length() {
    let listener = Listener::new().unwrap();
    let (mut client, _server) = attached_pair(&listener);

    let a = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let b = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    client.write_all(format!("{a}{b}").as_bytes()).unwrap();

    let mut buf = [0; 1024];
    for msg in [a, b] {
        let len = listener.recv(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(&buf[..len]).unwrap(), msg);
    }
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn http2_frames_are_split_at_their_length() {
    let listener = Listener::new().unwrap();
    let (mut client, _server) = attached_pair(&listener);

    let preface: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    let ping: &[u8] = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00pingping";
    client.write_all(&[preface, settings, ping].concat()).unwrap();

    let mut buf = [0; 1024];
    for msg in [preface, settings, ping] {
        let len = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], msg);
    }
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn unknown_protocols_are_rejected() {
    let listener = Listener::new().unwrap();
    let (mut client, server) = attached_pair(&listener);
    client.write_all(b"\x16\x03\x01\x00\x05hello").unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let err = loop {
        if let Some(err) = server.take_error().unwrap() {
            break err;
        }
        assert!(Instant::now() < deadline, "no error");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(err.raw_os_error(), Some(libc::EPROTO));
}
