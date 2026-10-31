use kcm::Listener;
use std::{
    io::Write,
    net::{TcpListener, TcpStream},
};

#[test]
fn messages_are_split_at_content_length() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (server, _) = tcp.accept().unwrap();

    let listener = Listener::new().unwrap();
    listener.attach(&server).unwrap();

    let a = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let b = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    client.write_all(format!("{a}{b}").as_bytes()).unwrap();

    let mut buf = [0; 1024];
    for msg in [a, b] {
        let len = listener.recv(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(&buf[..len]).unwrap(), msg);
    }
}
