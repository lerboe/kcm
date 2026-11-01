use kcm::{Listener, Stream};
use std::{io::Write, net::TcpStream, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};

async fn connect() -> (TcpStream, Stream) {
    let listener = Listener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().await.unwrap();

    (client, stream)
}

async fn read(stream: &mut Stream) -> Vec<u8> {
    let mut buf = vec![0; 1024];
    let len = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf.truncate(len);

    buf
}

#[tokio::test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
async fn messages_are_split_at_content_length() {
    let (mut client, mut stream) = connect().await;

    let a: &[u8] = b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let b: &[u8] = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    client.write_all(&[a, b].concat()).unwrap();

    assert_eq!(read(&mut stream).await, a);
    assert_eq!(read(&mut stream).await, b);

    drop(client);
    assert_eq!(read(&mut stream).await, b"", "the hangup ends the stream");
}

#[tokio::test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
async fn http2_frames_are_split_at_their_length() {
    let (mut client, mut stream) = connect().await;

    let preface: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    let ping: &[u8] = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00pingping";
    client
        .write_all(&[preface, settings, ping].concat())
        .unwrap();

    for msg in [preface, settings, ping] {
        assert_eq!(read(&mut stream).await, msg);
    }
}

#[tokio::test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
async fn unknown_protocols_end_the_stream() {
    let (mut client, mut stream) = connect().await;
    client.write_all(b"\x16\x03\x01\x00\x05hello").unwrap();

    assert_eq!(read(&mut stream).await, b"");
}

#[tokio::test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
async fn small_reads_keep_the_rest_of_a_message() {
    let (mut client, mut stream) = connect().await;

    let body = "a".repeat(40_000);
    let msg = format!(
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    client.write_all(msg.as_bytes()).unwrap();

    let mut read = vec![0; msg.len()];
    for chunk in read.chunks_mut(10) {
        timeout(Duration::from_secs(2), stream.read_exact(chunk))
            .await
            .expect("read timed out")
            .unwrap();
    }
    assert_eq!(read, msg.as_bytes());
}
