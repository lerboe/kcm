use axum::{Router, body::Bytes, http::Version, routing::get, serve::Listener};
use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

const ADDR: &str = "127.0.0.1:8080";

struct Kcm(kcm::Listener);

impl Listener for Kcm {
    type Io = kcm::Stream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok(conn) => return conn,
                Err(err) => eprintln!("accept failed: {err}"),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let app =
        Router::new().route(
            "/",
            get(|version: Version| async move { format!("{version:?}\n") }).post(
                |version: Version, body: Bytes| async move {
                    format!("{version:?} {} bytes\n", body.len())
                },
            ),
        );

    if std::env::args().any(|arg| arg == "--no-kcm") {
        println!("listening on {ADDR} without KCM");
        axum::serve(TcpListener::bind(ADDR).await?, app).await
    } else {
        println!("listening on {ADDR} with KCM");
        axum::serve(Kcm(kcm::Listener::bind(ADDR).await?), app).await
    }
}
