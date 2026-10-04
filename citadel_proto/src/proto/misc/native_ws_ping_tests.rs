//! A ping queued on a [`WebSocketByteStream`] goes out ahead of its next frame, and the other
//! side's pong is reported.

use super::{WebSocketByteStream, WsTransport};
use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
use citadel_io::tokio::net::{TcpListener, TcpStream};

#[test]
fn a_queued_ping_is_answered_by_the_other_side() {
    citadel_io::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = citadel_io::tokio::spawn(async move {
                let (tcp, peer) = listener.accept().await.unwrap();
                let local = tcp.local_addr().unwrap();
                let ws = tokio_tungstenite::accept_async(WsTransport::Plain(tcp))
                    .await
                    .unwrap();
                let mut stream = WebSocketByteStream::new(ws, peer, local);
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(b"back").await.unwrap();
                stream.flush().await.unwrap();
            });

            let tcp = TcpStream::connect(addr).await.unwrap();
            let local = tcp.local_addr().unwrap();
            let (ws, _) =
                tokio_tungstenite::client_async(format!("ws://{addr}"), WsTransport::Plain(tcp))
                    .await
                    .unwrap();
            let mut client = WebSocketByteStream::new(ws, addr, local);
            let answered = client.pinger().answered();
            let seq = client.pinger().ping();
            client.write_all(b"data").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"back");
            // The server's pong was queued when it read the ping, ahead of its reply.
            assert_eq!(*answered.borrow(), seq, "the ping was never answered");
            server.await.unwrap();
        });
}
