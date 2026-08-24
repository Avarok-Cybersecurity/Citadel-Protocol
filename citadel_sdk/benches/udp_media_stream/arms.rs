//! The three transport arms of the `udp_media_stream` bench, all driving the same
//! [`super::workload`]: Citadel P2P `UdpChannel`, bare quinn datagrams, bare `UdpSocket`.

use crate::workload::{run_receiver, run_sender, ArmResult, DatagramTx, Params};
use bytes::BytesMut;
use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_sdk::prefabs::client::peer_connection::{
    PeerConnectionKernel, PeerConnectionSetupAggregator,
};
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::{server_info, TestBarrier};
use citadel_wire::exports::Connection;
use citadel_wire::quic::{QuicClient, QuicServer, SELF_SIGNED_DOMAIN};
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use uuid::Uuid;

impl DatagramTx for OutboundUdpSender {
    fn send(&mut self, pkt: BytesMut) -> impl Future<Output = Result<(), String>> + Send {
        let r = self.unbounded_send(pkt).map_err(|e| e.to_string());
        async move { r }
    }
}

impl DatagramTx for Connection {
    fn send(&mut self, pkt: BytesMut) -> impl Future<Output = Result<(), String>> + Send {
        let r = self.send_datagram(pkt.freeze()).map_err(|e| e.to_string());
        async move { r }
    }
}

impl DatagramTx for Arc<UdpSocket> {
    fn send(&mut self, pkt: BytesMut) -> impl Future<Output = Result<(), String>> + Send {
        let s = self.clone();
        async move {
            UdpSocket::send(&s, &pkt)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }
}

/// (a) Two `PeerConnectionKernel`s through a local server, `UdpMode::Enabled`; one peer sends over
/// the `OutboundUdpSender` half, the other drains the `PeerChannelRecvHalf` half.
pub async fn citadel(p: Params) -> ArmResult {
    TestBarrier::reset(2);
    let (server, server_addr) = server_info::<StackedRatchet>();
    let server = tokio::task::spawn(server);
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    // Rendezvous (2 peers + driver): both UDP halves up before sending; both done before teardown.
    let ready = Arc::new(tokio::sync::Barrier::new(3));
    let done = Arc::new(tokio::sync::Barrier::new(3));
    let sender_done = Arc::new(AtomicBool::new(false));
    let result = Arc::new(citadel_io::Mutex::new(None));

    let mut clients = Vec::with_capacity(2);
    for (idx, id) in ids.iter().copied().enumerate() {
        let other = ids[1 - idx];
        let agg = PeerConnectionSetupAggregator::default()
            .with_peer_custom(other)
            .ensure_registered()
            .with_udp_mode(UdpMode::Enabled)
            .with_session_security_settings(SessionSecuritySettings::default())
            .add();
        let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, id)
            .with_udp_mode(UdpMode::Enabled)
            .build()
            .unwrap();
        let (ready, done, sender_done, result) = (
            ready.clone(),
            done.clone(),
            sender_done.clone(),
            result.clone(),
        );
        let kernel = PeerConnectionKernel::new(settings, agg, move |mut conn_rx, remote| {
            async move {
                eprintln!("[bench:{idx}] kernel connected, awaiting peer conn");
                let mut success = conn_rx
                    .recv()
                    .await
                    .ok_or_else(|| NetworkError::msg("peer conn rx closed".to_string()))??;
                let udp = success
                    .udp_channel_rx
                    .take()
                    .ok_or_else(|| NetworkError::msg("no udp channel rx".to_string()))?
                    .await
                    .map_err(|_| NetworkError::msg("udp channel never arrived".to_string()))?;
                let (mut tx, rx) = udp.split();
                eprintln!("[bench:{idx}] udp channel up");
                ready.wait().await;
                if idx == 0 {
                    run_sender(p, &mut tx, sender_done)
                        .await
                        .map_err(NetworkError::msg)?;
                } else {
                    *result.lock() = Some(run_receiver("citadel_udp", p, rx, sender_done).await);
                }
                eprintln!("[bench:{idx}] phase done");
                done.wait().await;
                // Keep the reliable channel alive until both sides are done; the UDP halves drop
                // here (DisconnectUDP) only after the done rendezvous, so no in-flight data is cut.
                drop(success.channel);
                remote.shutdown_kernel().await
            }
        });
        clients.push(tokio::task::spawn(
            DefaultNodeBuilder::default().build(kernel).unwrap(),
        ));
    }
    ready.wait().await;
    done.wait().await;
    for c in clients {
        let _ = c.await;
    }
    server.abort();
    let _ = server.await;
    let r = result
        .lock()
        .take()
        .expect("citadel receiver produced no result");
    r
}

/// (b) Two quinn endpoints (Citadel's own hole-punch-friendly transport config, self-signed cert,
/// no-verify client) exchanging QUIC DATAGRAM frames.
pub async fn quinn(p: Params) -> ArmResult {
    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = QuicServer::new_self_signed(server_sock).unwrap();
    let client = QuicClient::new_no_verify(client_sock).unwrap();
    let accept = async { server.endpoint.accept().await.unwrap().await.unwrap() };
    let connect = async {
        client
            .endpoint
            .connect(server_addr, SELF_SIGNED_DOMAIN)
            .unwrap()
            .await
            .unwrap()
    };
    let (server_conn, mut client_conn) = futures::future::join(accept, connect).await;
    let max = client_conn.max_datagram_size();
    eprintln!("[quinn] max_datagram_size = {max:?}");
    let sender_done = Arc::new(AtomicBool::new(false));
    let rx = futures::stream::unfold(server_conn.clone(), |c| async move {
        c.read_datagram().await.ok().map(|d| (d, c))
    });
    let recv = run_receiver("quinn_datagram", p, Box::pin(rx), sender_done.clone());
    let send = run_sender(p, &mut client_conn, sender_done);
    let (r, s) = futures::future::join(recv, send).await;
    s.expect("quinn send failed");
    client_conn.close(0u32.into(), b"done");
    r
}

/// (c) Two connected `tokio::net::UdpSocket`s on loopback: the floor every stack sits on.
pub async fn raw_udp(p: Params) -> ArmResult {
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    a.connect(b.local_addr().unwrap()).await.unwrap();
    b.connect(a.local_addr().unwrap()).await.unwrap();
    let sender_done = Arc::new(AtomicBool::new(false));
    let frag_bytes = p.frag_bytes;
    let rx = futures::stream::unfold(b, move |s| async move {
        let mut buf = vec![0u8; frag_bytes];
        let n = s.recv(&mut buf).await.ok()?;
        buf.truncate(n);
        Some((buf, s))
    });
    let recv = run_receiver("raw_udp", p, Box::pin(rx), sender_done.clone());
    let mut tx = a;
    let send = run_sender(p, &mut tx, sender_done);
    let (r, s) = futures::future::join(recv, send).await;
    s.expect("raw udp send failed");
    r
}
