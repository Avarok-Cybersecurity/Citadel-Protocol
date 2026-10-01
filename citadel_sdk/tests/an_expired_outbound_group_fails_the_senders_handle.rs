#![cfg(not(target_family = "wasm"))]
//! An outbound group that expires must fail the sender's `ObjectTransferHandle`.
//!
//! The only terminal events the sender's handle ever receives are
//! `TransferComplete` (the last group's final WAVE_ACK) and `Fail`. When a group
//! stops receiving WAVE_ACKs for `GROUP_EXPIRE_TIME_MS`, the expiry closure in
//! `session.rs` drops `outbound_files[file_key]`, fires `stop_tx`, and reports
//! `InternalServerError { ticket }` to the kernel -- but never touches
//! `file_transfer_handles`. That error is routed to the `SendObject` callback
//! subscription, which `send_file_with_custom_opts` stops polling the moment it
//! enters `handle.transfer_file()`. So a transfer whose final ack is lost on a
//! session that stays up waits forever: the handle's sender is still alive in
//! `file_transfer_handles`, and nothing will ever write to it again.
//!
//! How the loss is staged, without touching production code: the client
//! reaches the server through a TCP relay that forwards every frame verbatim,
//! except that server->client it lets exactly ONE WAVE_ACK through and drops
//! the rest. HdpHeader is plaintext on the wire (it is the AEAD's associated
//! data), so `cmd_primary == GROUP_PACKET && cmd_aux == WAVE_ACK` is readable
//! from the first two bytes of each length-delimited frame. One ack must pass:
//! the expiry check parks a group as `Incomplete` until `has_begun`, which only
//! the first WAVE_ACK sets. The session itself stays healthy (keep-alives run
//! on a 15-minute interval), so no teardown rescues the handle.
//!
//! What is asserted is an ORDERING, not a latency: by the time the expiry's
//! `InternalServerError` reaches the subscription, the handle must already hold
//! `Fail`. On a current_thread runtime the expiry closure runs to completion
//! before any other task is polled, so a `Fail` sent anywhere inside that
//! closure is queued before the kernel even sees the error. The test drains the
//! handle without awaiting (`now_or_never`); a pending handle at that point is
//! the defect. The wait for the expiry itself is the protocol's own
//! GROUP_EXPIRE_TIME_MS (checked on the same period, so roughly two periods).

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::{TcpListener, TcpStream};
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;
    use citadel_types::proto::ObjectTransferStatus;
    use futures::{FutureExt, StreamExt};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    /// `packet_flags::cmd::primary::GROUP_PACKET` (crate-private in citadel_proto).
    const GROUP_PACKET: u8 = 2;
    /// `packet_flags::cmd::aux::group::WAVE_ACK` (crate-private in citadel_proto).
    const WAVE_ACK: u8 = 3;
    /// `has_begun` needs one ack; every later one is the "lost final ack".
    const WAVE_ACKS_ALLOWED_THROUGH: usize = 1;

    /// Receives the object and keeps the session up afterwards: a server that
    /// shut down would close the client's handle channel and mask the defect.
    struct AcceptingServer<R: Ratchet>(Option<NodeRemote<R>>);

    #[async_trait]
    impl<R: Ratchet> NetKernel<R> for AcceptingServer<R> {
        fn load_remote(&mut self, node_remote: NodeRemote<R>) -> Result<(), NetworkError> {
            self.0 = Some(node_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
            if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) =
                message.into_result()?
            {
                handle
                    .accept()
                    .map_err(|err| NetworkError::msg(err.into_string()))?;
                while let Some(status) = handle.next().await {
                    log::info!(target: "citadel", "receiver status: {status:?}");
                }
            }
            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    /// Relays one client connection to `server`, dropping server->client
    /// WAVE_ACKs after the first `WAVE_ACKS_ALLOWED_THROUGH`.
    async fn relay(listener: TcpListener, server: SocketAddr, dropped: Arc<AtomicUsize>) {
        let (client, _) = listener.accept().await.expect("relay accept");
        let upstream = TcpStream::connect(server).await.expect("relay connect");
        let (mut client_rx, mut client_tx) = client.into_split();
        let (mut server_rx, mut server_tx) = upstream.into_split();

        let up = async move {
            let _ = tokio::io::copy(&mut client_rx, &mut server_tx).await;
        };
        let down = async move {
            let mut acks_seen = 0usize;
            loop {
                let mut len = [0u8; 4];
                if server_rx.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                if server_rx.read_exact(&mut body).await.is_err() {
                    return;
                }
                if body.len() >= 2 && body[0] == GROUP_PACKET && body[1] == WAVE_ACK {
                    acks_seen += 1;
                    if acks_seen > WAVE_ACKS_ALLOWED_THROUGH {
                        dropped.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                }
                if client_tx.write_all(&len).await.is_err()
                    || client_tx.write_all(&body).await.is_err()
                {
                    return;
                }
            }
        };
        futures::future::join(up, down).await;
    }

    /// Everything the sender's handle yielded without waiting.
    fn drain_ready(handle: &mut ObjectTransferHandler) -> (Vec<ObjectTransferStatus>, bool) {
        let mut seen = Vec::new();
        loop {
            match handle.next().now_or_never() {
                Some(Some(status)) => seen.push(status),
                Some(None) => return (seen, true),
                None => return (seen, false),
            }
        }
    }

    #[tokio::test]
    async fn an_expired_outbound_group_fails_the_senders_handle() {
        citadel_logging::setup_log();
        let (server, server_addr) =
            server_test_node(AcceptingServer::<StackedRatchet>(None), |_| {});

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let relay_task = tokio::spawn(relay(relay_listener, server_addr, dropped.clone()));

        let settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(relay_addr, Uuid::new_v4())
                .disable_udp()
                .build()
                .unwrap();

        let (verdict_tx, verdict_rx) = tokio::sync::oneshot::channel();
        let verdict_tx = std::sync::Mutex::new(Some(verdict_tx));

        let client_kernel = SingleClientServerConnectionKernel::new(settings, move |connection| {
            let verdict_tx = verdict_tx.lock().unwrap().take().unwrap();
            async move {
                let remote = &connection.remote;
                let mut subscription = remote
                    .remote()
                    .send_callback_subscription(NodeRequest::SendObject(SendObject {
                        source: Box::new("../resources/TheBridge.pdf"),
                        chunk_size: Some(32 * 1024),
                        session_cid: remote.user().get_session_cid(),
                        v_conn_type: *remote.user(),
                        transfer_type: TransferType::FileTransfer,
                    }))
                    .await?;

                let mut handle = loop {
                    match subscription.next().await.map(|e| e.into_result()) {
                        Some(Ok(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                            handle,
                            ..
                        }))) => break handle,
                        Some(Ok(other)) => {
                            log::warn!(target: "citadel", "ignoring {other:?}");
                        }
                        other => panic!("subscription ended before a handle: {other:?}"),
                    }
                };

                // Wait for the expiry's kernel error, while consuming the handle's
                // progress so that a TransferComplete (the relay failed to stage
                // the loss) is reported rather than mistaken for the defect.
                let mut before_expiry = Vec::new();
                let expiry = loop {
                    tokio::select! {
                        biased;
                        status = handle.next() => match status {
                            Some(ObjectTransferStatus::TransferComplete) => {
                                panic!("transfer completed: the relay did not stage a lost ack")
                            }
                            Some(ObjectTransferStatus::Fail(reason)) => {
                                // Failing before the expiry notice is also a correct outcome.
                                break format!("handle failed first: {reason}");
                            }
                            Some(other) => before_expiry.push(other),
                            None => panic!("handle stream ended with no terminal status"),
                        },
                        event = subscription.next() => match event.map(|e| e.into_result()) {
                            Some(Err(err)) => break format!("expiry reported: {err:?}"),
                            Some(Ok(NodeResult::InternalServerError(err))) => {
                                break format!("expiry reported: {}", err.message)
                            }
                            Some(Ok(other)) => log::warn!(target: "citadel", "ignoring {other:?}"),
                            None => panic!("subscription ended without an expiry notice"),
                        },
                    }
                };

                let (after_expiry, ended) = drain_ready(&mut handle);
                let _ = verdict_tx.send((expiry, before_expiry, after_expiry, ended));
                connection.shutdown_kernel().await
            }
        });

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        tokio::select! {
            res = client => { res.expect("client node failed"); }
            res = server => panic!("server ended first: {:?}", res.map(|_| ())),
        }
        relay_task.abort();

        let (expiry, before, after, ended) = verdict_rx.await.expect("client produced no verdict");
        log::info!(target: "citadel", "{expiry}; before={before:?} after={after:?} ended={ended}");
        assert!(
            dropped.load(Ordering::SeqCst) > 0,
            "the relay dropped no WAVE_ACK, so no loss was staged"
        );
        let failed = expiry.starts_with("handle failed first")
            || after
                .iter()
                .any(|s| matches!(s, ObjectTransferStatus::Fail(_)));
        assert!(
            failed,
            "the outbound group expired ({expiry}) but the sender's ObjectTransferHandle \
             holds no Fail (ready after expiry: {after:?}, stream ended: {ended}). \
             transfer_file() would wait forever on a session that stays up."
        );
    }
}
