//! Test 1: C2S Reconnection
//!
//! Verifies client can disconnect from server and reconnect with same CID.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_c2s_reconnection() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let state_a = Arc::new(NodeState::default());
        let state_a_clone = state_a.clone();

        // Server setup - echo messages back
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                log::info!("[Server] Connection received");
                let channel = connection.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();

                // Echo messages back
                while let Some(msg) = rx.next().await {
                    log::trace!("[Server] Echoing message");
                    tx.send(msg).await?;
                }

                Ok(())
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        // Username must be 3-37 chars, so use short prefix + first 8 chars of UUID
        let username = format!("c2s_{}", &uuid.to_string()[..8]);
        let password = "password123";

        // Client kernel
        let client_kernel = ReconnectionTestKernel::new(
            state_a_clone.clone(),
            move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| async move {
                log::info!("[Client] Starting C2S reconnection test");

                // ===== PHASE 0: Initial Setup =====
                state.set_phase(0);
                log::info!("[Client] Phase 0: Register + Connect + Rekey");

                // Register
                let reg_result = remote
                    .register_with_defaults(
                        server_addr,
                        username.as_str(),
                        username.as_str(),
                        password,
                    )
                    .await?;
                log::info!("[Client] Registered with CID: {}", reg_result.cid);
                state.set_cid(reg_result.cid).await;

                // Connect
                let mut conn = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                let cid_1 = conn.cid;
                log::info!("[Client] Connected with CID: {}", cid_1);
                state.set_cid(cid_1).await;

                // Rekey to advance ratchet version
                let rekey_result = conn.rekey().await?;
                log::info!("[Client] Rekey result: {:?}", rekey_result);

                // ===== PHASE 1: First USE =====
                state.set_phase(1);
                log::info!("[Client] Phase 1: Send 5 messages");

                let channel = conn.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();

                for i in 0..5 {
                    let msg = format!("Message {}", i);
                    tx.send(SecBuffer::from(msg.as_bytes())).await?;
                    state.increment_messages_sent();
                }

                // Receive echoed messages
                for _ in 0..5 {
                    let _msg = rx.next().await;
                    state.increment_messages_received();
                }

                log::info!("[Client] Phase 1 complete: sent and received 5 messages");

                // ===== PHASE 2: Disconnect =====
                state.set_phase(2);
                log::info!("[Client] Phase 2: Disconnect");

                conn.disconnect().await?;
                log::info!("[Client] Disconnected");

                // Small delay to ensure server processes disconnect
                citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;

                // ===== PHASE 3: Reconnect Setup =====
                state.set_phase(3);
                log::info!("[Client] Phase 3: Reconnect");

                // Reconnect (login, not register)
                let mut conn2 = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                let cid_2 = conn2.cid;
                log::info!("[Client] Reconnected with CID: {}", cid_2);
                state.set_cid(cid_2).await;

                // Verify CID unchanged
                assert_eq!(cid_1, cid_2, "CID should be permanent per account");

                // Rekey again after reconnect
                let rekey_result = conn2.rekey().await?;
                log::info!("[Client] Rekey result after reconnect: {:?}", rekey_result);

                // ===== PHASE 4: Post-Reconnect USE =====
                state.set_phase(4);
                log::info!("[Client] Phase 4: Send 5 more messages");

                let channel2 = conn2.take_channel().unwrap();
                let (mut tx2, mut rx2) = channel2.split();

                for i in 5..10 {
                    let msg = format!("Message {}", i);
                    tx2.send(SecBuffer::from(msg.as_bytes())).await?;
                    state.increment_messages_sent();
                }

                // Receive echoed messages
                for _ in 0..5 {
                    let _msg = rx2.next().await;
                    state.increment_messages_received();
                }

                log::info!("[Client] Phase 4 complete: sent and received 5 more messages");

                // ===== PHASE 5: Verification =====
                state.set_phase(5);
                log::info!("[Client] Phase 5: Verify state");

                state.assert_final_state(
                    "Client A", 0,  // c2s_connect (intercepted)
                    0,  // c2s_disconnect (intercepted)
                    0,  // p2p_connect (N/A)
                    0,  // p2p_disconnect_recv (N/A)
                    10, // msgs_sent
                    10, // msgs_recv
                );

                conn2.shutdown_kernel().await
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = client => client_res
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("Test timed out");

        assert!(result.is_ok(), "Test failed: {:?}", result);
        log::info!("Test 1 (C2S Reconnection) PASSED");
    }
}
