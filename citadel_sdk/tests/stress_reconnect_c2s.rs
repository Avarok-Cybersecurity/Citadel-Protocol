#![cfg(not(target_family = "wasm"))]
//! Stress Test: C2S Iterative Disconnect/Reconnect
//!
//! Registers once, then loops N iterations of:
//! connect → rekey → send/recv messages → disconnect
//!
//! Verifies CID permanence and correct message counts across iterations.

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

    const ITERATIONS: usize = 3;
    const MSGS_PER_ITERATION: usize = 2;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_stress_c2s_reconnect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let state = Arc::new(NodeState::default());
        let state_clone = state.clone();

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                let channel = connection.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();
                while let Some(msg) = rx.next().await {
                    tx.send(msg).await?;
                }
                Ok(())
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let username = format!("sc2s_{}", &uuid.to_string()[..8]);
        let password = "password123";

        let client_kernel = ReconnectionTestKernel::new(
            state_clone.clone(),
            move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| async move {
                // Register once
                let reg = remote
                    .register_with_defaults(
                        server_addr,
                        username.as_str(),
                        username.as_str(),
                        password,
                    )
                    .await?;
                let expected_cid = reg.cid;
                state.set_cid(expected_cid).await;
                log::info!("[C2S Stress] Registered CID={expected_cid}");

                for i in 0..ITERATIONS {
                    log::info!("[C2S Stress] === Iteration {}/{} ===", i + 1, ITERATIONS);

                    // Connect
                    let mut conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;
                    assert_eq!(conn.cid, expected_cid, "CID changed on iteration {}", i + 1);
                    state.set_cid(conn.cid).await;

                    // Rekey
                    conn.rekey().await?;

                    // Send/recv messages
                    let channel = conn.take_channel().unwrap();
                    let (mut tx, mut rx) = channel.split();

                    for j in 0..MSGS_PER_ITERATION {
                        let msg = format!("iter{i}_msg{j}");
                        tx.send(SecBuffer::from(msg.as_bytes())).await?;
                        state.increment_messages_sent();
                    }

                    for _ in 0..MSGS_PER_ITERATION {
                        let _msg = rx.next().await;
                        state.increment_messages_received();
                    }

                    // Disconnect
                    conn.disconnect().await?;
                    log::info!("[C2S Stress] Iteration {} complete", i + 1);

                    // Brief pause between iterations
                    citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
                }

                let total_msgs = ITERATIONS * MSGS_PER_ITERATION;
                state.assert_final_state(
                    "C2S Stress Client",
                    0, // c2s_connect (intercepted by connect_with_defaults)
                    0, // c2s_disconnect (intercepted by disconnect)
                    0, // p2p_connect (N/A)
                    0, // p2p_disconnect_recv (N/A)
                    total_msgs,
                    total_msgs,
                );

                // Reconnect to get a handle for shutdown
                let conn = remote
                    .connect_with_defaults(AuthenticationRequest::credentialed(
                        username.clone(),
                        password,
                    ))
                    .await?;
                conn.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = client => client_res
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .expect("C2S stress test timed out");

        assert!(result.is_ok(), "C2S stress test failed: {:?}", result);
        log::info!("C2S Stress Reconnect Test PASSED ({ITERATIONS} iterations)");
    }
}
