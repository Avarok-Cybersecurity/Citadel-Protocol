#![cfg(not(target_family = "wasm"))]
//! Stress Test: P2P Iterative Disconnect/Reconnect
//!
//! Two registered peers loop N iterations of:
//! P2P connect → send/recv messages → B disconnects P2P → reconnect
//!
//! C2S stays active throughout. Verifies CID permanence, correct message
//! counts, and that disconnect signals are received correctly.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    const ITERATIONS: usize = 3;
    const MSGS_PER_ITERATION: usize = 2;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_stress_p2p_reconnect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let state_a = Arc::new(NodeState::default());
        let state_b = Arc::new(NodeState::default());

        let (server, server_addr) = server_info::<StackedRatchet>();

        let uuid_a = Uuid::new_v4();
        let uuid_b = Uuid::new_v4();
        let username_a = format!("spa_{}", &uuid_a.to_string()[..8]);
        let username_b = format!("spb_{}", &uuid_b.to_string()[..8]);
        let password = "password123";

        // 3 barriers per iteration: connect sync, msg sync, disconnect sync
        // Plus one final barrier for end-of-test sync
        let total_barriers = ITERATIONS * 3 + 1;
        let barriers: Vec<Arc<Barrier>> = (0..total_barriers)
            .map(|_| Arc::new(Barrier::new(2)))
            .collect();
        let barriers_b = barriers.clone();

        let server_addr_a = server_addr;
        let server_addr_b = server_addr;
        let username_a_clone = username_a.clone();
        let username_b_clone = username_b.clone();
        let peer_username_b = username_b.clone();
        let peer_username_a = username_a.clone();

        // Peer A
        let state_a_clone = state_a.clone();
        let client_a_kernel = ReconnectionTestKernel::new(
            state_a_clone.clone(),
            move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| {
                let barriers = barriers;
                let username = username_a_clone;
                let addr = server_addr_a;
                let peer_username = peer_username_b;

                async move {
                    log::info!("[Peer A] Starting P2P stress test");

                    // === ONE-TIME SETUP: Register + C2S + P2P Register ===
                    let reg = remote
                        .register_with_defaults(
                            addr,
                            username.as_str(),
                            username.as_str(),
                            password,
                        )
                        .await?;
                    state.set_cid(reg.cid).await;

                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;

                    conn.rekey().await?;

                    wait_for_peers().await;

                    let peer_handle = conn.propose_target(reg.cid, peer_username.clone()).await?;
                    let _reg_status = peer_handle.register_to_peer().await?;
                    log::info!("[Peer A] Setup complete, starting iterations");

                    // === ITERATIONS ===
                    for i in 0..ITERATIONS {
                        let base = i * 3;
                        log::info!("[Peer A] === Iteration {}/{} ===", i + 1, ITERATIONS);

                        // Barrier: connect sync
                        barriers[base].wait().await;

                        // P2P Connect
                        let peer_handle = conn.find_target(conn.cid, peer_username.clone()).await?;
                        let p2p = peer_handle.connect_to_peer().await?;
                        let channel = p2p.channel;
                        let (mut tx, mut rx) = channel.split();

                        p2p.remote.rekey().await?;
                        log::info!("[Peer A] Iteration {} P2P connected", i + 1);

                        // Barrier: msg sync
                        barriers[base + 1].wait().await;

                        // Send messages
                        for j in 0..MSGS_PER_ITERATION {
                            let msg = format!("A->B iter{i}_msg{j}");
                            tx.send(SecBuffer::from(msg.as_bytes())).await?;
                            state.increment_messages_sent();
                        }

                        // Receive messages
                        for _ in 0..MSGS_PER_ITERATION {
                            let _msg = rx.next().await;
                            state.increment_messages_received();
                        }

                        // Drop channel refs before disconnect
                        drop(tx);
                        drop(rx);

                        // Barrier: disconnect sync — B disconnects after this
                        barriers[base + 2].wait().await;

                        // Wait for actual P2P disconnect signal from B
                        state.wait_for_p2p_disconnect(Duration::from_secs(15)).await;
                        log::info!("[Peer A] Iteration {} complete", i + 1);
                    }

                    // Final barrier
                    barriers[ITERATIONS * 3].wait().await;

                    let total_msgs = ITERATIONS * MSGS_PER_ITERATION;
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer A (P2P Stress)",
                        0,          // c2s_connect (intercepted)
                        0,          // c2s_disconnect (C2S stays active)
                        0,          // p2p_connect (intercepted)
                        ITERATIONS, // min p2p_disconnect_recv (1 per iteration from B)
                        total_msgs,
                        total_msgs,
                    );

                    conn.shutdown_kernel().await
                }
            },
        );

        // Peer B
        let state_b_clone = state_b.clone();
        let client_b_kernel = ReconnectionTestKernel::new(
            state_b_clone.clone(),
            move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| {
                let barriers = barriers_b;
                let username = username_b_clone;
                let addr = server_addr_b;
                let peer_username = peer_username_a;

                async move {
                    log::info!("[Peer B] Starting P2P stress test");

                    // === ONE-TIME SETUP: Register + C2S + P2P Register ===
                    let reg = remote
                        .register_with_defaults(
                            addr,
                            username.as_str(),
                            username.as_str(),
                            password,
                        )
                        .await?;
                    state.set_cid(reg.cid).await;

                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;

                    conn.rekey().await?;

                    wait_for_peers().await;

                    let peer_handle = conn.propose_target(reg.cid, peer_username.clone()).await?;
                    let _reg_status = peer_handle.register_to_peer().await?;
                    log::info!("[Peer B] Setup complete, starting iterations");

                    // === ITERATIONS ===
                    for i in 0..ITERATIONS {
                        let base = i * 3;
                        log::info!("[Peer B] === Iteration {}/{} ===", i + 1, ITERATIONS);

                        // Barrier: connect sync
                        barriers[base].wait().await;

                        // P2P Connect
                        let peer_handle = conn.find_target(conn.cid, peer_username.clone()).await?;
                        let p2p = peer_handle.connect_to_peer().await?;
                        let channel = p2p.channel;
                        let (mut tx, mut rx) = channel.split();
                        let p2p_remote = p2p.remote;

                        p2p_remote.rekey().await?;
                        log::info!("[Peer B] Iteration {} P2P connected", i + 1);

                        // Barrier: msg sync
                        barriers[base + 1].wait().await;

                        // Send messages
                        for j in 0..MSGS_PER_ITERATION {
                            let msg = format!("B->A iter{i}_msg{j}");
                            tx.send(SecBuffer::from(msg.as_bytes())).await?;
                            state.increment_messages_sent();
                        }

                        // Receive messages
                        for _ in 0..MSGS_PER_ITERATION {
                            let _msg = rx.next().await;
                            state.increment_messages_received();
                        }

                        // Drop channel refs before disconnect
                        drop(tx);
                        drop(rx);

                        // Barrier: disconnect sync
                        barriers[base + 2].wait().await;

                        // B disconnects P2P (C2S stays active)
                        p2p_remote.disconnect().await?;
                        log::info!("[Peer B] Iteration {} P2P disconnected", i + 1);

                        // Iteration barrier handles synchronization before next round
                    }

                    // Final barrier
                    barriers[ITERATIONS * 3].wait().await;

                    let total_msgs = ITERATIONS * MSGS_PER_ITERATION;
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer B (P2P Stress)",
                        0, // c2s_connect (intercepted)
                        0, // c2s_disconnect (C2S stays active)
                        0, // p2p_connect (intercepted)
                        0, // min p2p_disconnect_recv (B initiated all disconnects)
                        total_msgs,
                        total_msgs,
                    );

                    conn.shutdown_kernel().await
                }
            },
        );

        let client_a = DefaultNodeBuilder::default()
            .build(client_a_kernel)
            .unwrap();
        let client_b = DefaultNodeBuilder::default()
            .build(client_b_kernel)
            .unwrap();

        let clients = futures::future::try_join(client_a, client_b);

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(300), task)
            .await
            .expect("P2P stress test timed out");

        assert!(result.is_ok(), "P2P stress test failed: {:?}", result);
        log::info!("P2P Stress Reconnect Test PASSED ({ITERATIONS} iterations)");
    }
}
