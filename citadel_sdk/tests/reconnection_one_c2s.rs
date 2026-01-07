//! Test 5: P2P Disconnect then ONE C2S Disconnect
//!
//! Verifies recovery when P2P disconnects, then only one peer (B) disconnects C2S.
//! A stays connected to the server throughout.
//!
//! ## Causal Pathway
//!
//! ```text
//! C2S Register x2 → C2S Connect x2 → rekey() x2 →
//! P2P Register x2 (simultaneous) → P2P Connect x2 (simultaneous) → P2P rekey() x2 →
//! send P2P messages → P2P disconnect() → B.disconnect() [C2S] →
//! B: C2S Connect → rekey() → P2P Connect x2 → P2P rekey() x2 → send P2P messages
//! ```
//!
//! ## Signal Flow
//!
//! | Phase | Actor | Action | Signal to Other |
//! |-------|-------|--------|-----------------|
//! | 2 | B | p2p.disconnect() | A receives P2P disconnect |
//! | 2 | B | disconnect() (C2S) | - |
//! | 3 | B | reconnect C2S | - |
//! | 3 | Both | connect_to_peer() | P2P re-established |

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use futures::StreamExt;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_p2p_then_one_c2s_disconnect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2); // 2 clients only

        let state_a = Arc::new(NodeState::default());
        let state_b = Arc::new(NodeState::default());

        let (server, server_addr) = server_info::<StackedRatchet>();

        let uuid_a = Uuid::new_v4();
        let uuid_b = Uuid::new_v4();
        let username_a = format!("ona_{}", &uuid_a.to_string()[..8]);
        let username_b = format!("onb_{}", &uuid_b.to_string()[..8]);
        let password = "password123";

        // Barriers for synchronization
        let barrier_phase1 = Arc::new(Barrier::new(2));
        let barrier_phase2 = Arc::new(Barrier::new(2));
        let barrier_phase3 = Arc::new(Barrier::new(2));
        let barrier_phase4 = Arc::new(Barrier::new(2));

        let barrier_phase1_b = barrier_phase1.clone();
        let barrier_phase2_b = barrier_phase2.clone();
        let barrier_phase3_b = barrier_phase3.clone();
        let barrier_phase4_b = barrier_phase4.clone();

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
                let barrier1 = barrier_phase1;
                let barrier2 = barrier_phase2;
                let barrier3 = barrier_phase3;
                let barrier4 = barrier_phase4;
                let username = username_a_clone;
                let addr = server_addr_a;
                let peer_username = peer_username_b;

                async move {
                    log::info!("[Peer A] Starting");

                    // ===== PHASE 0: Register, Connect, P2P Setup =====
                    state.set_phase(0);

                    // Register
                    let reg = remote
                        .register_with_defaults(
                            addr,
                            username.as_str(),
                            username.as_str(),
                            password,
                        )
                        .await?;
                    log::info!("[Peer A] Registered CID={}", reg.cid);
                    state.set_cid(reg.cid).await;

                    // Connect
                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;
                    log::info!("[Peer A] C2S Connected");

                    // Rekey C2S
                    conn.rekey().await?;
                    log::info!("[Peer A] C2S Rekey done");

                    // Wait for Peer B before P2P operations
                    wait_for_peers().await;
                    log::info!("[Peer A] All peers ready for P2P");

                    // P2P Register with B
                    let peer_handle = conn.propose_target(reg.cid, peer_username.clone()).await?;
                    let _reg_status = peer_handle.register_to_peer().await?;
                    log::info!("[Peer A] P2P Registered with peer B");

                    // P2P Connect
                    let p2p = peer_handle.connect_to_peer().await?;
                    log::info!("[Peer A] P2P Connected");

                    let channel = p2p.channel;
                    let (mut tx, mut rx) = channel.split();

                    // Rekey P2P
                    p2p.remote.rekey().await?;
                    log::info!("[Peer A] P2P Rekey done");

                    // ===== PHASE 1: First USE =====
                    state.set_phase(1);
                    barrier1.wait().await;

                    // Send 5 messages
                    for i in 0..5 {
                        let msg = format!("A->B Message {}", i);
                        tx.send(SecBuffer::from(msg.as_bytes())).await?;
                        state.increment_messages_sent();
                    }

                    // Receive 5 messages
                    for _ in 0..5 {
                        let _msg = rx.next().await;
                        state.increment_messages_received();
                    }

                    log::info!("[Peer A] Phase 1 complete");

                    // ===== PHASE 2: P2P disconnect (B initiates), then B disconnects C2S =====
                    state.set_phase(2);

                    // Drop channel refs
                    drop(tx);
                    drop(rx);

                    // Wait for P2P disconnect signal from B
                    citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;

                    log::info!(
                        "[Peer A] P2P disconnect received count: {}",
                        state.p2p_disconnect_received_count.load(Ordering::SeqCst)
                    );

                    barrier2.wait().await;

                    // A does NOT disconnect C2S - stays connected
                    log::info!("[Peer A] Staying connected to server (C2S active)");

                    citadel_io::tokio::time::sleep(Duration::from_millis(200)).await;

                    // ===== PHASE 3: B reconnects, both reconnect P2P =====
                    state.set_phase(3);
                    barrier3.wait().await;

                    // Reconnect P2P (A's C2S is still active) - already registered, just connect
                    let peer_handle2 = conn.find_target(conn.cid, peer_username.clone()).await?;
                    let p2p2 = peer_handle2.connect_to_peer().await?;
                    log::info!("[Peer A] P2P Reconnected");

                    let channel2 = p2p2.channel;
                    let (mut tx2, mut rx2) = channel2.split();

                    // Rekey P2P
                    p2p2.remote.rekey().await?;
                    log::info!("[Peer A] P2P Rekey done after reconnect");

                    // ===== PHASE 4: Post-Reconnect USE =====
                    state.set_phase(4);
                    barrier4.wait().await;

                    // Send 5 more messages
                    for i in 5..10 {
                        let msg = format!("A->B Message {}", i);
                        tx2.send(SecBuffer::from(msg.as_bytes())).await?;
                        state.increment_messages_sent();
                    }

                    // Receive 5 more messages
                    for _ in 0..5 {
                        let _msg = rx2.next().await;
                        state.increment_messages_received();
                    }

                    log::info!("[Peer A] Phase 4 complete");

                    // ===== PHASE 5: Verification =====
                    state.set_phase(5);

                    // A never disconnected C2S, but should have received P2P disconnect from B.
                    // Additional cleanup disconnects may arrive.
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer A (Test 5)",
                        0,  // c2s_connect (intercepted)
                        0,  // c2s_disconnect (A never disconnected C2S)
                        0,  // p2p_connect (intercepted)
                        1,  // min p2p_disconnect_recv (from B's P2P disconnect)
                        10, // msgs_sent
                        10, // msgs_recv
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
                let barrier1 = barrier_phase1_b;
                let barrier2 = barrier_phase2_b;
                let barrier3 = barrier_phase3_b;
                let barrier4 = barrier_phase4_b;
                let username = username_b_clone;
                let addr = server_addr_b;
                let peer_username = peer_username_a;

                async move {
                    log::info!("[Peer B] Starting");

                    // ===== PHASE 0: Register, Connect, P2P Setup =====
                    state.set_phase(0);

                    // Register
                    let reg = remote
                        .register_with_defaults(
                            addr,
                            username.as_str(),
                            username.as_str(),
                            password,
                        )
                        .await?;
                    log::info!("[Peer B] Registered CID={}", reg.cid);
                    state.set_cid(reg.cid).await;

                    // Connect
                    let conn = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;
                    log::info!("[Peer B] C2S Connected");

                    // Rekey C2S
                    conn.rekey().await?;
                    log::info!("[Peer B] C2S Rekey done");

                    // Wait for Peer A before P2P operations
                    wait_for_peers().await;
                    log::info!("[Peer B] All peers ready for P2P");

                    // P2P Register with A
                    let peer_handle = conn.propose_target(reg.cid, peer_username.clone()).await?;
                    let _reg_status = peer_handle.register_to_peer().await?;
                    log::info!("[Peer B] P2P Registered with peer A");

                    // P2P Connect
                    let p2p = peer_handle.connect_to_peer().await?;
                    log::info!("[Peer B] P2P Connected");

                    let channel = p2p.channel;
                    let (mut tx, mut rx) = channel.split();
                    let p2p_remote = p2p.remote;

                    // Rekey P2P
                    p2p_remote.rekey().await?;
                    log::info!("[Peer B] P2P Rekey done");

                    // ===== PHASE 1: First USE =====
                    state.set_phase(1);
                    barrier1.wait().await;

                    // Send 5 messages
                    for i in 0..5 {
                        let msg = format!("B->A Message {}", i);
                        tx.send(SecBuffer::from(msg.as_bytes())).await?;
                        state.increment_messages_sent();
                    }

                    // Receive 5 messages
                    for _ in 0..5 {
                        let _msg = rx.next().await;
                        state.increment_messages_received();
                    }

                    log::info!("[Peer B] Phase 1 complete");

                    // ===== PHASE 2: B initiates P2P disconnect, then B disconnects C2S =====
                    state.set_phase(2);

                    // Drop channel refs before P2P disconnect
                    drop(tx);
                    drop(rx);

                    // B initiates P2P disconnect
                    p2p_remote.disconnect().await?;
                    log::info!("[Peer B] P2P Disconnected");

                    barrier2.wait().await;

                    // B disconnects C2S
                    conn.disconnect().await?;
                    log::info!("[Peer B] C2S Disconnected");

                    citadel_io::tokio::time::sleep(Duration::from_millis(200)).await;

                    // ===== PHASE 3: B reconnects C2S, both reconnect P2P =====
                    state.set_phase(3);

                    // B reconnects C2S
                    let conn2 = remote
                        .connect_with_defaults(AuthenticationRequest::credentialed(
                            username.clone(),
                            password,
                        ))
                        .await?;
                    log::info!("[Peer B] C2S Reconnected");
                    state.set_cid(conn2.cid).await;

                    // Rekey C2S
                    conn2.rekey().await?;
                    log::info!("[Peer B] C2S Rekey done after reconnect");

                    barrier3.wait().await;

                    // Reconnect P2P - already registered, just need to connect
                    let peer_handle2 = conn2.find_target(conn2.cid, peer_username.clone()).await?;
                    let p2p2 = peer_handle2.connect_to_peer().await?;
                    log::info!("[Peer B] P2P Reconnected");

                    let channel2 = p2p2.channel;
                    let (mut tx2, mut rx2) = channel2.split();

                    // Rekey P2P
                    p2p2.remote.rekey().await?;
                    log::info!("[Peer B] P2P Rekey done after reconnect");

                    // ===== PHASE 4: Post-Reconnect USE =====
                    state.set_phase(4);
                    barrier4.wait().await;

                    // Send 5 more messages
                    for i in 5..10 {
                        let msg = format!("B->A Message {}", i);
                        tx2.send(SecBuffer::from(msg.as_bytes())).await?;
                        state.increment_messages_sent();
                    }

                    // Receive 5 more messages
                    for _ in 0..5 {
                        let _msg = rx2.next().await;
                        state.increment_messages_received();
                    }

                    log::info!("[Peer B] Phase 4 complete");

                    // ===== PHASE 5: Verification =====
                    state.set_phase(5);

                    // B initiated P2P disconnect and C2S disconnect.
                    // May receive 0+ cleanup disconnects.
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer B (Test 5)",
                        0,  // c2s_connect (intercepted)
                        0,  // c2s_disconnect (intercepted)
                        0,  // p2p_connect (intercepted)
                        0,  // min p2p_disconnect_recv (B initiated)
                        10, // msgs_sent
                        10, // msgs_recv
                    );

                    conn2.shutdown_kernel().await
                }
            },
        );

        let client_a = NodeBuilder::default().build(client_a_kernel).unwrap();
        let client_b = NodeBuilder::default().build(client_b_kernel).unwrap();

        let clients = futures::future::try_join(client_a, client_b);

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .expect("Test timed out");

        assert!(result.is_ok(), "Test failed: {:?}", result);
        log::info!("Test 5 (P2P then ONE C2S Disconnect) PASSED");
    }
}
