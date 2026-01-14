//! Test 3: P2P-Only Disconnect
//!
//! Verifies P2P can be re-established while C2S stays active.
//!
//! ## Causal Pathway
//!
//! ```text
//! C2S Register x2 → C2S Connect x2 → rekey() x2 →
//! P2P Register x2 (simultaneous) → P2P Connect x2 (simultaneous) → P2P rekey() x2 →
//! send P2P messages → B.p2p.disconnect() →
//! P2P Connect x2 → P2P rekey() x2 → send P2P messages
//! ```
//!
//! ## Signal Flow
//!
//! | Phase | Actor | Action | Signal to Other |
//! |-------|-------|--------|-----------------|
//! | 2 | B | p2p.disconnect() | A receives PeerDisconnect signal |
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
    async fn test_p2p_only_disconnect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2); // 2 clients only - server doesn't participate in barrier

        let state_a = Arc::new(NodeState::default());
        let state_b = Arc::new(NodeState::default());

        let (server, server_addr) = server_info::<StackedRatchet>();

        let uuid_a = Uuid::new_v4();
        let uuid_b = Uuid::new_v4();
        let username_a = format!("pra_{}", &uuid_a.to_string()[..8]);
        let username_b = format!("prb_{}", &uuid_b.to_string()[..8]);
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
        let peer_username_b = username_b.clone(); // For P2P with B
        let peer_username_a = username_a.clone(); // For P2P with A

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

                    // Wait for Peer B to complete C2S setup before P2P operations
                    wait_for_peers().await;
                    log::info!("[Peer A] All peers ready for P2P");

                    // P2P Register with B (use username, not UUID)
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

                    // ===== PHASE 2: Wait for B to disconnect P2P =====
                    state.set_phase(2);

                    // Drop channel refs to allow disconnect
                    drop(tx);
                    drop(rx);

                    barrier2.wait().await;

                    // Wait for P2P disconnect signal from B
                    citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;

                    log::info!(
                        "[Peer A] Phase 2 complete, p2p_disconnect_recv={}",
                        state.p2p_disconnect_received_count.load(Ordering::SeqCst)
                    );

                    // ===== PHASE 3: Reconnect P2P =====
                    state.set_phase(3);
                    barrier3.wait().await;

                    // Reconnect P2P - already registered, just need to connect
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

                    // A should have received at least 1 p2p disconnect signal from B in Phase 2.
                    // Additional cleanup disconnects may or may not arrive before assertions.
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer A (Test 3)",
                        0,  // c2s_connect (intercepted)
                        0,  // c2s_disconnect (N/A - C2S stays active)
                        0,  // p2p_connect (intercepted)
                        1,  // min p2p_disconnect_recv (at least 1 from B's Phase 2 disconnect)
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

                    // Wait for Peer A to complete C2S setup before P2P operations
                    wait_for_peers().await;
                    log::info!("[Peer B] All peers ready for P2P");

                    // P2P Register with A (use username, not UUID)
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

                    // ===== PHASE 2: B disconnects P2P (C2S stays active) =====
                    state.set_phase(2);

                    // Drop channel refs before disconnect
                    drop(tx);
                    drop(rx);

                    // Disconnect P2P only
                    p2p_remote.disconnect().await?;
                    log::info!("[Peer B] P2P disconnected (C2S still active)");

                    barrier2.wait().await;

                    // ===== PHASE 3: Reconnect P2P =====
                    state.set_phase(3);
                    barrier3.wait().await;

                    // Reconnect P2P - already registered, just need to connect
                    let peer_handle2 = conn.find_target(conn.cid, peer_username.clone()).await?;
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

                    // B initiated Phase 2 disconnect (no signal for that).
                    // B may receive 0+ cleanup disconnects from second P2P connection at test end.
                    state.assert_final_state_with_min_p2p_disconnect(
                        "Peer B (Test 3)",
                        0,  // c2s_connect (intercepted)
                        0,  // c2s_disconnect (N/A - C2S stays active)
                        0,  // p2p_connect (intercepted)
                        0,  // min p2p_disconnect_recv (B initiated, so 0 required)
                        10, // msgs_sent
                        10, // msgs_recv
                    );

                    conn.shutdown_kernel().await
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
        log::info!("Test 3 (P2P-Only Disconnect) PASSED");
    }
}
