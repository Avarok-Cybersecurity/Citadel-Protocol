//! Shared test utilities for Citadel SDK reconnection tests.
//!
//! This module provides common infrastructure for testing reconnection scenarios:
//! - `NodeState`: Tracks signals and state for a single node across all phases
//! - `ReconnectionTestKernel`: Custom kernel that tracks events via NodeState

#![allow(dead_code)]

use citadel_io::tokio::sync::Mutex;
use citadel_sdk::async_trait;
use citadel_sdk::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

/// Shared state tracker for a single node across all test phases.
///
/// Tracks:
/// - CID consistency (should never change for a given account)
/// - Current phase (0-5)
/// - C2S connect/disconnect counts
/// - P2P connect/disconnect counts
/// - Rekey success counts
/// - Message sent/received counts
#[derive(Debug)]
pub struct NodeState {
    /// The CID assigned to this node (should be permanent per account)
    pub cid: Mutex<Option<u64>>,
    /// Current phase (0-5)
    pub phase: AtomicU8,
    /// Signals received - C2S
    pub c2s_connect_success_count: AtomicUsize,
    pub c2s_disconnect_count: AtomicUsize,
    /// Signals received - P2P
    pub p2p_connect_success_count: AtomicUsize,
    /// PeerSignal::Disconnect received FROM PEER (not self-initiated)
    pub p2p_disconnect_received_count: AtomicUsize,
    /// Rekey success count (C2S and P2P combined)
    pub rekey_success_count: AtomicUsize,
    /// Messages sent and received
    pub messages_sent: AtomicUsize,
    pub messages_received: AtomicUsize,
    /// CID consistency check - should never change
    pub cid_consistent: AtomicBool,
}

impl Default for NodeState {
    fn default() -> Self {
        Self {
            cid: Mutex::new(None),
            phase: AtomicU8::new(0),
            c2s_connect_success_count: AtomicUsize::new(0),
            c2s_disconnect_count: AtomicUsize::new(0),
            p2p_connect_success_count: AtomicUsize::new(0),
            p2p_disconnect_received_count: AtomicUsize::new(0),
            rekey_success_count: AtomicUsize::new(0),
            messages_sent: AtomicUsize::new(0),
            messages_received: AtomicUsize::new(0),
            cid_consistent: AtomicBool::new(true),
        }
    }
}

impl NodeState {
    pub fn set_phase(&self, phase: u8) {
        self.phase.store(phase, Ordering::SeqCst);
    }

    pub fn get_phase(&self) -> u8 {
        self.phase.load(Ordering::SeqCst)
    }

    pub fn increment_messages_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increment_messages_received(&self) {
        self.messages_received.fetch_add(1, Ordering::SeqCst);
    }

    pub async fn set_cid(&self, new_cid: u64) {
        let mut cid_guard = self.cid.lock().await;
        if let Some(old_cid) = *cid_guard {
            if old_cid != new_cid {
                log::error!(
                    "CID changed from {} to {} - this should NEVER happen!",
                    old_cid,
                    new_cid
                );
                self.cid_consistent.store(false, Ordering::SeqCst);
            }
        }
        *cid_guard = Some(new_cid);
    }

    pub async fn get_cid(&self) -> Option<u64> {
        *self.cid.lock().await
    }

    /// Process a NodeResult and update state accordingly.
    /// This is called for unsolicited events (not intercepted by remote_ext subscriptions).
    pub async fn process_node_event<R: Ratchet>(&self, event: &NodeResult<R>) {
        match event {
            // Note: ConnectSuccess is typically intercepted by connect() subscription
            // but we track it here for unexpected cases
            NodeResult::ConnectSuccess(ConnectSuccess { session_cid, .. }) => {
                log::trace!(
                    "NodeState: ConnectSuccess received (unsolicited) cid={}",
                    session_cid
                );
                self.set_cid(*session_cid).await;
                self.c2s_connect_success_count
                    .fetch_add(1, Ordering::SeqCst);
            }

            // C2S Disconnect event - NodeResult::Disconnect is for C2S only
            // P2P disconnects come via NodeResult::PeerEvent(PeerSignal::Disconnect)
            NodeResult::Disconnect(Disconnect { .. }) => {
                log::trace!("NodeState: C2S Disconnect received (unsolicited)");
                self.c2s_disconnect_count.fetch_add(1, Ordering::SeqCst);
            }

            // P2P Channel Created - typically intercepted by connect_to_peer()
            NodeResult::PeerChannelCreated(PeerChannelCreated { .. }) => {
                log::trace!("NodeState: PeerChannelCreated received (unsolicited)");
                self.p2p_connect_success_count
                    .fetch_add(1, Ordering::SeqCst);
            }

            // P2P Disconnect - NodeResult::PeerEvent(PeerSignal::Disconnect) is for P2P
            NodeResult::PeerEvent(PeerEvent {
                event: PeerSignal::Disconnect { .. },
                ..
            }) => {
                log::trace!("NodeState: P2P Disconnect received via PeerEvent");
                self.p2p_disconnect_received_count
                    .fetch_add(1, Ordering::SeqCst);
            }

            // Rekey result - typically intercepted by rekey() subscription
            NodeResult::ReKeyResult(ReKeyResult { .. }) => {
                log::trace!("NodeState: ReKeyResult received (unsolicited)");
                self.rekey_success_count.fetch_add(1, Ordering::SeqCst);
            }

            _ => {
                // Other events we don't track
            }
        }
    }

    /// Assert final state matches expected values.
    #[allow(clippy::too_many_arguments)]
    pub fn assert_final_state(
        &self,
        name: &str,
        expected_c2s_connect: usize,
        expected_c2s_disconnect: usize,
        expected_p2p_connect: usize,
        expected_p2p_disconnect_recv: usize,
        expected_msgs_sent: usize,
        expected_msgs_recv: usize,
    ) {
        let cid_consistent = self.cid_consistent.load(Ordering::SeqCst);
        let c2s_connect = self.c2s_connect_success_count.load(Ordering::SeqCst);
        let c2s_disconnect = self.c2s_disconnect_count.load(Ordering::SeqCst);
        let p2p_connect = self.p2p_connect_success_count.load(Ordering::SeqCst);
        let p2p_disconnect = self.p2p_disconnect_received_count.load(Ordering::SeqCst);
        let msgs_sent = self.messages_sent.load(Ordering::SeqCst);
        let msgs_recv = self.messages_received.load(Ordering::SeqCst);

        log::info!(
            "[{}] Final state: cid_consistent={}, c2s_connect={}/{}, c2s_disconnect={}/{}, p2p_connect={}/{}, p2p_disconnect_recv={}/{}, msgs_sent={}/{}, msgs_recv={}/{}",
            name, cid_consistent,
            c2s_connect, expected_c2s_connect,
            c2s_disconnect, expected_c2s_disconnect,
            p2p_connect, expected_p2p_connect,
            p2p_disconnect, expected_p2p_disconnect_recv,
            msgs_sent, expected_msgs_sent,
            msgs_recv, expected_msgs_recv
        );

        assert!(
            cid_consistent,
            "[{}] CID changed during test - should be permanent per account",
            name
        );
        assert_eq!(
            c2s_connect, expected_c2s_connect,
            "[{}] c2s_connect mismatch",
            name
        );
        assert_eq!(
            c2s_disconnect, expected_c2s_disconnect,
            "[{}] c2s_disconnect mismatch",
            name
        );
        assert_eq!(
            p2p_connect, expected_p2p_connect,
            "[{}] p2p_connect mismatch",
            name
        );
        assert_eq!(
            p2p_disconnect, expected_p2p_disconnect_recv,
            "[{}] p2p_disconnect_recv mismatch",
            name
        );
        assert_eq!(
            msgs_sent, expected_msgs_sent,
            "[{}] msgs_sent mismatch",
            name
        );
        assert_eq!(
            msgs_recv, expected_msgs_recv,
            "[{}] msgs_recv mismatch",
            name
        );
    }

    /// Assert final state with minimum P2P disconnect count.
    /// Use this when cleanup disconnects cause non-deterministic counts.
    #[allow(clippy::too_many_arguments)]
    pub fn assert_final_state_with_min_p2p_disconnect(
        &self,
        name: &str,
        expected_c2s_connect: usize,
        expected_c2s_disconnect: usize,
        expected_p2p_connect: usize,
        min_p2p_disconnect_recv: usize,
        expected_msgs_sent: usize,
        expected_msgs_recv: usize,
    ) {
        let cid_consistent = self.cid_consistent.load(Ordering::SeqCst);
        let c2s_connect = self.c2s_connect_success_count.load(Ordering::SeqCst);
        let c2s_disconnect = self.c2s_disconnect_count.load(Ordering::SeqCst);
        let p2p_connect = self.p2p_connect_success_count.load(Ordering::SeqCst);
        let p2p_disconnect = self.p2p_disconnect_received_count.load(Ordering::SeqCst);
        let msgs_sent = self.messages_sent.load(Ordering::SeqCst);
        let msgs_recv = self.messages_received.load(Ordering::SeqCst);

        log::info!(
            "[{}] Final state: cid_consistent={}, c2s_connect={}/{}, c2s_disconnect={}/{}, p2p_connect={}/{}, p2p_disconnect_recv={}>={}, msgs_sent={}/{}, msgs_recv={}/{}",
            name, cid_consistent,
            c2s_connect, expected_c2s_connect,
            c2s_disconnect, expected_c2s_disconnect,
            p2p_connect, expected_p2p_connect,
            p2p_disconnect, min_p2p_disconnect_recv,
            msgs_sent, expected_msgs_sent,
            msgs_recv, expected_msgs_recv
        );

        assert!(
            cid_consistent,
            "[{}] CID changed during test - should be permanent per account",
            name
        );
        assert_eq!(
            c2s_connect, expected_c2s_connect,
            "[{}] c2s_connect mismatch",
            name
        );
        assert_eq!(
            c2s_disconnect, expected_c2s_disconnect,
            "[{}] c2s_disconnect mismatch",
            name
        );
        assert_eq!(
            p2p_connect, expected_p2p_connect,
            "[{}] p2p_connect mismatch",
            name
        );
        assert!(
            p2p_disconnect >= min_p2p_disconnect_recv,
            "[{}] p2p_disconnect_recv too low: {} < {}",
            name,
            p2p_disconnect,
            min_p2p_disconnect_recv
        );
        assert_eq!(
            msgs_sent, expected_msgs_sent,
            "[{}] msgs_sent mismatch",
            name
        );
        assert_eq!(
            msgs_recv, expected_msgs_recv,
            "[{}] msgs_recv mismatch",
            name
        );
    }
}

/// Custom kernel that tracks state via NodeState and forwards events to a callback.
///
/// This kernel is designed for reconnection tests where we need to:
/// 1. Track events that arrive via `on_node_event_received` (unsolicited events)
/// 2. Execute test logic in `on_start`
/// 3. Use the same kernel across different reconnection scenarios
pub struct ReconnectionTestKernel<F, Fut, R: Ratchet> {
    pub state: Arc<NodeState>,
    pub handler: Mutex<Option<F>>,
    pub remote: Option<NodeRemote<R>>,
    // by using fn() -> (F, Fut), the future does not need to be Sync
    pub _pd: std::marker::PhantomData<fn() -> (F, Fut)>,
}

impl<F, Fut, R: Ratchet> std::fmt::Debug for ReconnectionTestKernel<F, Fut, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconnectionTestKernel")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<F, Fut, R: Ratchet> ReconnectionTestKernel<F, Fut, R>
where
    F: FnOnce(NodeRemote<R>, Arc<NodeState>) -> Fut + Send,
    Fut: std::future::Future<Output = Result<(), NetworkError>> + Send,
{
    pub fn new(state: Arc<NodeState>, handler: F) -> Self {
        Self {
            state,
            handler: Mutex::new(Some(handler)),
            remote: None,
            _pd: Default::default(),
        }
    }
}

#[async_trait]
impl<F, Fut, R: Ratchet> NetKernel<R> for ReconnectionTestKernel<F, Fut, R>
where
    F: FnOnce(NodeRemote<R>, Arc<NodeState>) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), NetworkError>> + Send,
{
    fn load_remote(&mut self, node_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.remote = Some(node_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let remote = self.remote.clone().unwrap();
        let handler = self.handler.lock().await.take().unwrap();
        let state = self.state.clone();

        handler(remote, state).await
    }

    async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
        // Process unsolicited events and update state
        self.state.process_node_event(&message).await;
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
