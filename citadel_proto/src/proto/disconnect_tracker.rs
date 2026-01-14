//! Disconnect Signal Tracker
//!
//! Centralizes tracking of disconnect signals to ensure at most one signal
//! is sent to the kernel per unique session (C2S) or session/peer pair (P2P).
//!
//! This prevents duplicate disconnect signals from multiple code paths
//! (explicit disconnect, connection loss, Drop impl, etc.) from reaching
//! the kernel, which would cause test failures in reconnection scenarios.
//!
//! ## Key Design Decisions
//!
//! - Uses Ticket (UUID-based) to identify unique session instances, NOT CID
//! - This allows reconnection with the same CID to work correctly
//! - Each unique session gets exactly one C2S disconnect signal
//! - Each unique session/peer pair gets exactly one P2P disconnect signal

use crate::proto::remote::Ticket;
use citadel_io::Mutex;
use std::collections::HashSet;
use std::sync::Arc;

/// Tracks disconnect signals to ensure at most 1 per unique session/peer instance.
///
/// Uses Ticket (UUID-based) to identify unique sessions, allowing reconnection
/// with the same CID to work correctly. The same CID can have multiple sessions
/// over time (after reconnection), each with a unique Ticket.
#[derive(Clone, Default)]
pub struct DisconnectSignalTracker {
    inner: Arc<DisconnectSignalTrackerInner>,
}

#[derive(Default)]
struct DisconnectSignalTrackerInner {
    /// Unique session IDs (Ticket) that have received C2S disconnect signal to kernel
    c2s_disconnected: Mutex<HashSet<Ticket>>,
    /// (session_ticket, peer_cid) pairs that have received P2P disconnect signal to kernel
    p2p_disconnected: Mutex<HashSet<(Ticket, u64)>>,
}

impl DisconnectSignalTracker {
    /// Create a new disconnect signal tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to mark a C2S session as disconnected.
    ///
    /// Returns `true` if this is the first disconnect signal for this session
    /// (signal should be sent to kernel). Returns `false` if a disconnect signal
    /// has already been sent for this session (should NOT send again).
    ///
    /// # Arguments
    /// * `session_ticket` - Unique ID for this session instance (NOT the CID!)
    pub fn try_c2s_disconnect(&self, session_ticket: Ticket) -> bool {
        self.inner.c2s_disconnected.lock().insert(session_ticket)
    }

    /// Try to mark a P2P peer as disconnected for this session.
    ///
    /// Returns `true` if this is the first disconnect signal for this session/peer pair
    /// (signal should be sent to kernel). Returns `false` if a disconnect signal
    /// has already been sent (should NOT send again).
    ///
    /// # Arguments
    /// * `session_ticket` - Unique ID for this session instance
    /// * `peer_cid` - The CID of the peer being disconnected from
    pub fn try_p2p_disconnect(&self, session_ticket: Ticket, peer_cid: u64) -> bool {
        self.inner
            .p2p_disconnected
            .lock()
            .insert((session_ticket, peer_cid))
    }

    /// Clear all disconnect tracking state for a session.
    ///
    /// Called when a session is fully cleaned up to prevent memory leaks
    /// from accumulated Tickets.
    ///
    /// # Arguments
    /// * `session_ticket` - Unique ID for the session to clear
    #[allow(dead_code)]
    pub fn clear_session(&self, session_ticket: Ticket) {
        self.inner.c2s_disconnected.lock().remove(&session_ticket);
        self.inner
            .p2p_disconnected
            .lock()
            .retain(|(t, _)| *t != session_ticket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2s_disconnect_first_time() {
        let tracker = DisconnectSignalTracker::new();
        let ticket = Ticket::from(12345u128);

        // First call should return true (send signal)
        assert!(tracker.try_c2s_disconnect(ticket));
        // Second call should return false (already sent)
        assert!(!tracker.try_c2s_disconnect(ticket));
    }

    #[test]
    fn test_c2s_disconnect_different_sessions() {
        let tracker = DisconnectSignalTracker::new();
        let ticket1 = Ticket::from(111u128);
        let ticket2 = Ticket::from(222u128);

        // Each session can send one signal
        assert!(tracker.try_c2s_disconnect(ticket1));
        assert!(tracker.try_c2s_disconnect(ticket2));

        // But not twice
        assert!(!tracker.try_c2s_disconnect(ticket1));
        assert!(!tracker.try_c2s_disconnect(ticket2));
    }

    #[test]
    fn test_p2p_disconnect_first_time() {
        let tracker = DisconnectSignalTracker::new();
        let session_ticket = Ticket::from(12345u128);
        let peer_cid = 67890u64;

        // First call should return true
        assert!(tracker.try_p2p_disconnect(session_ticket, peer_cid));
        // Second call should return false
        assert!(!tracker.try_p2p_disconnect(session_ticket, peer_cid));
    }

    #[test]
    fn test_p2p_disconnect_different_peers() {
        let tracker = DisconnectSignalTracker::new();
        let session_ticket = Ticket::from(12345u128);
        let peer1 = 111u64;
        let peer2 = 222u64;

        // Each peer can get one signal per session
        assert!(tracker.try_p2p_disconnect(session_ticket, peer1));
        assert!(tracker.try_p2p_disconnect(session_ticket, peer2));

        // But not twice
        assert!(!tracker.try_p2p_disconnect(session_ticket, peer1));
    }

    #[test]
    fn test_clear_session() {
        let tracker = DisconnectSignalTracker::new();
        let ticket = Ticket::from(12345u128);
        let peer_cid = 67890u64;

        // Mark as disconnected
        tracker.try_c2s_disconnect(ticket);
        tracker.try_p2p_disconnect(ticket, peer_cid);

        // Clear the session
        tracker.clear_session(ticket);

        // Now it should accept signals again (new session with same ticket would be unusual,
        // but this tests the clear functionality)
        assert!(tracker.try_c2s_disconnect(ticket));
        assert!(tracker.try_p2p_disconnect(ticket, peer_cid));
    }

    #[test]
    fn test_clone_shares_state() {
        let tracker1 = DisconnectSignalTracker::new();
        let tracker2 = tracker1.clone();
        let ticket = Ticket::from(12345u128);

        // Mark via tracker1
        assert!(tracker1.try_c2s_disconnect(ticket));

        // tracker2 should see the same state
        assert!(!tracker2.try_c2s_disconnect(ticket));
    }
}
