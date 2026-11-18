//! Hole-punch packets that arrive before this node has registered the pipe they belong to.
//!
//! The two ends of a punch register their pipes at slightly different moments, so the first
//! frames from the faster end can arrive before the slower end's pipe exists. Those are held,
//! and only those: a packet is held only while a key exchange with its peer is in progress
//! (the punch runs only inside one), and at most [`MAX_EARLY_HOLE_PUNCH_PACKETS_PER_PEER`] per
//! peer. Anything else is dropped.

use super::includes::*;

/// The most early hole-punch packets held for one peer: well above the frames a punch sends
/// before both ends have registered their pipes.
pub(crate) const MAX_EARLY_HOLE_PUNCH_PACKETS_PER_PEER: usize = 32;

/// Whether one more early packet is held, given whether a key exchange with its peer is in
/// progress and how many are held for that peer already.
pub(crate) fn holds_early_packet(exchange_in_progress: bool, held: usize) -> bool {
    exchange_in_progress && held < MAX_EARLY_HOLE_PUNCH_PACKETS_PER_PEER
}

impl<R: Ratchet> StateContainerInner<R> {
    /// Holds `packet` for `peer_cid`'s pipe if [`holds_early_packet`] allows it. Returns whether
    /// it was held.
    pub(crate) fn hold_early_hole_punch_packet(&mut self, peer_cid: u64, packet: Bytes) -> bool {
        let exchange_in_progress = self.peer_kem_states.contains_key(&peer_cid);
        let held = self
            .pending_hole_punch_packets
            .get(&peer_cid)
            .map_or(0, Vec::len);
        if !holds_early_packet(exchange_in_progress, held) {
            return false;
        }
        self.pending_hole_punch_packets
            .entry(peer_cid)
            .or_default()
            .push(packet);
        true
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::super::test_support::state_container;
    use super::*;
    use citadel_io::tokio;

    const PEER_CID: u64 = 20;

    fn exchange_state<R: Ratchet>() -> PeerKemStateContainer<R> {
        PeerKemStateContainer::new(Default::default(), false, Default::default())
    }

    #[tokio::test]
    async fn early_packets_for_a_peer_are_held_up_to_the_cap() {
        let container = state_container(true, 0).await;
        let mut inner = inner_mut_state!(container);
        let _ = inner.peer_kem_states.insert(PEER_CID, exchange_state());
        let held = (0..1_000)
            .filter(|_| inner.hold_early_hole_punch_packet(PEER_CID, Bytes::from_static(b"punch")))
            .count();
        assert_eq!(held, MAX_EARLY_HOLE_PUNCH_PACKETS_PER_PEER);
        assert_eq!(
            inner.pending_hole_punch_packets[&PEER_CID].len(),
            MAX_EARLY_HOLE_PUNCH_PACKETS_PER_PEER
        );
    }

    #[tokio::test]
    async fn no_packet_is_held_for_a_peer_with_no_exchange_in_progress() {
        let container = state_container(true, 0).await;
        let mut inner = inner_mut_state!(container);
        for _ in 0..1_000 {
            assert!(!inner.hold_early_hole_punch_packet(PEER_CID, Bytes::from_static(b"punch")));
        }
        assert!(inner.pending_hole_punch_packets.is_empty());
    }
}
