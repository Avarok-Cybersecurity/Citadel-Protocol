//! Ending a P2P virtual connection: the one place every teardown path gives back what the
//! connection held.

use super::includes::*;
use super::peer_keys::STALE_P2P_RATCHET_TTL;

impl<R: Ratchet> StateContainerInner<R> {
    /// Ends the P2P connection with `peer_cid` and returns its vconn, if there was one.
    ///
    /// - Its UDP channel is closed.
    /// - Its ratchet is kept for [`STALE_P2P_RATCHET_TTL`], so packets already in flight still
    ///   open, and then dropped.
    /// - Its session password is dropped, unless a newer attempt with the peer has begun and
    ///   holds it. Without one, a later key exchange from the peer answers no request and is
    ///   refused.
    pub(crate) fn end_virtual_connection(&mut self, peer_cid: u64) -> Option<VirtualConnection<R>> {
        self.remove_udp_channel(peer_cid);
        let vconn = self.active_virtual_connections.remove(&peer_cid)?;
        let connection_id = vconn.p2p_connection_id;

        if !self.has_newer_attempt(peer_cid, connection_id) {
            self.peer_keys.remove_password(peer_cid);
        }

        if let Some(ratchet) = vconn.get_endpoint_ratchet(None) {
            self.peer_keys
                .keep_stale_ratchet(peer_cid, ratchet, connection_id);
            match self.queue_handle.get() {
                Some(queue) => queue.insert_oneshot(STALE_P2P_RATCHET_TTL, move |state| {
                    let _ = state
                        .peer_keys
                        .expire_stale_ratchet(peer_cid, connection_id);
                }),
                // No queue worker means no session running to receive anything in flight.
                None => self.peer_keys.forget_stale_ratchet(peer_cid),
            }
        }

        Some(vconn)
    }

    /// Whether a connect attempt with `peer_cid` other than `connection_id` is under way.
    fn has_newer_attempt(&self, peer_cid: u64, connection_id: Ticket) -> bool {
        self.outgoing_peer_connect_attempts.contains_key(&peer_cid)
            || self
                .peer_kem_states
                .get(&peer_cid)
                .is_some_and(|kem| kem.p2p_connection_id != connection_id)
    }
}
