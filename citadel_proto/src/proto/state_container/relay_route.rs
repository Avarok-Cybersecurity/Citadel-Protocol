//! The routes a server relays a peer pair's traffic on.
//!
//! A server forges a pair's routes when the responder accepts a connect request, and marks them
//! inactive when either side ends the connection. Only a live forged route carries relayed
//! packets or a key exchange: that is the server's record that both peers consented to this pair.

use super::VirtualConnection;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::outbound_udp_sender::OutboundUdpSender;
use citadel_crypt::ratchets::Ratchet;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

impl<R: Ratchet> VirtualConnection<R> {
    /// The senders a server relays this pair's packets on: `None` unless the server forged the
    /// route and the connection is still live.
    pub(crate) fn relay_route(
        &self,
    ) -> Option<&(Option<OutboundUdpSender>, OutboundPrimaryStreamSender)> {
        if !self.is_active.load(Ordering::SeqCst) {
            return None;
        }
        self.sender.as_ref()
    }
}

/// Whether a server relays a key exchange from this session to `peer_cid`: only along a live route
/// it forged for the pair, which exists only after the peer accepted this session's request.
pub(crate) fn admits_key_exchange<R: Ratchet>(
    routes: &HashMap<u64, VirtualConnection<R>>,
    peer_cid: u64,
) -> bool {
    routes
        .get(&peer_cid)
        .and_then(VirtualConnection::relay_route)
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::misc::dual_rwlock::DualRwLock;
    use crate::proto::remote::Ticket;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_types::proto::VirtualConnectionType;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    const PEER: u64 = 20;

    fn route(forged: bool, live: bool) -> VirtualConnection<StackedRatchet> {
        let (tx, _rx) = crate::proto::outbound_sender::unbounded();
        VirtualConnection {
            connection_type: VirtualConnectionType::LocalGroupPeer {
                session_cid: 10,
                peer_cid: PEER,
            },
            last_delivered_message_timestamp: DualRwLock::from(None),
            is_active: Arc::new(AtomicBool::new(live)),
            sender: forged.then(|| (None, OutboundPrimaryStreamSender::from(tx))),
            endpoint_container: None,
            adjacent_nat_type: None,
            p2p_connection_id: Ticket(0),
            peer_session_init_time: None,
        }
    }

    fn routes(forged: bool, live: bool) -> HashMap<u64, VirtualConnection<StackedRatchet>> {
        HashMap::from([(PEER, route(forged, live))])
    }

    #[test]
    fn a_live_forged_route_carries_the_pairs_traffic() {
        assert!(route(true, true).relay_route().is_some());
        assert!(admits_key_exchange(&routes(true, true), PEER));
    }

    #[test]
    fn an_ended_connection_relays_nothing() {
        assert!(route(true, false).relay_route().is_none());
        assert!(!admits_key_exchange(&routes(true, false), PEER));
    }

    #[test]
    fn a_route_the_server_did_not_forge_relays_nothing() {
        assert!(route(false, true).relay_route().is_none());
        assert!(!admits_key_exchange(&routes(false, true), PEER));
    }

    #[test]
    fn a_key_exchange_with_a_peer_that_never_accepted_is_not_relayed() {
        assert!(!admits_key_exchange(&routes(true, true), PEER + 1));
    }
}
