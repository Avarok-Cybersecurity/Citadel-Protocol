//! Attaching a direct route to a virtual connection, including the dual-connect tie-breaker.
//!
//! When both peers' attempts produce a connection, both sides keep the SAME one — the connection
//! on which the higher-CID peer is the client — and stop the other. A stopped route takes its
//! queued and in-flight messages with it, so the survivor re-sends every message the peer has not
//! acknowledged ([`DirectJournal`]) before carrying anything new; the receiver drops copies it
//! already delivered, so nothing is lost and nothing arrives twice.

use crate::functional::IfEqConditional;
use crate::proto::peer::direct_journal::DirectJournal;
use crate::proto::peer::p2p_conn_handler::DirectP2PRemote;

/// Attaches `provisional` into `slot` unless the tie-breaker keeps the existing route. Returns
/// whether `provisional` is now the route.
///
/// `implcid`: this node's CID, for the tie-breaker; 0 for C2S (never tie-broken).
pub(crate) fn attach(
    slot: &mut Option<DirectP2PRemote>,
    mut provisional: DirectP2PRemote,
    implcid: u64,
    peer_cid: u64,
    journal: &mut DirectJournal,
) -> bool {
    log::trace!(target: "citadel", "UPGRADING {} conn type", provisional.from_listener.if_eq(true, "listener").if_false("client"));

    // CID-based tie-breaker for simultaneous P2P connections (defense-in-depth).
    // Rule: Keep connection where the higher-CID peer is the client.
    // This ensures both peers converge on the SAME underlying connection.
    if let Some(existing) = slot.as_ref() {
        // Determine which connection type we should have based on CIDs
        // If implcid < peer_cid, we should be the listener (peer is client)
        let should_be_listener = implcid != 0 && implcid < peer_cid;

        if existing.from_listener == should_be_listener {
            // Existing connection is the correct type, discard provisional
            log::info!(target: "citadel",
                "P2P already has correct {} connection for peer {peer_cid}, discarding duplicate {} connection",
                existing.from_listener.if_eq(true, "listener").if_false("client"),
                provisional.from_listener.if_eq(true, "listener").if_false("client")
            );
            // Stop the provisional's handler cleanly
            if let Some(stopper) = provisional.stopper.take() {
                let _ = stopper.send(());
            }
            return false;
        } else if provisional.from_listener == should_be_listener {
            // Provisional is the correct type, replace existing
            log::info!(target: "citadel",
                "Replacing {} with correct {} P2P connection for peer {peer_cid} (CID tie-breaker: implcid={}, peer={})",
                existing.from_listener.if_eq(true, "listener").if_false("client"),
                provisional.from_listener.if_eq(true, "listener").if_false("client"),
                implcid, peer_cid
            );
            // Stop the existing handler cleanly before replacing
            if let Some(mut old) = slot.take() {
                if let Some(stopper) = old.stopper.take() {
                    let _ = stopper.send(());
                }
            }
        } else {
            // Neither matches expected type (edge case) - keep existing
            log::warn!(target: "citadel",
                "Neither connection matches expected type for peer {peer_cid}, keeping existing {} (expected {})",
                existing.from_listener.if_eq(true, "listener").if_false("client"),
                should_be_listener.if_eq(true, "listener").if_false("client")
            );
            if let Some(stopper) = provisional.stopper.take() {
                let _ = stopper.send(());
            }
            return false;
        }
    }

    // A replaced route took its queued and in-flight messages with it; send every one the peer
    // has not acknowledged again, ahead of anything new, on the survivor.
    let replayed = journal.replay_onto(&provisional.p2p_primary_stream);
    if replayed > 0 {
        log::info!(target: "citadel", "Re-sent {replayed} unacknowledged message(s) to peer {peer_cid} on the surviving direct route");
    }
    *slot = Some(provisional);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::outbound_sender::{
        unbounded, OutboundPacket, OutboundPrimaryStreamSender, UnboundedReceiver,
    };
    use crate::proto::peer::p2p_conn_handler::next_route_id;
    use bytes::BytesMut;

    fn route(
        from_listener: bool,
    ) -> (
        DirectP2PRemote,
        UnboundedReceiver<OutboundPacket>,
        citadel_io::tokio::sync::oneshot::Receiver<()>,
    ) {
        let (tx, rx) = unbounded();
        let (stop_tx, stop_rx) = citadel_io::tokio::sync::oneshot::channel();
        let remote = DirectP2PRemote {
            stopper: Some(stop_tx),
            p2p_primary_stream: OutboundPrimaryStreamSender::from(tx),
            from_listener,
            route_id: next_route_id(),
        };
        (remote, rx, stop_rx)
    }

    fn drain(rx: &mut UnboundedReceiver<OutboundPacket>) -> Vec<u8> {
        std::iter::from_fn(|| match rx.try_recv().ok()? {
            OutboundPacket::Contiguous(buf) => Some(buf[0]),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
    }

    /// This node (CID 5) is below its peer (CID 9), so the route it keeps is the one it listens
    /// on. The client-side route attached first and carried messages; the listener-side one
    /// replaces it.
    #[test]
    fn a_replaced_route_loses_no_unacknowledged_message() {
        let (implcid, peer_cid) = (5, 9);
        let mut slot = None;
        let mut journal = DirectJournal::default();

        let (first, _first_rx, mut first_stop) = route(false);
        assert!(attach(&mut slot, first, implcid, peer_cid, &mut journal));
        for id in 1u8..=4 {
            journal.record(id as u64, &BytesMut::from(&[id][..]));
        }
        journal.ack(1);

        let (survivor, mut survivor_rx, _survivor_stop) = route(true);
        let survivor_id = survivor.route_id;
        assert!(attach(&mut slot, survivor, implcid, peer_cid, &mut journal));
        assert!(
            first_stop.try_recv().is_ok(),
            "the replaced route is stopped"
        );
        assert_eq!(slot.as_ref().unwrap().route_id, survivor_id);
        assert_eq!(
            drain(&mut survivor_rx),
            vec![2, 3, 4],
            "every unacknowledged message is re-sent on the survivor, in order"
        );
    }

    #[test]
    fn a_discarded_duplicate_leaves_the_route_and_its_traffic_alone() {
        let (implcid, peer_cid) = (5, 9);
        let mut slot = None;
        let mut journal = DirectJournal::default();
        let (keeper, mut keeper_rx, _keeper_stop) = route(true);
        let keeper_id = keeper.route_id;
        assert!(attach(&mut slot, keeper, implcid, peer_cid, &mut journal));
        journal.record(1, &BytesMut::from(&[1u8][..]));

        let (duplicate, mut duplicate_rx, mut duplicate_stop) = route(false);
        assert!(!attach(
            &mut slot,
            duplicate,
            implcid,
            peer_cid,
            &mut journal
        ));
        assert!(duplicate_stop.try_recv().is_ok());
        assert_eq!(slot.as_ref().unwrap().route_id, keeper_id);
        assert!(drain(&mut keeper_rx).is_empty());
        assert!(drain(&mut duplicate_rx).is_empty());
    }
}
