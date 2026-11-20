//! The task that carries an attached route and, when it ends, either falls the connection back
//! to the server relay (a live connection outlives its direct route) or tears it down (a
//! connection already closing).

use std::future::Future;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot::Receiver;
use citadel_io::ErrorCode;

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::RouteEnd;

pub(super) struct CarriedStream<R: Ratchet, T: PlatformOps, W, Rd> {
    pub(super) session: CitadelSession<R, T>,
    pub(super) peer_cid: u64,
    pub(super) route_id: u64,
    pub(super) connection_id: Ticket,
    pub(super) writer: W,
    pub(super) reader: Rd,
    pub(super) stopper: Receiver<()>,
}

async fn stopped(receiver: Receiver<()>) -> Result<(), NetworkError> {
    receiver
        .await
        .map_err(|err| NetworkError::generic(err.to_string()))?;
    Err(citadel_io::error!(ErrorCode::P2pStopperTriggered))
}

pub(super) fn carry_stream<R, T, W, Rd>(carried: CarriedStream<R, T, W, Rd>)
where
    R: Ratchet,
    T: PlatformOps,
    W: Future<Output = Result<(), NetworkError>> + ContextRequirements + 'static,
    Rd: Future<Output = Result<(), NetworkError>> + ContextRequirements + 'static,
{
    let CarriedStream {
        session: sess,
        peer_cid,
        route_id,
        connection_id,
        writer,
        reader,
        stopper,
    } = carried;
    let future = async move {
        let res = citadel_io::tokio::select! {
            res0 = writer => res0,
            res1 = reader => res1,
            res2 = stopped(stopper) => res2
        };

        // When the stopper fires, this stream was replaced or discarded by the CID tie-breaker
        // in insert_direct_p2p_connection. The surviving stream's handler will manage cleanup
        // when it exits. Skip cleanup here: both streams share the same p2p_connection_id
        // (from the same KEX), so is_current_connection would incorrectly match, destroying
        // the live connection's vconn and ratchet.
        let was_replaced = res
            .as_ref()
            .err()
            .is_some_and(|e| e.code == ErrorCode::P2pStopperTriggered);
        if was_replaced {
            log::trace!(target: "citadel", "[P2P-stream] Stream replaced by tie-breaker for peer {peer_cid}, skipping cleanup");
            return res;
        }
        if let Err(err) = &res {
            log::error!(target: "citadel", "[P2P-stream] P2P stream ending. Reason: {err}");
        }

        let mut state_container = inner_mut_state!(sess.state_container);
        // A live connection outlives its direct route: it falls back to the server relay.
        // Only a connection that is already closing is torn down here.
        let route_end = state_container.fall_back_to_server_relay(peer_cid, route_id);
        let is_current_connection = route_end == RouteEnd::ConnectionClosed
            && state_container
                .active_virtual_connections
                .get(&peer_cid)
                .map(|vconn| vconn.p2p_connection_id == connection_id)
                .unwrap_or(false);

        if route_end == RouteEnd::FellBack {
            log::info!(target: "citadel", "[P2P-stream] Direct route to peer {peer_cid} ended; the channel continues over the server relay");
        } else if is_current_connection {
            let _ = state_container.end_virtual_connection(peer_cid);
            // While C2S is up, dropping the vconn sends a Disconnect over it, and the server
            // answers down that same connection -- behind whatever the peer relayed first,
            // such as the final ack of a transfer it has stored. That answer ends the
            // transfers. Ending them here, on this stream's EOF, beat the ack whenever the
            // peer closed this stream after finishing.
            if !sess.state.is_connected() {
                let _ = state_container
                    .fail_transfers_with_peer(peer_cid, "the connection to this peer ended");
            }
            // Only clean up the kem_state if it belongs to the old connection. A new
            // connect_to_peer() may have already inserted fresh state for the next attempt.
            let kem_belongs_to_old = state_container
                .peer_kem_states
                .get(&peer_cid)
                .map(|kem| kem.p2p_connection_id == connection_id);
            if kem_belongs_to_old == Some(true) {
                state_container.peer_kem_states.remove(&peer_cid);
            }
            // Never remove `outgoing_peer_connect_attempts` here: the KEM stage arms CONSUME
            // the entry when the channel is created, so the old attempt's entry is already
            // gone by teardown time — any entry present now belongs to the NEXT attempt
            // (inserted at its connect dispatch). Removing it made that attempt's
            // PeerChannelCreated fall back to the raw exchange ticket, orphaning the caller's
            // connect_to_peer subscription.
        } else {
            log::trace!(target: "citadel", "[P2P-stream] Skipping cleanup for peer {peer_cid} — connection replaced by newer instance");
        }

        log::trace!(target: "citadel", "[P2P-stream] Dropping tri-joined future");
        res
    };
    spawn!(future);
}
