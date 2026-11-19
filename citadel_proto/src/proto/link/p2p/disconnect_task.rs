//! The task that turns an attached route's disconnect signal into the peer's `Disconnect` over
//! C2S and the kernel's `PeerSignal::Disconnect`, once per connection and never for a stale one.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot::Receiver;
use citadel_types::crypto::SecurityLevel;

use crate::error::NetworkError;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::{NodeResult, PeerEvent};
use crate::proto::outbound_sender::UnboundedSender;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::negotiation::reason::PeerClosing;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::P2PDisconnectSignal;

pub(super) struct DisconnectReport<R: Ratchet, T: PlatformOps> {
    pub(super) session: CitadelSession<R, T>,
    pub(super) session_cid: DualRwLock<Option<u64>>,
    pub(super) kernel_tx: UnboundedSender<NodeResult<R>>,
    pub(super) peer_closing: Option<PeerClosing>,
    pub(super) signal: Receiver<P2PDisconnectSignal>,
}

pub(super) fn report_disconnects<R: Ratchet, T: PlatformOps>(report: DisconnectReport<R, T>) {
    let DisconnectReport {
        session,
        session_cid,
        kernel_tx,
        peer_closing,
        signal,
    } = report;
    let tracker = session.session_manager.disconnect_tracker();
    let session_ticket = session.kernel_ticket.get();
    spawn!(async move {
        let Ok(signal) = signal.await else {
            return;
        };
        log::trace!(target: "citadel", "P2P disconnect notification received for peer {}: {:?}", signal.peer_cid, signal.reason);
        if !tracker.try_p2p_disconnect(session_ticket, signal.peer_cid) {
            log::trace!(target: "citadel", "Skipping P2P D/C signal - already sent for session {:?} peer {}", session_ticket, signal.peer_cid);
            return;
        }
        if let Some(ref token) = signal.disconnect_token {
            let state_container = inner_state!(session.state_container);
            if let Some(current_vconn) = state_container
                .active_virtual_connections
                .get(&signal.peer_cid)
            {
                if current_vconn.p2p_connection_id != token.connection_id {
                    log::trace!(target: "citadel", "Rejecting stale P2P disconnect signal for peer {} — new connection exists (expected {:?}, got {:?})", signal.peer_cid, current_vconn.p2p_connection_id, token.connection_id);
                    return;
                }
            }
        }
        if let Some(local_cid) = session_cid.get() {
            tell_the_peer(&session, local_cid, &signal);
        }
        let local_cid = session_cid.get().unwrap_or(0);
        let disconnect_result = NodeResult::PeerEvent(PeerEvent {
            event: PeerSignal::Disconnect {
                peer_conn_type: PeerConnectionType::LocalGroupPeer {
                    session_cid: local_cid,
                    peer_cid: signal.peer_cid,
                },
                disconnect_response: Some(PeerResponse::Disconnected(format!(
                    "P2P disconnect: {:?}",
                    signal.reason
                ))),
                disconnect_token: signal.disconnect_token,
                reason: peer_closing.as_ref().and_then(|closing| closing.reason()),
            },
            ticket: signal.ticket.unwrap_or(Ticket(0)),
            session_cid: local_cid,
        });
        let _ = kernel_tx.unbounded_send(disconnect_result);
    });
}

/// Sends the peer `PeerSignal::Disconnect` over C2S, when C2S is still up.
fn tell_the_peer<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    local_cid: u64,
    signal: &P2PDisconnectSignal,
) {
    let peer_signal = PeerSignal::Disconnect {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: local_cid,
            peer_cid: signal.peer_cid,
        },
        disconnect_response: Some(PeerResponse::Disconnected(format!(
            "P2P disconnect: {:?}",
            signal.reason
        ))),
        disconnect_token: signal.disconnect_token,
        reason: None,
    };
    let Some(to_primary_stream) = session.to_primary_stream.as_ref() else {
        return;
    };
    let state_container = inner_state!(session.state_container);
    let Ok(c2s_container) = state_container.get_endpoint_container(C2S_IDENTITY_CID) else {
        return;
    };
    let Some(ratchet) = c2s_container.ratchet_manager.get_ratchet(None) else {
        return;
    };
    let timestamp = session.time_tracker.get_global_time_ns();
    let security_level = state_container
        .session_security_settings
        .map(|s| s.security_level)
        .unwrap_or(SecurityLevel::Standard);
    let packet = packet_crafter::peer_cmd::craft_peer_signal(
        &ratchet,
        peer_signal,
        signal.ticket.unwrap_or(Ticket(0)),
        timestamp,
        security_level,
    );
    let sent = packet.and_then(|packet| {
        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::msg(err.to_string()))
    });
    match sent {
        Err(err) => {
            log::warn!(target: "citadel", "Failed to send P2P disconnect signal via C2S: {err:?}")
        }
        Ok(()) => {
            log::trace!(target: "citadel", "Sent PeerSignal::Disconnect via C2S for peer {}", signal.peer_cid)
        }
    }
}
