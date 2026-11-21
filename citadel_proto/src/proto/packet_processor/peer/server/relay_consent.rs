//! A server relays a signal from one peer to another only along a live route it forged when the
//! responder accepted the pair's connect request: the server's record that both consented to this
//! pair. A key exchange is gated this way, and so are WebRTC signalling and relayed errors, so an
//! account cannot drive another session's connection setup or report errors into it.

use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use crate::proto::remote::Ticket;

/// The answer to a sender whose signal was not relayed: it names the pair, so a sender waiting on
/// the exchange it belongs to hears that it ended.
pub(crate) fn unconsented_relay(sender_cid: u64, target_cid: u64, ticket: Ticket) -> PeerSignal {
    PeerSignal::SignalError {
        ticket,
        error: citadel_io::error!(
            citadel_io::ErrorCode::PeerRelayNotConsented,
            sender_cid,
            target_cid
        )
        .into_string(),
        peer_connection_type: PeerConnectionType::LocalGroupPeer {
            session_cid: sender_cid,
            peer_cid: target_cid,
        },
    }
}
