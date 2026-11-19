//! The one constructor of the request that closes a P2P connection (S-P7): the channel's drop
//! closes without a reason, the negotiation lane's deliberate close with one.

use crate::proto::disconnect_tracker::DisconnectToken;
use crate::proto::node_request::{NodeRequest, PeerCommand};
use crate::proto::peer::negotiation::reason::DisconnectReason;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};

/// `PeerSignal::Disconnect` for `peer_conn_type`, as this side's request to its node.
pub(crate) fn p2p_disconnect_request(
    peer_conn_type: PeerConnectionType,
    disconnect_token: Option<DisconnectToken>,
    reason: Option<DisconnectReason>,
) -> NodeRequest {
    NodeRequest::PeerCommand(PeerCommand {
        session_cid: peer_conn_type.get_original_session_cid(),
        command: PeerSignal::Disconnect {
            peer_conn_type,
            disconnect_response: None,
            disconnect_token,
            reason,
        },
    })
}
