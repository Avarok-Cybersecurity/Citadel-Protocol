//! A UDP channel loaded after a P2P connection's first, by a path recovery that restored UDP
//! (see `peer::p2p_rearm`), goes to the application's `PeerChannel::take_restored_udp`.

use crate::proto::peer::channel::UdpChannel;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode, NetworkError};

pub(crate) fn deliver<R: Ratchet>(
    state_container: &StateContainerInner<R>,
    peer_cid: u64,
    channel: UdpChannel<R>,
) -> Result<(), NetworkError> {
    let sender = state_container
        .active_virtual_connections
        .get(&peer_cid)
        .and_then(|vconn| vconn.endpoint_container.as_ref())
        .and_then(|endpoint| endpoint.udp_restored.as_ref());
    let Some(sender) = sender else {
        log::error!(target: "citadel", "A restored UDP channel for peer {peer_cid} has no connection to go to");
        return Err(error!(ErrorCode::UdpStateContainerNoSender));
    };
    sender
        .send(channel)
        .map_err(|_| error!(ErrorCode::UdpChannelSendFailed))
}
