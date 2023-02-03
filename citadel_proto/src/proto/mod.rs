use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::packet::HdpHeader;
use crate::proto::session::HdpSession;
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;

/// For the custom BytesCodec that doesn't overflow
pub(crate) mod codec;
///
pub(crate) mod endpoint_crypto_accessor;
pub(crate) mod misc;
/// Used at each HyperNode
pub mod node;
pub mod node_request;
pub mod node_result;
/// A cloneable handle for sending data through UDP ports
pub(crate) mod outbound_sender;
/// The fundamental packet types
pub(crate) mod packet;
/// For creating specific packet types
pub(crate) mod packet_crafter;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub(crate) mod packet_processor;
///
pub(crate) mod peer;
pub mod remote;
/// Each CID gets a session
pub(crate) mod session;
/// Manages multiple sessions
pub(crate) mod session_manager;
pub(crate) mod session_queue_handler;
/// For keeping track of the stages of different processes
pub(crate) mod state_container;
/// For organizing the stage containers
pub(crate) mod state_subcontainers;
/// ~!
pub(crate) mod transfer_stats;
/// Packet validations. This is not the same as encryption
pub(crate) mod validation;

/// Returns the preferred primary stream for returning a response
pub(crate) fn get_preferred_primary_stream(
    header: &HdpHeader,
    session: &HdpSession,
    state_container: &StateContainerInner,
) -> Option<OutboundPrimaryStreamSender> {
    if header.target_cid.get() != 0 {
        Some(
            state_container
                .get_preferred_stream(header.session_cid.get())
                .clone(),
        )
    } else {
        session.to_primary_stream.clone()
    }
}

pub(crate) fn send_with_error_logging(stream: &OutboundPrimaryStreamSender, packet: BytesMut) {
    if let Err(err) = stream.unbounded_send(packet) {
        log::error!(target: "citadel", "Error while sending packet outbound: {:?}", err)
    }
}
