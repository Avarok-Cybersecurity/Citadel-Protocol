//! Real-time audio/video transport over a Citadel connection.
//!
//! Binds the I/O-free [`citadel_media`] primitives (packetizer, reassembler,
//! jitter buffer, send-queue policy, control messages) to a live connection:
//!
//! * **Unreliable** mode: media fragments travel over the session's UDP
//!   channel (`UdpMode::Enabled`), control messages over the ordered-reliable
//!   channel.
//! * **Reliable** mode (no UDP channel arrived within `udp_wait`): everything
//!   travels over the ordered-reliable channel; the receiver demuxes by wire
//!   message type.
//!
//! Entry point: [`MediaEndpoint::from_peer_connection`] /
//! [`MediaEndpoint::from_c2s`], then [`MediaEndpoint::split`].
//!
//! Dropping a [`MediaReceiver`] drops the UDP receive half it owns, which
//! signals `PeerSignal::DisconnectUDP` to the peer — keep it alive for the
//! lifetime of the call.

mod config;
mod endpoint;
mod eos;
pub mod error;
mod receiver;
mod sender;
mod transport;

#[cfg(test)]
mod tests;

pub use config::{
    MediaTransportConfig, RECOMMENDED_FRAGMENT_PAYLOAD, RECOMMENDED_UDP_PAYLOAD_BUDGET,
};
pub use endpoint::{MediaEndpoint, MediaEndpointParts};
pub use receiver::{MediaEvent, MediaReceiver};
pub use sender::MediaSender;
pub use transport::{MediaDatagramSink, MediaDatagramSource, MediaTransportKind, ReliableSink};
