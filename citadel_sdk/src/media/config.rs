use super::error::MediaResultExt;
use citadel_io::time::Duration;
use citadel_media::{MediaConfig, FRAGMENT_HEADER_LEN};
use citadel_proto::prelude::NetworkError;

/// Recommended upper bound on the plaintext bytes handed to the UDP channel per
/// datagram across every transport. Measured floors: the P2P QUIC connection
/// reports a 1162-byte datagram ceiling at spawn (=> 1066 B payload after the
/// 64-byte HDP header + 32-byte AEAD at `SecurityLevel::Standard`); the raw
/// hole-punched socket allows 1232 B datagrams (=> 1136 B). 1024 fits both
/// with headroom for one extra AEAD layer.
///
/// The endpoint verifies the budget against the live transport's
/// `OutboundUdpSender::max_payload_len()`; this constant is only a safe
/// starting point for callers.
pub const RECOMMENDED_UDP_PAYLOAD_BUDGET: usize = 1024;

/// Recommended [`MediaConfig::max_fragment_payload`]:
/// `RECOMMENDED_UDP_PAYLOAD_BUDGET - FRAGMENT_HEADER_LEN` = 1004, rounded down.
pub const RECOMMENDED_FRAGMENT_PAYLOAD: usize = 1000;

/// Transport tunables for a [`super::MediaEndpoint`]. Every field is mandatory
/// (no `Default`); call [`MediaTransportConfig::validate`] before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaTransportConfig {
    /// Packetizer / reassembler / jitter-buffer settings.
    pub media: MediaConfig,
    /// Capacity of the outbound [`citadel_media::SendQueue`] in frames.
    pub send_queue_frames: usize,
    /// Maximum plaintext bytes per datagram handed to the unreliable sink.
    /// Must be at least `media.max_fragment_payload + FRAGMENT_HEADER_LEN`.
    pub udp_payload_budget: usize,
    /// How long to wait for the session's UDP channel before falling back to
    /// the ordered-reliable channel.
    pub udp_wait: Duration,
}

impl MediaTransportConfig {
    pub fn validate(&self) -> Result<(), NetworkError> {
        self.media.validate().net()?;
        if self.send_queue_frames == 0 {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::MediaConfigInvalid,
                "send_queue_frames must be > 0"
            ));
        }
        let datagram = self
            .media
            .max_fragment_payload
            .saturating_add(FRAGMENT_HEADER_LEN);
        if datagram > self.udp_payload_budget {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::MediaConfigInvalid,
                format!(
                    "max_fragment_payload + {FRAGMENT_HEADER_LEN} = {datagram} exceeds udp_payload_budget {}",
                    self.udp_payload_budget
                )
            ));
        }
        Ok(())
    }

    /// The largest datagram this config will ever emit.
    pub const fn max_datagram_len(&self) -> usize {
        self.media.max_fragment_payload + FRAGMENT_HEADER_LEN
    }
}
