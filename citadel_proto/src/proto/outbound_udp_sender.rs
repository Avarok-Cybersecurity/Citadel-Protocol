//! UDP datagram sender: the application-facing handle onto the per-session UDP subsystem.
//! Split out of `outbound_sender.rs` (exact piecewise copy) to respect the file-size limit.

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::proto::outbound_sender::UnboundedSender;
use crate::proto::packet::{packet_flags, packet_sizes};
use bytes::BytesMut;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecurityLevel;
use futures::task::{Context, Poll};
use futures::Sink;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// For keeping the firewall open
pub const KEEP_ALIVE: &[u8; 2] = b"KA";

/// One queued UDP payload: command aux flag, the AEAD level to seal it at, and the plaintext.
pub type UdpQueueItem = (u8, SecurityLevel, BytesMut);

#[derive(Clone)]
pub struct OutboundUdpSender {
    sender: UnboundedSender<UdpQueueItem>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    security_level: SecurityLevel,
    max_datagram_len: usize,
    dropped: Arc<AtomicU64>,
    pub(crate) needs_manual_ka: bool,
}

impl OutboundUdpSender {
    /// `max_datagram_len` is the transport's hard per-datagram ceiling (QUIC datagram limit, raw
    /// socket safe MTU, or SCTP message limit); `security_level` is the level every payload is
    /// sealed at until [`Self::set_security_level`] is called.
    pub fn new(
        sender: UnboundedSender<UdpQueueItem>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        needs_manual_ka: bool,
        security_level: SecurityLevel,
        max_datagram_len: usize,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        Self {
            sender,
            local_addr,
            remote_addr,
            security_level,
            max_datagram_len,
            dropped,
            needs_manual_ka,
        }
    }

    /// Enqueues one datagram payload. Fails fast if it cannot fit in a datagram at the current
    /// security level; the subsystem itself is never torn down by an oversized payload.
    pub fn unbounded_send<T: Into<BytesMut>>(&self, packet: T) -> Result<(), NetworkError> {
        let packet = packet.into();
        let max = self.max_payload_len();
        if packet.len() > max {
            return Err(error!(ErrorCode::UdpDatagramTooLarge, packet.len(), max));
        }
        self.sender
            .unbounded_send((
                packet_flags::cmd::aux::udp::STREAM,
                self.security_level,
                packet,
            ))
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    pub fn send_keep_alive(&self) -> bool {
        self.sender
            .unbounded_send((
                packet_flags::cmd::aux::udp::KEEP_ALIVE,
                self.security_level,
                BytesMut::from(&KEEP_ALIVE[..]),
            ))
            .is_ok()
    }

    /// Changes the AEAD level applied to subsequently enqueued payloads. The receiver reads the
    /// level from each packet header, so no negotiation is required.
    pub fn set_security_level(&mut self, security_level: SecurityLevel) {
        self.security_level = security_level;
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// The transport's hard per-datagram ceiling, including the Citadel header and AEAD trailer.
    pub fn max_datagram_len(&self) -> usize {
        self.max_datagram_len
    }

    /// Largest application payload that fits in one datagram at the current security level.
    pub fn max_payload_len(&self) -> usize {
        let layers = self.security_level.value() as usize + 1;
        self.max_datagram_len
            .saturating_sub(HDP_HEADER_BYTE_LEN + packet_sizes::protection_overhead(layers))
    }

    /// Number of queued datagrams discarded because the transport sink stalled.
    pub fn dropped_datagrams(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Sink<BytesMut> for OutboundUdpSender {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_ready(cx)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
        let max = self.max_payload_len();
        if item.len() > max {
            return Err(error!(ErrorCode::UdpDatagramTooLarge, item.len(), max));
        }
        let level = self.security_level;
        Pin::new(&mut self.sender)
            .start_send((packet_flags::cmd::aux::udp::STREAM, level, item))
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_flush(cx)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sender)
            .poll_close(cx)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }
}

impl std::fmt::Debug for OutboundUdpSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP Sender")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::outbound_sender::unbounded;

    type Rx = crate::proto::outbound_sender::UnboundedReceiver<UdpQueueItem>;

    fn sender(level: SecurityLevel, max_datagram_len: usize) -> (OutboundUdpSender, Rx) {
        let (tx, rx) = unbounded();
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let sender = OutboundUdpSender::new(
            tx,
            addr,
            addr,
            false,
            level,
            max_datagram_len,
            Arc::new(AtomicU64::new(0)),
        );
        (sender, rx)
    }

    #[test]
    fn payload_budget_subtracts_header_and_one_trailer_per_layer() {
        let (mut s, _rx) = sender(SecurityLevel::Standard, 1248);
        assert_eq!(s.max_payload_len(), 1248 - HDP_HEADER_BYTE_LEN - 32);
        s.set_security_level(SecurityLevel::Reinforced);
        assert_eq!(s.max_payload_len(), 1248 - HDP_HEADER_BYTE_LEN - 64);
    }

    #[test]
    fn oversized_payload_is_rejected_before_queueing() {
        let (s, _rx) = sender(SecurityLevel::Standard, 1248);
        let max = s.max_payload_len();
        assert!(s.unbounded_send(BytesMut::zeroed(max)).is_ok());
        let err = s.unbounded_send(BytesMut::zeroed(max + 1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UdpDatagramTooLarge);
    }

    #[test]
    fn tiny_transport_budget_saturates_to_zero() {
        assert_eq!(sender(SecurityLevel::Standard, 10).0.max_payload_len(), 0);
    }
}
