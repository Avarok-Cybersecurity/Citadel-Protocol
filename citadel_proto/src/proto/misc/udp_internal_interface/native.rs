//! Native `UdpSplittableTypes`: QUIC datagrams or a raw hole-punched socket.

use super::quic::QuicUdpSocketConnector;
use super::raw::RawUdpSocketConnector;
use super::{UdpSink, UdpSplittable, UdpStream};
use crate::functional::PairMap;
use citadel_io::{error, ErrorCode, NetworkError};
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use std::net::SocketAddr;

// `pub` (not `pub(crate)`) because it is exposed through the public `PlatformOps` trait's
// method signatures; rustc 1.83+ rejects leaking a crate-private type through a public trait
// (E0446). The variant payload structs are likewise `pub` but keep their fields private.
pub enum UdpSplittableTypes {
    Quic(QuicUdpSocketConnector),
    Raw(RawUdpSocketConnector),
}

impl UdpSplittableTypes {
    pub fn split(self) -> (Box<dyn UdpSink>, Box<dyn UdpStream>) {
        match self {
            Self::Quic(quic) => quic
                .split_sink_stream()
                .map_left(|r| Box::new(r) as _)
                .map_right(|r| Box::new(r) as _),
            Self::Raw(raw) => raw
                .split_sink_stream()
                .map_left(|r| Box::new(r) as _)
                .map_right(|r| Box::new(r) as _),
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Quic(quic) => quic.local_addr(),
            Self::Raw(raw) => raw.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> TargettedSocketAddr {
        match self {
            Self::Quic(quic) => TargettedSocketAddr::new_invariant(quic.remote_address()),
            Self::Raw(raw) => TargettedSocketAddr::new_invariant(raw.peer_addr()),
        }
    }

    /// QUIC automatically handles keep alives, RAW UDP does not
    pub(crate) fn needs_manual_ka(&self) -> bool {
        matches!(self, UdpSplittableTypes::Raw(..))
    }

    /// Hard per-datagram ceiling of this transport (header + AEAD trailer + payload). Taken once
    /// at subsystem spawn: QUIC only ever grows it via PMTUD, so the initial value is a safe floor.
    pub(crate) fn max_datagram_len(&self) -> Result<usize, NetworkError> {
        match self {
            Self::Quic(quic) => quic.max_datagram_len().ok_or_else(|| {
                error!(
                    ErrorCode::UdpDatagramsUnsupported,
                    "QUIC datagrams disabled"
                )
            }),
            Self::Raw(_) => Ok(crate::constants::RAW_UDP_SAFE_DATAGRAM_LEN),
        }
    }
}
