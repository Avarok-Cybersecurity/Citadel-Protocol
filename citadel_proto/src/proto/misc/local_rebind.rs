//! A node's handle on the transports that can follow it to a new local address.
//!
//! Every client-role QUIC endpoint the node opens (a C2S QUIC connection, the dialing side of a
//! direct P2P path, and the dialing side of a TURN path that sends plain UDP to the peer's relay)
//! is tracked here, and [`LocalRebinder::rebind_local`] moves each one to a fresh socket, so the
//! connections on it migrate without a new handshake (see `citadel_wire::quic_rebind`).
//!
//! Not tracked, because they cannot migrate this way: QUIC listeners (only a QUIC client can
//! change address), a dialer that sends through its own TURN allocation (the allocation itself is
//! bound to the old address), TCP/TLS/WebSocket transports, and the raw hole-punched UDP socket.
//!
//! Local only: nothing new crosses the wire, so no protocol version gates it.

use crate::error::NetworkError;
use citadel_wire::quic_rebind::RebindReport;

#[derive(Clone)]
pub struct LocalRebinder {
    #[cfg(not(target_family = "wasm"))]
    quic: citadel_wire::quic_rebind::LiveQuicEndpoints,
}

impl LocalRebinder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_family = "wasm"))]
            quic: citadel_wire::quic_rebind::LiveQuicEndpoints::new(),
        }
    }

    /// Tracks the endpoint of an established client-role QUIC connection.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn track_quic_client(&self, endpoint: citadel_wire::exports::Endpoint) {
        self.quic.track(endpoint)
    }

    /// Moves every tracked endpoint with an open connection to a fresh socket on the current
    /// local address. A failure to move one endpoint is reported in the result, not hidden; it
    /// keeps its old socket.
    #[cfg(not(target_family = "wasm"))]
    pub fn rebind_local(&self) -> Result<RebindReport, NetworkError> {
        Ok(self.quic.rebind_all())
    }

    /// A browser node's transports belong to the browser, which follows address changes itself.
    #[cfg(target_family = "wasm")]
    pub fn rebind_local(&self) -> Result<RebindReport, NetworkError> {
        Err(citadel_io::error!(
            citadel_io::ErrorCode::RebindLocalUnsupported
        ))
    }
}
