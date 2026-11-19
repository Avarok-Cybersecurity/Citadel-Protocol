//! The protocol's connect and stage timers, in one place (`ROBUST-CONNECTION-MANAGER.md` S-P5,
//! S-W1). Each value used to be written where it was read, across three crates, and the ones
//! derived from another (the posting TTL from the connect wait) were derived by hand.

use std::time::Duration;

/// One transport connect step to a server: a TCP connect, a TLS handshake, a QUIC upgrade, a
/// WebSocket handshake.
pub const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// A connect to a TURN server, which may sit across the internet rather than beside the Citadel
/// server: two and a half transport steps.
pub const TURN_CONNECT_TIMEOUT: Duration =
    Duration::from_millis(TRANSPORT_CONNECT_TIMEOUT.as_millis() as u64 * 5 / 2);

/// One P2P path stage planned without a stamped plan (the hole punch with its QUIC handshake, or
/// one TURN attempt), and the wait for the peer at a retry's rendezvous.
pub const P2P_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a P2P dial waits for the peer's answer through the server.
pub const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the server holds a dial's posting beyond the dialler's own wait, so the answer to a
/// dial still waited for is never refused for want of its posting.
pub const POSTING_SLACK: Duration = Duration::from_secs(5);

/// How long the server holds a P2P dial's posting.
pub const POSTING_TTL: Duration = Duration::from_millis(
    P2P_CONNECT_TIMEOUT.as_millis() as u64 + POSTING_SLACK.as_millis() as u64,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derived_timers_keep_their_values() {
        assert_eq!(TURN_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(POSTING_TTL, Duration::from_secs(65));
        assert!(POSTING_TTL > P2P_CONNECT_TIMEOUT);
    }
}
