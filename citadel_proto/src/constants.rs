//! Protocol Constants for Citadel Protocol
//!
//! This module defines the core constants used throughout the Citadel Protocol implementation.
//! These constants control protocol behavior, networking parameters, timing, and security settings.
//!
//! # Features
//! - **Version Management**: Protocol version control using semantic versioning
//! - **Network Parameters**: MTU sizes, header lengths, and payload limits
//! - **Timing Constants**: Keep-alive intervals, timeouts, and update frequencies
//! - **Buffer Settings**: Codec and group size limitations
//! - **Port Configuration**: Network port ranges and defaults
//! - **Security Levels**: Update frequency bases for different security levels
//!
//! # Important Notes
//! - Protocol version uses semantic versioning (major.minor.patch)
//! - All timing constants are in nanoseconds unless specified
//! - MTU is set for IPv6 compatibility (1280 bytes)
//! - Buffer sizes are optimized for typical use cases
//! - Security level update frequencies are configurable
//!
//! # Related Components
//! - `proto::packet`: Uses header and payload size constants
//! - `proto::codec`: Uses buffer capacity constants
//! - `proto::validation`: Uses timing constants
//! - `proto::state_subcontainers`: Uses security level constants
//!

use crate::proto::packet::HdpHeader;
use citadel_types::proto::UdpMode;
use embedded_semver::prelude::*;
use lazy_static::lazy_static;

// Note: these values can each be up to 1024 in size, but, to be safe, we fix the upper
// bound to 255 (u8::MAX) to ensure that the values fit inside the u32 bit packer
pub const MAJOR_VERSION: u8 = 0;
// Bumped 9 -> 10: the per-message nonce KDF changed from SHA3-256 to a BLAKE3 keyed-hash PRF
// (citadel_crypt entropy_bank::get_nonce). This is wire-breaking — a peer on the old derivation
// produces different nonces, so cross-version traffic must not interoperate.
// Bumped 10 -> 11: the hole-punch coordination stream now carries attempt-numbered frames
// (citadel_wire udp_traversal::paired_attempts). A peer on 0.10 sends unframed attempts, so the
// two cannot punch with each other. The same bump covers the additive changes that ship with it:
// key-exchange signals carry the sender's protocol version, media endpoints exchange
// transport offers (see `MEDIA_TRANSPORT_OFFER_SINCE`), and servers answer
// `GroupBroadcast::AwaitGroup` (see `AWAIT_GROUP_SINCE`).
// Bumped 11 -> 12: post-quantum sign-in (see `PQ_SIGN_IN_SINCE`). Additive like the patches before
// it: each side runs the new exchange only with a node at or above it, and an older node keeps the
// legacy Argon2 path, so 0.11 and 0.12 nodes still interoperate.
pub const MINOR_VERSION: u8 = 12;
// Bumped 0 -> 1: group members acknowledge each CGKA Commit to the server, which tells the owner
// once every member it reached has applied it, and the owner holds a joiner's Welcome until then
// (see `GROUP_COMMIT_ACK_SINCE`). Additive: each side uses it only with a peer at or above it.
// Bumped 1 -> 2: the server issues a resume token at connect SUCCESS, and a client's next login
// presents it, so a reconnect replaces the session the server still holds for that same client
// (see `SESSION_RESUME_SINCE`). Additive, like 0 -> 1.
// Reset to 0 by the minor bump to 12.
// Bumped 0 -> 1: a client may probe its server's liveness at any time (see `SERVER_PROBE_SINCE`),
// and peers can re-arm a P2P path campaign that gave up (see `PATH_REARM_SINCE`). Additive: each
// side uses them only with a node at or above it.
pub const PATCH_VERSION: u8 = 1;

/// The first protocol version whose media endpoints send and expect a transport offer as the
/// first message on the reliable lane. A peer below it, or of unknown version, gets none.
pub const MEDIA_TRANSPORT_OFFER_SINCE: (u8, u8, u8) = (0, 10, 1);

/// The first protocol version whose server answers `GroupBroadcast::AwaitGroup`. A joiner
/// talking to a server below it, or of unknown version, polls for the owner's group instead.
pub const AWAIT_GROUP_SINCE: (u8, u8, u8) = (0, 11, 0);

/// The first protocol version whose nodes take part in the group Commit acknowledgement: a member
/// sends `GroupBroadcast::CommitApplied` after processing a Commit, the server answers the owner
/// with `GroupBroadcast::CommitSettled` once every such member it delivered the Commit to has, and
/// the owner releases a joiner's Welcome only then. A node below it, or of unknown version, keeps
/// the earlier behaviour: an owner sends the Welcome at once, and a server waits on no member.
pub const GROUP_COMMIT_ACK_SINCE: (u8, u8, u8) = (0, 11, 1);

/// The first protocol version whose nodes exchange session resume tokens: a server issues one in
/// connect SUCCESS and accepts it back at STAGE0 as proof that a login is the held session's own
/// client (see `proto::session_resume`). A node below it, or of unknown version, sends and reads
/// none, and a login from it is refused while the server holds a session for the account.
pub const SESSION_RESUME_SINCE: (u8, u8, u8) = (0, 11, 2);

/// The first protocol version whose nodes run post-quantum sign-in (see `proto::pq_sign_in`): a
/// client sends connect `AUTH_START` before STAGE0 and register `PQ_START` before STAGE2, and the
/// server proves the account's ML-KEM factors. Since the Argon2 sunset it is the only password
/// sign-in: a client refuses to sign a password account in or up with a server below it, and a
/// server tells a client below it to update unless the sign-in is passwordless.
pub const PQ_SIGN_IN_SINCE: (u8, u8, u8) = (0, 12, 0);

/// The first protocol version whose server answers a liveness probe: a `KEEP_ALIVE` with
/// `cmd_aux` PROBE, echoed at once (see `proto::server_probe`). A server below it reads a probe as
/// a scheduled keep-alive and would start a second keep-alive cycle, so it is never sent one.
pub const SERVER_PROBE_SINCE: (u8, u8, u8) = (0, 12, 1);

/// The first protocol version whose P2P campaign, having given up, parks on the coordination
/// endpoint instead of ending, so either peer can re-arm it (`PeerChannel::upgrade`). With a peer
/// below it, or of unknown version, the campaign ends as before and an upgrade is refused.
pub const PATH_REARM_SINCE: (u8, u8, u8) = (0, 12, 1);

/// Whether an adjacent node's protocol version is known and at least `since`. An unknown or
/// unparseable version is not.
pub fn protocol_version_at_least(version: Option<u32>, since: (u8, u8, u8)) -> bool {
    let Some(version) = version.and_then(|v| Semver::from_u32(v).ok()) else {
        return false;
    };
    let since = (since.0 as usize, since.1 as usize, since.2 as usize);
    (version.major, version.minor, version.patch) >= since
}

lazy_static! {
    pub static ref PROTOCOL_VERSION: u32 =
        Semver::new(MAJOR_VERSION as _, MINOR_VERSION as _, PATCH_VERSION as _)
            .to_u32()
            .unwrap();
}

/// by default, the UDP is not initialized
pub const UDP_MODE: UdpMode = UdpMode::Disabled;
/// For calculating network latency
pub const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;
/// The HDP header len
pub const HDP_HEADER_BYTE_LEN: usize = std::mem::size_of::<HdpHeader>();
/// the initial reconnect delay
pub const INITIAL_RECONNECT_LOCKOUT_TIME_NS: i64 = NANOSECONDS_PER_SECOND;
pub const KEEP_ALIVE_INTERVAL_MS: u64 = 60000 * 15; // every 15 minutes
/// The keep alive max interval
pub const KEEP_ALIVE_TIMEOUT_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 3 * 1_000_000) as i64;
/// For setting up the GroupReceivers
pub const GROUP_TIMEOUT_MS: usize = KEEP_ALIVE_INTERVAL_MS as usize;
pub const INDIVIDUAL_WAVE_TIMEOUT_MS: usize = GROUP_TIMEOUT_MS / 2;
pub const DO_DEREGISTER_EXPIRE_TIME_NS: i64 = KEEP_ALIVE_TIMEOUT_NS;

/// The frequency at which KEEP_ALIVES need to be sent through the system
pub const FIREWALL_KEEP_ALIVE_UDP: std::time::Duration = std::time::Duration::from_secs(60);
/// The AEAD security level every UDP stream packet is sealed at unless the application calls
/// `OutboundUdpSender::set_security_level`. UDP is the low-latency, unreliable channel: a single
/// layer keeps per-datagram overhead at one `MESSAGE_PACKET_PER_LAYER_OVERHEAD` and maximises
/// the payload budget (each extra layer costs 32 bytes of a ~1.2 KB datagram).
pub const UDP_STREAM_SECURITY_LEVEL: citadel_types::crypto::SecurityLevel =
    citadel_types::crypto::SecurityLevel::Standard;
/// Maximum number of queued UDP payloads sealed under one crypto-state borrow and handed to the
/// transport sink before a flush. Bounds per-wake latency while amortising the StateContainer
/// lock across a burst (e.g. the fragments of one media frame).
pub const UDP_OUTBOUND_DRAIN_BATCH: usize = 32;
/// Maximum number of datagrams allowed to queue behind a stalled UDP sink before the oldest are
/// dropped. Real-time media wants fresh data to win over stale data; ~512 x 1.2 KB = ~600 KB.
pub const UDP_OUTBOUND_MAX_QUEUED: usize = 512;
/// Conservative per-datagram ceiling for the raw (hole-punched) UDP socket path: the IPv6
/// minimum MTU (1280) minus the IPv6 (40) and UDP (8) headers, so it is never fragmented on path.
pub const RAW_UDP_SAFE_DATAGRAM_LEN: usize = 1280 - 40 - 8;
/// How many bytes are stored
pub const CODEC_BUFFER_CAPACITY: usize = u16::MAX as usize;
/// The minimum number of bytes allocated in the codec
pub const CODEC_MIN_BUFFER: usize = 8192;
/// After the time defined below, any incomplete packet groups will be discarded
pub const GROUP_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(60000);
/// After this time, the registration state is invalidated
pub const DO_REGISTER_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(10000);
/// After this time, the connect state is invalidated
pub const DO_CONNECT_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(8000);
/// The minimum time (in nanoseconds) per rekey (nanoseconds per update)
pub const REKEY_UPDATE_FREQUENCY_STANDARD: u64 = 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per rekey (nanoseconds per update)
pub const REKEY_UPDATE_FREQUENCY_REINFORCED: u64 = 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per rekey (nanoseconds per update)
pub const REKEY_UPDATE_FREQUENCY_HIGH: u64 = 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per rekey (nanoseconds per update)
pub const REKEY_UPDATE_FREQUENCY_ULTRA: u64 = 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per rekey (nanoseconds per update)
pub const REKEY_UPDATE_FREQUENCY_EXTREME: u64 = 480 * 1_000_000_000;
/// For ensuring that the hole-punching process begin at about the same time (required)
/// this is applied to the ping. If the ping is 200ms, the a multiplier of 2.0 will mean that in 200*2.0 = 400ms,
/// the hole-punching process will begin
pub const HOLE_PUNCH_SYNC_TIME_MULTIPLIER: f64 = 2.0f64;
/// the preconnect + connect stage will be limited by this duration
pub const LOGIN_EXPIRATION_TIME: std::time::Duration = std::time::Duration::from_secs(20);
pub const TCP_CONN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

pub const MAX_OUTGOING_UNPROCESSED_REQUESTS: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;

    fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
        Some(Semver::new(major, minor, patch).to_u32().unwrap())
    }

    #[test]
    fn this_node_supports_media_transport_offers() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
    }

    #[test]
    fn an_older_or_unknown_version_is_not_at_least() {
        assert!(!protocol_version_at_least(
            version(0, 10, 0),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 9, 7),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
        assert!(!protocol_version_at_least(
            None,
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
        assert!(!protocol_version_at_least(
            Some(u32::MAX),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
    }

    #[test]
    fn a_newer_version_is_at_least() {
        assert!(protocol_version_at_least(
            version(0, 10, 1),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
        assert!(protocol_version_at_least(
            version(0, 11, 0),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
        assert!(protocol_version_at_least(
            version(1, 0, 0),
            MEDIA_TRANSPORT_OFFER_SINCE
        ));
    }
}
