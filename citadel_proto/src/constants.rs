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
// Bumped 1 -> 2: servers send their path policy at connect SUCCESS and stamp each peer pair's
// effective plan into the pair's key exchange (see `PATH_POLICY_SINCE`). Additive: a node below it
// neither sends nor reads either, and its peers plan their paths as before. In the same patch,
// servers honour a group's relay options (see `GROUP_RELAY_OPTIONS_SINCE`).
// Bumped 2 -> 3 (one release, several additive changes, each with its own gate at 0.12.3):
// P2P connections carry a negotiation lane, and a deliberate disconnect carries its reason (see
// `NEGOTIATION_SINCE`); a P2P connection's keys are derived from the pair it joins and the
// connection's id (see `IDENTITY_BOUND_SEAL_SINCE`); the coordination endpoints pair
// subscriptions by an exchanged id within a named topic, and time a synchronized start by a
// relative delay (see `EXCHANGED_SUBSCRIPTIONS_SINCE`); a server names its security-key relying
// party and a client creates the credential it enrols (see `SECURITY_KEY_CEREMONY_SINCE`).
// Additive: each side uses them only with a node at or above the gate, and with an older peer
// behaves as before.
// Bumped 3 -> 4 (the RobustConnectionManager release, one bump shared by every lane, §12.2): a
// P2P pair exchanges its ends' link-manager modes and runs the manager only when both are
// Managed (see `LINK_MODE_SINCE`), and a client may reattach a held session over a new path (see
// `LINK_REATTACH_SINCE`). Additive: with a peer below it, each behaves as before. In the same
// release, a device with no bundle recovers an account with its recovery phrase, and sessions
// set passwords and replace phrases (see `RECOVERY_SINCE`).
pub const PATCH_VERSION: u8 = 4;

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
/// server proves the account's ML-KEM factors instead of verifying an Argon2 hash. A client talking
/// to a server below it, or of unknown version, logs in and registers the legacy way; a server
/// receiving a legacy login checks it the legacy way, unless the account has already upgraded.
pub const PQ_SIGN_IN_SINCE: (u8, u8, u8) = (0, 12, 0);

/// The first protocol version whose server answers a liveness probe: a `KEEP_ALIVE` with
/// `cmd_aux` PROBE, echoed at once (see `proto::server_probe`). A server below it reads a probe as
/// a scheduled keep-alive and would start a second keep-alive cycle, so it is never sent one.
pub const SERVER_PROBE_SINCE: (u8, u8, u8) = (0, 12, 1);

/// The first protocol version whose P2P campaign, having given up, parks on the coordination
/// endpoint instead of ending, so either peer can re-arm it (`PeerChannel::upgrade`). With a peer
/// below it, or of unknown version, the campaign ends as before and an upgrade is refused.
pub const PATH_REARM_SINCE: (u8, u8, u8) = (0, 12, 1);

/// The first protocol version whose server sends its `PathPolicy` in connect SUCCESS, and whose
/// peers offer their path restrictions in each key exchange and execute the `EffectivePlan` the
/// server stamps into it. A client below it, or of unknown version, is sent no policy; a key
/// exchange in which either peer is below it carries no plan, and both peers plan their paths
/// themselves (`plan_p2p`), exactly as before.
pub const PATH_POLICY_SINCE: (u8, u8, u8) = (0, 12, 2);

/// The first protocol version whose server honours a group's relay options: it mails an
/// `ephemeral` group's broadcasts to no offline member, and holds each message to the group's
/// `limits`, answering a refused one with `GroupBroadcast::MessageRefused` (to a sender at this
/// version; an older sender gets the `MessageResponse { success: false }` it understands). A
/// server below it would ignore both options, so a client refuses to create such a group there.
pub const GROUP_RELAY_OPTIONS_SINCE: (u8, u8, u8) = (0, 12, 2);

/// The first protocol version whose P2P connections carry a negotiation lane: control frames on
/// the reliable stream, beginning with each side's `Hello`, that the SDK takes out before the
/// application sees them (`proto::peer::negotiation::lane`). Its server copies a deliberate
/// disconnect's `reason` into the `PeerSignal::Disconnect` it sends on. A peer below it, or of
/// unknown version, is sent no lane frame and its Hello reads as empty: every setting is legacy
/// toward it. A server below it drops the reason, which the lane then carries instead.
pub const NEGOTIATION_SINCE: (u8, u8, u8) = (0, 12, 3);

/// The first protocol version whose P2P key exchange binds the keys to the connection they are
/// for: both peers mix the initiator's CID, the responder's CID and the connection's id into the
/// exchange (`proto::peer::p2p_seal_binding`), so a packet is accepted only under the connection
/// it was sealed for. Both peers must agree: each binds only when the other's key-exchange signal
/// names a version at or above it, and a pair with an older or unknown peer derives its keys as
/// before.
pub const IDENTITY_BOUND_SEAL_SINCE: (u8, u8, u8) = (0, 12, 3);

/// The first protocol version whose hole-punch and P2P coordination endpoints speak
/// `netbeam::sync::wire::WireRevision::Exchanged`. Both ends pick the revision from the other's
/// version, so a pair with either below it, or of unknown version, speaks the count-paired wire.
pub const EXCHANGED_SUBSCRIPTIONS_SINCE: (u8, u8, u8) = (0, 12, 3);

/// The first protocol version whose sign-in messages carry the security-key ceremony: a server
/// names the WebAuthn relying party its keys are scoped to and the keys an enrolment must avoid,
/// and a client enrolling a key creates its credential after the challenge, rather than naming
/// one it created before. Each field rides appended after the 0.12.2 layout
/// (`citadel_user::auth::pq::messages::SignInLayout`). A peer below it, or of unknown version, is
/// sent exactly the 0.12.2 bytes and hashes the 0.12.2 transcript; a client cannot enrol a key at
/// a server below it.
pub const SECURITY_KEY_CEREMONY_SINCE: (u8, u8, u8) = (0, 12, 3);

/// The first protocol version whose server recovers accounts: after register STAGE1 it reads
/// `RECOVER_START` (a device with no bundle proves the account's recovery phrase inside the fresh
/// key exchange, and that exchange's ratchet becomes the account's bundle), it challenges a
/// recovery phrase offered at sign-in, and it reads the management changes `SetPassword` and
/// `RegenerateRecoveryPhrase`. A client checks STAGE1's header and the session's server version
/// first, and asks an older server for none of these.
pub const RECOVERY_SINCE: (u8, u8, u8) = (0, 12, 4);

/// A client may reattach a held session over a new path with the same seal, and a server answers
/// it (`proto::link::reattach`, `ROBUST-CONNECTION-MANAGER.md` §5.2). Additive: a node below it is
/// never sent the frames, and the manager seals afresh as before. Shares the one 0.12.4 bump with
/// the rest of the mega PR (§12.2).
pub const LINK_REATTACH_SINCE: (u8, u8, u8) = (0, 12, 4);

/// The first protocol version whose P2P pairs exchange their link-manager modes on the
/// coordination endpoint before any path work (`link::p2p::agree`). With a peer below it the
/// pair runs the Legacy campaign, whatever this node's mode.
pub const LINK_MODE_SINCE: (u8, u8, u8) = (0, 12, 4);

/// The first protocol version whose P2P campaign shares a lost direct path
/// (`p2p_retry::wait_for_shared_fall_back`). The first peer to lose the route wakes the other over
/// the coordination endpoint, so both fall back and meet for the retry together. With a peer below
/// it, each side learns only from its own transport, as before.
pub const PATH_LOSS_SHARED_SINCE: (u8, u8, u8) = (0, 12, 4);

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
/// How long the server holds a registration invite for its target to answer, before answering
/// it as timed out. (A deregistration's posting lasts only `SIMULTANEOUS_DEREGISTER_WINDOW`.)
pub const PEER_POSTING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);
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
pub const TCP_CONN_TIMEOUT: std::time::Duration =
    citadel_types::proto::timing::TRANSPORT_CONNECT_TIMEOUT;

pub const MAX_OUTGOING_UNPROCESSED_REQUESTS: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;

    fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
        Some(Semver::new(major, minor, patch).to_u32().unwrap())
    }

    #[test]
    fn this_node_carries_the_negotiation_lane_and_the_previous_patch_does_not() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            NEGOTIATION_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 12, 2),
            NEGOTIATION_SINCE
        ));
    }

    #[test]
    fn this_node_binds_p2p_keys_and_the_previous_patch_does_not() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            IDENTITY_BOUND_SEAL_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 12, 2),
            IDENTITY_BOUND_SEAL_SINCE
        ));
    }

    #[test]
    fn this_node_shares_a_lost_path_and_the_previous_patch_does_not() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            PATH_LOSS_SHARED_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 12, 3),
            PATH_LOSS_SHARED_SINCE
        ));
        assert!(!protocol_version_at_least(None, PATH_LOSS_SHARED_SINCE));
    }

    #[test]
    fn this_node_runs_the_security_key_ceremony_and_the_previous_patch_does_not() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            SECURITY_KEY_CEREMONY_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 12, 2),
            SECURITY_KEY_CEREMONY_SINCE
        ));
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
