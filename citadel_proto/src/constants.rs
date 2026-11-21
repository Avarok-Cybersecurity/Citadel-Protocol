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
//
// The version a node announces in its handshake. A node takes part only with a node at or above
// `version_gate::OLDEST_PEER_PROTOCOL_VERSION`, and refuses anything else by name. Each
// `*_SINCE` constant below records the release a feature arrived in. Every one of them is at or
// below the oldest admitted version, so each always holds for a node this node takes part with,
// and no code path serves a node below one. They stay as the place a later gate is added: when a
// release must keep working with the one before it, lower the oldest admitted version and give
// each newer gate its older-node path there.
pub const MAJOR_VERSION: u8 = 0;
// 9 -> 10: the per-message nonce KDF moved from SHA3-256 to a BLAKE3 keyed-hash PRF.
// 10 -> 11: the hole-punch coordination stream carries attempt-numbered frames; key-exchange
// signals carry the sender's protocol version; media endpoints exchange transport offers; servers
// answer `GroupBroadcast::AwaitGroup`.
// 11 -> 12: post-quantum sign-in.
pub const MINOR_VERSION: u8 = 12;
// 0 -> 1: liveness probes; re-arming a P2P campaign that gave up.
// 1 -> 2: server path policy and per-pair effective plans; group relay options.
// 2 -> 3: the P2P negotiation lane and disconnect reasons; identity-bound P2P keys; exchanged
// coordination subscriptions; the security-key ceremony.
// 3 -> 4: link-manager modes; session reattach; signed P2P key-exchange stages; account
// recovery; shared path loss; bound waves.
// 4 -> 5: group integrity: signed group messages bound to their sender, per-member delivery
// reports, bounded group backlogs, resumable group state.
pub const PATCH_VERSION: u8 = 5;

/// Media endpoints send and expect a transport offer as the first message on the reliable lane.
pub const MEDIA_TRANSPORT_OFFER_SINCE: (u8, u8, u8) = (0, 10, 1);

/// The server answers `GroupBroadcast::AwaitGroup`, so a joiner waits for the owner's group.
pub const AWAIT_GROUP_SINCE: (u8, u8, u8) = (0, 11, 0);

/// Group Commit acknowledgement: a member sends `GroupBroadcast::CommitApplied` after processing
/// a Commit, the server answers the owner with `GroupBroadcast::CommitSettled` once every member
/// it delivered the Commit to has, and the owner releases a joiner's Welcome only then.
pub const GROUP_COMMIT_ACK_SINCE: (u8, u8, u8) = (0, 11, 1);

/// Session resume tokens: a server issues one in connect SUCCESS and accepts it back at STAGE0 as
/// proof that a login is the held session's own client (see `proto::session_resume`).
pub const SESSION_RESUME_SINCE: (u8, u8, u8) = (0, 11, 2);

/// Post-quantum sign-in (see `proto::pq_sign_in`): a client sends connect `AUTH_START` before
/// STAGE0 and register `PQ_START` before STAGE2, and the server proves the account's ML-KEM
/// factors instead of verifying an Argon2 hash.
pub const PQ_SIGN_IN_SINCE: (u8, u8, u8) = (0, 12, 0);

/// The server answers a liveness probe: a `KEEP_ALIVE` with `cmd_aux` PROBE, echoed at once (see
/// `proto::server_probe`).
pub const SERVER_PROBE_SINCE: (u8, u8, u8) = (0, 12, 1);

/// A P2P campaign that gave up parks on the coordination endpoint instead of ending, so either
/// peer can re-arm it (`PeerChannel::upgrade`).
pub const PATH_REARM_SINCE: (u8, u8, u8) = (0, 12, 1);

/// The server sends its `PathPolicy` in connect SUCCESS; peers offer their path restrictions in
/// each key exchange and execute the `EffectivePlan` the server stamps into it.
pub const PATH_POLICY_SINCE: (u8, u8, u8) = (0, 12, 2);

/// The server honours a group's relay options: it mails an `ephemeral` group's broadcasts to no
/// offline member, and holds each message to the group's `limits`, answering a refused one with
/// `GroupBroadcast::MessageRefused`. A client refuses to create a group with either option on a
/// server below it.
pub const GROUP_RELAY_OPTIONS_SINCE: (u8, u8, u8) = (0, 12, 2);

/// P2P connections carry a negotiation lane: control frames on the reliable stream, beginning
/// with each side's `Hello`, that the SDK takes out before the application sees them
/// (`proto::peer::negotiation::lane`). The server copies a deliberate disconnect's `reason` into
/// the `PeerSignal::Disconnect` it sends on.
pub const NEGOTIATION_SINCE: (u8, u8, u8) = (0, 12, 3);

/// A P2P key exchange binds its keys to the connection they are for: both peers mix the
/// initiator's CID, the responder's CID and the connection's id into the exchange
/// (`proto::peer::p2p_seal_binding`), so a packet is accepted only under the connection it was
/// sealed for.
pub const IDENTITY_BOUND_SEAL_SINCE: (u8, u8, u8) = (0, 12, 3);

/// Hole-punch and P2P coordination endpoints speak
/// `netbeam::sync::wire::WireRevision::Exchanged`.
pub const EXCHANGED_SUBSCRIPTIONS_SINCE: (u8, u8, u8) = (0, 12, 3);

/// Sign-in messages carry the security-key ceremony: a server names the WebAuthn relying party
/// its keys are scoped to and the keys an enrolment must avoid, and a client enrolling a key
/// creates its credential after the challenge.
pub const SECURITY_KEY_CEREMONY_SINCE: (u8, u8, u8) = (0, 12, 3);

/// The server recovers accounts: after register STAGE1 it reads `RECOVER_START` (a device with no
/// bundle proves the account's recovery phrase inside the fresh key exchange, and that exchange's
/// ratchet becomes the account's bundle), it challenges a recovery phrase offered at sign-in, and
/// it reads the management changes `SetPassword` and `RegenerateRecoveryPhrase`.
pub const RECOVERY_SINCE: (u8, u8, u8) = (0, 12, 4);

/// A client may reattach a held session over a new path with the same seal, and a server answers
/// it (`proto::link::reattach`, `ROBUST-CONNECTION-MANAGER.md` §5.2).
pub const LINK_REATTACH_SINCE: (u8, u8, u8) = (0, 12, 4);

/// P2P pairs exchange their link-manager modes on the coordination endpoint before any path work
/// (`link::p2p::agree`).
pub const LINK_MODE_SINCE: (u8, u8, u8) = (0, 12, 4);

/// P2P key-exchange stages carry a signature by the sending account's identity key over the
/// exchange's transcript (`proto::peer::kex_auth`). Each side signs its stage whenever its
/// account has an identity key. Whether an unsigned stage is accepted is decided by the key
/// pinned for the peer, never by the version a stage claims.
pub const P2P_KEX_SIGNED_SINCE: (u8, u8, u8) = (0, 12, 4);

/// A P2P campaign shares a lost direct path (`p2p_retry::wait_for_shared_fall_back`): the first
/// peer to lose the route wakes the other over the coordination endpoint, so both fall back and
/// meet for the retry together.
pub const PATH_LOSS_SHARED_SINCE: (u8, u8, u8) = (0, 12, 4);

/// Group messages are signed by their sender's leaf and bound to the relaying session; sends are
/// answered per member; members resume their kept group state and read what was held for them.
pub const GROUP_INTEGRITY_SINCE: (u8, u8, u8) = (0, 12, 5);

/// Whether an adjacent node's protocol version is known and at least `since`. An unknown or
/// unparseable version is not.
pub fn protocol_version_at_least(version: Option<u32>, since: (u8, u8, u8)) -> bool {
    let Some(version) = version.and_then(|v| Semver::from_u32(v).ok()) else {
        return false;
    };
    let since = (since.0 as usize, since.1 as usize, since.2 as usize);
    (version.major, version.minor, version.patch) >= since
}

/// File and object waves carry their object, group, index and ratchet version as associated
/// data (`citadel_crypt::scramble::wave_binding`).
pub const WAVE_BINDING_SINCE: (u8, u8, u8) = (0, 12, 4);

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
    fn this_node_carries_group_integrity_and_the_previous_patch_does_not() {
        assert!(protocol_version_at_least(
            Some(*PROTOCOL_VERSION),
            GROUP_INTEGRITY_SINCE
        ));
        assert!(!protocol_version_at_least(
            version(0, 12, 4),
            GROUP_INTEGRITY_SINCE
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
