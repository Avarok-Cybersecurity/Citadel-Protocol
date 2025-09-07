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
pub const MINOR_VERSION: u8 = 8;
pub const PATCH_VERSION: u8 = 0;

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
