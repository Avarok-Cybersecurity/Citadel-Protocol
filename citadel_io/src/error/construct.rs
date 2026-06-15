//! Typed constructors for [`NetworkError`], one per old error variant across the workspace.
//!
//! Each helper pins the [`ErrorCode`] and boxes the (optional) per-occurrence detail, so call sites
//! read like the enum-variant constructors they replaced (`NetworkError::generic(msg)` instead of the
//! old `NetworkError::Generic(msg)`).

use super::{ErrorCode, NetworkError};

impl NetworkError {
    // --- general / protocol ---

    /// A generic, uncategorized error with a message.
    pub fn generic<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Generic, msg)
    }

    /// Alias of [`NetworkError::generic`] (matches the old `NetworkError::msg`).
    pub fn msg<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Generic, msg)
    }

    /// A low-level socket error with a message.
    pub fn socket<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Socket, msg)
    }

    /// An operation timed out; `detail` records the elapsed/limit value or subject.
    pub fn timeout(value: u64) -> Self {
        Self::coded(ErrorCode::Timeout, value.to_string())
    }

    /// A received packet failed structural validation.
    pub fn invalid_packet<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::InvalidPacket, msg)
    }

    /// A packet's size was rejected.
    pub fn invalid_packet_size(size: usize) -> Self {
        Self::coded(ErrorCode::InvalidPacketSize, size.to_string())
    }

    /// A request was malformed or not permitted in the current state.
    pub fn invalid_request<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::InvalidRequest, msg)
    }

    /// An internal protocol invariant was violated.
    pub fn internal<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::InternalError, msg)
    }

    /// Failed to hand a request to the node's remote; `detail` is the failure reason.
    pub fn node_remote_send<T: Into<String>>(reason: T) -> Self {
        Self::coded(ErrorCode::NodeRemoteSend, reason)
    }

    /// The session shut down cleanly.
    pub const fn proper_shutdown() -> Self {
        Self::bare(ErrorCode::ProperShutdown)
    }

    /// A wrapped I/O error described by `msg` (prefer `From<std::io::Error>` when you have the error).
    pub fn io<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Io, msg)
    }

    // --- cryptography ---

    /// Encryption failed.
    pub fn encrypt<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Encrypt, msg)
    }

    /// Decryption failed.
    pub fn decrypt<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Decrypt, msg)
    }

    /// A rekey/ratchet-update step failed.
    pub fn rekey_update<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::RekeyUpdate, msg)
    }

    /// A ratchet operation failed.
    pub fn ratchet<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Ratchet, msg)
    }

    /// An index/length was outside the valid range.
    pub const fn out_of_bounds() -> Self {
        Self::bare(ErrorCode::OutOfBounds)
    }

    /// The requested security setting was invalid or unsupported.
    pub const fn bad_security_setting() -> Self {
        Self::bare(ErrorCode::BadSecuritySetting)
    }

    /// An unrecoverable cryptographic fault.
    pub fn fatal_crypt<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::FatalCrypt, msg)
    }

    // --- crypto types ---

    /// The shared secret has not been loaded yet.
    pub const fn shared_secret_not_loaded() -> Self {
        Self::bare(ErrorCode::SharedSecretNotLoaded)
    }

    /// A generic encryption failure (no further context).
    pub const fn encryption_failure() -> Self {
        Self::bare(ErrorCode::EncryptionFailure)
    }

    /// A generic decryption failure (no further context).
    pub const fn decryption_failure() -> Self {
        Self::bare(ErrorCode::DecryptionFailure)
    }

    /// A buffer/key length was invalid.
    pub const fn invalid_length() -> Self {
        Self::bare(ErrorCode::InvalidLength)
    }

    /// The requested algorithm is not supported.
    pub const fn unsupported_algorithm() -> Self {
        Self::bare(ErrorCode::UnsupportedAlgorithm)
    }

    // --- accounts ---

    /// A client account already exists (`cid`).
    pub fn account_client_exists(cid: u64) -> Self {
        Self::coded(ErrorCode::AccountClientExists, cid.to_string())
    }

    /// The referenced client account does not exist (`cid`).
    pub fn account_client_non_exists(cid: u64) -> Self {
        Self::coded(ErrorCode::AccountClientNonExists, cid.to_string())
    }

    /// A server account already exists (`cid`).
    pub fn account_server_exists(cid: u64) -> Self {
        Self::coded(ErrorCode::AccountServerExists, cid.to_string())
    }

    /// The referenced server account does not exist (`cid`).
    pub fn account_server_non_exists(cid: u64) -> Self {
        Self::coded(ErrorCode::AccountServerNonExists, cid.to_string())
    }

    /// The supplied username was invalid.
    pub const fn account_invalid_username() -> Self {
        Self::bare(ErrorCode::AccountInvalidUsername)
    }

    /// The supplied password was invalid.
    pub const fn account_invalid_password() -> Self {
        Self::bare(ErrorCode::AccountInvalidPassword)
    }

    /// The account is disengaged / deregistered (`cid`).
    pub fn account_disengaged(cid: u64) -> Self {
        Self::coded(ErrorCode::AccountDisengaged, cid.to_string())
    }

    // --- firewall / NAT traversal ---

    /// A UPnP operation failed.
    pub fn firewall_upnp<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::FirewallUpnp, msg)
    }

    /// A hole-punch operation failed.
    pub fn firewall_hole_punch<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::FirewallHolePunch, msg)
    }

    /// Firewall traversal was deliberately skipped.
    pub const fn firewall_skip() -> Self {
        Self::bare(ErrorCode::FirewallSkip)
    }

    /// Firewall traversal was not applicable in this context.
    pub const fn firewall_not_applicable() -> Self {
        Self::bare(ErrorCode::FirewallNotApplicable)
    }

    /// All hole-punch attempts were exhausted.
    pub const fn firewall_hole_punch_exhausted() -> Self {
        Self::bare(ErrorCode::FirewallHolePunchExhausted)
    }

    /// The local IP address could not be determined.
    pub const fn firewall_local_ip_fail() -> Self {
        Self::bare(ErrorCode::FirewallLocalIpFail)
    }

    // --- channels ---

    /// A channel send failed (receiver gone or full).
    pub fn channel_send<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::ChannelSend, msg)
    }

    /// A channel receive failed (sender gone).
    pub const fn channel_recv() -> Self {
        Self::bare(ErrorCode::ChannelRecv)
    }

    /// An internal channel invariant was violated.
    pub fn channel_internal<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::ChannelInternal, msg)
    }

    // --- networking misc ---

    /// Failed to retrieve the public/external IP address.
    pub fn ip_retrieve<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::IpRetrieve, msg)
    }

    /// A Firebase RTDB operation failed.
    pub fn rtdb<T: Into<String>>(msg: T) -> Self {
        Self::coded(ErrorCode::Rtdb, msg)
    }
}
