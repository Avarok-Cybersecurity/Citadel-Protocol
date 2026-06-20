//! Ergonomic shim constructors for [`NetworkError`], one per legacy error variant.
//!
//! These keep the established call sites (`NetworkError::generic(msg)`, `::io(e)`, …) compiling while
//! the workspace migrates to the [`crate::error!`] macro. Each forwards to `error!`, so the message
//! template lives in the [`ErrorCode`] registry. NOTE: because `file!()`/`line!()` only capture inside
//! a macro, an error built through one of these *functions* records the shim's own location as its
//! origin — accurate origins require calling [`crate::error!`] directly (the end state of the migration).

use super::{ErrorArgs, ErrorCode, NetworkError};

impl NetworkError {
    // --- general / protocol ---

    /// A generic, uncategorized error. Prefer a specific [`ErrorCode`].
    pub fn generic(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Generic, msg)
    }

    /// Alias of [`NetworkError::generic`].
    pub fn msg(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Generic, msg)
    }

    /// A low-level socket error.
    pub fn socket(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Socket, msg)
    }

    /// An operation timed out (`value` is the elapsed/limit or subject).
    pub fn timeout(value: u64) -> Self {
        crate::error!(ErrorCode::Timeout, value)
    }

    /// A received packet failed structural validation.
    pub fn invalid_packet(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::InvalidPacket, msg)
    }

    /// A packet's size was rejected.
    pub fn invalid_packet_size(size: usize) -> Self {
        crate::error!(ErrorCode::InvalidPacketSize, size)
    }

    /// A request was malformed or not permitted in the current state.
    pub fn invalid_request(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::InvalidRequest, msg)
    }

    /// An internal protocol invariant was violated.
    pub fn internal(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::InternalError, msg)
    }

    /// Failed to hand a request to the node's remote.
    pub fn node_remote_send(reason: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::NodeRemoteSend, reason)
    }

    /// The session shut down cleanly.
    pub fn proper_shutdown() -> Self {
        crate::error!(ErrorCode::ProperShutdown)
    }

    /// A wrapped I/O error described by `msg`.
    pub fn io(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Io, msg)
    }

    // --- cryptography ---

    /// Encryption failed (with context).
    pub fn encrypt(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Encrypt, msg)
    }

    /// Decryption failed (with context).
    pub fn decrypt(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Decrypt, msg)
    }

    /// A rekey/ratchet-update step failed.
    pub fn rekey_update(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::RekeyUpdate, msg)
    }

    /// A ratchet operation failed.
    pub fn ratchet(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Ratchet, msg)
    }

    /// An index/length was outside the valid range.
    pub fn out_of_bounds() -> Self {
        crate::error!(ErrorCode::OutOfBounds)
    }

    /// The requested security setting was invalid or unsupported.
    pub fn bad_security_setting() -> Self {
        crate::error!(ErrorCode::BadSecuritySetting)
    }

    /// An unrecoverable cryptographic fault.
    pub fn fatal_crypt(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::FatalCrypt, msg)
    }

    // --- crypto types ---

    /// The shared secret has not been loaded yet.
    pub fn shared_secret_not_loaded() -> Self {
        crate::error!(ErrorCode::SharedSecretNotLoaded)
    }

    /// A generic encryption failure (no further context).
    pub fn encryption_failure() -> Self {
        crate::error!(ErrorCode::EncryptionFailure)
    }

    /// A generic decryption failure (no further context).
    pub fn decryption_failure() -> Self {
        crate::error!(ErrorCode::DecryptionFailure)
    }

    /// A buffer/key length was invalid.
    pub fn invalid_length() -> Self {
        crate::error!(ErrorCode::InvalidLength)
    }

    /// The requested algorithm is not supported.
    pub fn unsupported_algorithm() -> Self {
        crate::error!(ErrorCode::UnsupportedAlgorithm)
    }

    // --- accounts ---

    /// A client account already exists (`cid`).
    pub fn account_client_exists(cid: u64) -> Self {
        crate::error!(ErrorCode::AccountClientExists, cid)
    }

    /// The referenced client account does not exist (`cid`).
    pub fn account_client_non_exists(cid: u64) -> Self {
        crate::error!(ErrorCode::AccountClientNonExists, cid)
    }

    /// A server account already exists (`cid`).
    pub fn account_server_exists(cid: u64) -> Self {
        crate::error!(ErrorCode::AccountServerExists, cid)
    }

    /// The referenced server account does not exist (`cid`).
    pub fn account_server_non_exists(cid: u64) -> Self {
        crate::error!(ErrorCode::AccountServerNonExists, cid)
    }

    /// The supplied username was invalid.
    pub fn account_invalid_username() -> Self {
        crate::error!(ErrorCode::AccountInvalidUsername)
    }

    /// The supplied password was invalid.
    pub fn account_invalid_password() -> Self {
        crate::error!(ErrorCode::AccountInvalidPassword)
    }

    /// The account is disengaged / deregistered (`cid`).
    pub fn account_disengaged(cid: u64) -> Self {
        crate::error!(ErrorCode::AccountDisengaged, cid)
    }

    // --- firewall / NAT traversal ---

    /// A UPnP operation failed.
    pub fn firewall_upnp(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::FirewallUpnp, msg)
    }

    /// A hole-punch operation failed.
    pub fn firewall_hole_punch(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::FirewallHolePunch, msg)
    }

    /// Firewall traversal was deliberately skipped.
    pub fn firewall_skip() -> Self {
        crate::error!(ErrorCode::FirewallSkip)
    }

    /// Firewall traversal was not applicable in this context.
    pub fn firewall_not_applicable() -> Self {
        crate::error!(ErrorCode::FirewallNotApplicable)
    }

    /// All hole-punch attempts were exhausted.
    pub fn firewall_hole_punch_exhausted() -> Self {
        crate::error!(ErrorCode::FirewallHolePunchExhausted)
    }

    /// The local IP address could not be determined.
    pub fn firewall_local_ip_fail() -> Self {
        crate::error!(ErrorCode::FirewallLocalIpFail)
    }

    // --- channels ---

    /// A channel send failed (receiver gone or full).
    pub fn channel_send(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::ChannelSend, msg)
    }

    /// A channel receive failed (sender gone).
    pub fn channel_recv() -> Self {
        crate::error!(ErrorCode::ChannelRecv)
    }

    /// An internal channel invariant was violated.
    pub fn channel_internal(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::ChannelInternal, msg)
    }

    // --- networking misc ---

    /// Failed to retrieve the public/external IP address.
    pub fn ip_retrieve(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::IpRetrieve, msg)
    }

    /// A Firebase RTDB operation failed.
    pub fn rtdb(msg: impl ErrorArgs) -> Self {
        crate::error!(ErrorCode::Rtdb, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shim constructor must carry its declared `ErrorCode` and render a non-empty message.
    #[test]
    fn all_constructors_carry_their_code() {
        let cases: Vec<(NetworkError, ErrorCode)> = vec![
            (NetworkError::generic("x"), ErrorCode::Generic),
            (NetworkError::msg("x"), ErrorCode::Generic),
            (NetworkError::socket("x"), ErrorCode::Socket),
            (NetworkError::timeout(5), ErrorCode::Timeout),
            (NetworkError::invalid_packet("x"), ErrorCode::InvalidPacket),
            (
                NetworkError::invalid_packet_size(9),
                ErrorCode::InvalidPacketSize,
            ),
            (
                NetworkError::invalid_request("x"),
                ErrorCode::InvalidRequest,
            ),
            (NetworkError::internal("x"), ErrorCode::InternalError),
            (
                NetworkError::node_remote_send("x"),
                ErrorCode::NodeRemoteSend,
            ),
            (NetworkError::proper_shutdown(), ErrorCode::ProperShutdown),
            (NetworkError::io("x"), ErrorCode::Io),
            (NetworkError::encrypt("x"), ErrorCode::Encrypt),
            (NetworkError::decrypt("x"), ErrorCode::Decrypt),
            (NetworkError::rekey_update("x"), ErrorCode::RekeyUpdate),
            (NetworkError::ratchet("x"), ErrorCode::Ratchet),
            (NetworkError::out_of_bounds(), ErrorCode::OutOfBounds),
            (
                NetworkError::bad_security_setting(),
                ErrorCode::BadSecuritySetting,
            ),
            (NetworkError::fatal_crypt("x"), ErrorCode::FatalCrypt),
            (
                NetworkError::shared_secret_not_loaded(),
                ErrorCode::SharedSecretNotLoaded,
            ),
            (
                NetworkError::encryption_failure(),
                ErrorCode::EncryptionFailure,
            ),
            (
                NetworkError::decryption_failure(),
                ErrorCode::DecryptionFailure,
            ),
            (NetworkError::invalid_length(), ErrorCode::InvalidLength),
            (
                NetworkError::unsupported_algorithm(),
                ErrorCode::UnsupportedAlgorithm,
            ),
            (
                NetworkError::account_client_exists(1),
                ErrorCode::AccountClientExists,
            ),
            (
                NetworkError::account_client_non_exists(1),
                ErrorCode::AccountClientNonExists,
            ),
            (
                NetworkError::account_server_exists(1),
                ErrorCode::AccountServerExists,
            ),
            (
                NetworkError::account_server_non_exists(1),
                ErrorCode::AccountServerNonExists,
            ),
            (
                NetworkError::account_invalid_username(),
                ErrorCode::AccountInvalidUsername,
            ),
            (
                NetworkError::account_invalid_password(),
                ErrorCode::AccountInvalidPassword,
            ),
            (
                NetworkError::account_disengaged(1),
                ErrorCode::AccountDisengaged,
            ),
            (NetworkError::firewall_upnp("x"), ErrorCode::FirewallUpnp),
            (
                NetworkError::firewall_hole_punch("x"),
                ErrorCode::FirewallHolePunch,
            ),
            (NetworkError::firewall_skip(), ErrorCode::FirewallSkip),
            (
                NetworkError::firewall_not_applicable(),
                ErrorCode::FirewallNotApplicable,
            ),
            (
                NetworkError::firewall_hole_punch_exhausted(),
                ErrorCode::FirewallHolePunchExhausted,
            ),
            (
                NetworkError::firewall_local_ip_fail(),
                ErrorCode::FirewallLocalIpFail,
            ),
            (NetworkError::channel_send("x"), ErrorCode::ChannelSend),
            (NetworkError::channel_recv(), ErrorCode::ChannelRecv),
            (
                NetworkError::channel_internal("x"),
                ErrorCode::ChannelInternal,
            ),
            (NetworkError::ip_retrieve("x"), ErrorCode::IpRetrieve),
            (NetworkError::rtdb("x"), ErrorCode::Rtdb),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code, "constructor produced the wrong code");
            assert_eq!(err.code_u16(), code as u16);
            assert!(!err.into_string().is_empty());
        }
    }
}
