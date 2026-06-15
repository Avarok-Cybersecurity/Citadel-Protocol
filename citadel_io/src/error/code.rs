//! Stable, workspace-wide error codes.
//!
//! [`ErrorCode`] is a fieldless `#[repr(u16)]` enum: each variant is one *known* error across the
//! entire Citadel workspace, and its discriminant **is** the stable wire/log error code (0..=65_535).
//! The variant also owns its canonical, human-readable message via [`ErrorCode::message`]. Dynamic
//! per-occurrence context (a peer id, a path, a wrapped `io::Error` string) is carried separately by
//! [`super::NetworkError`]'s boxed `detail`, so this type stays exactly 2 bytes.
//!
//! Append-only: never renumber an existing variant (codes are stable). New errors go at the end.

/// A stable 2-byte error code. The discriminant is the canonical error code; never renumber.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // --- general / protocol (formerly citadel_proto::NetworkError) ---
    /// A generic, uncategorized error.
    Generic = 0,
    /// A low-level socket error.
    Socket,
    /// An operation exceeded its time budget.
    Timeout,
    /// A received packet failed structural validation.
    InvalidPacket,
    /// A packet's declared/actual size was rejected.
    InvalidPacketSize,
    /// A request was malformed or not permitted in the current state.
    InvalidRequest,
    /// An invariant was violated inside the protocol.
    InternalError,
    /// Failed to hand a request to the node's remote.
    NodeRemoteSend,
    /// The session shut down cleanly (not a failure per se).
    ProperShutdown,
    /// A wrapped `std::io::Error`.
    Io,

    // --- cryptography (formerly citadel_crypt::CryptError) ---
    /// Encryption failed.
    Encrypt,
    /// Decryption failed.
    Decrypt,
    /// A rekey/ratchet-update step failed.
    RekeyUpdate,
    /// A ratchet operation failed.
    Ratchet,
    /// An index/length was outside the valid range.
    OutOfBounds,
    /// The requested security setting was invalid or unsupported.
    BadSecuritySetting,
    /// An unrecoverable cryptographic fault.
    FatalCrypt,

    // --- crypto types (formerly citadel_types::errors::Error) ---
    /// The shared secret has not been loaded yet.
    SharedSecretNotLoaded,
    /// A generic encryption failure (no further context).
    EncryptionFailure,
    /// A generic decryption failure (no further context).
    DecryptionFailure,
    /// A buffer/key length was invalid.
    InvalidLength,
    /// The requested algorithm is not supported.
    UnsupportedAlgorithm,

    // --- accounts (formerly citadel_user::AccountError) ---
    /// A client account already exists.
    AccountClientExists,
    /// The referenced client account does not exist.
    AccountClientNonExists,
    /// A server account already exists.
    AccountServerExists,
    /// The referenced server account does not exist.
    AccountServerNonExists,
    /// The supplied username was invalid.
    AccountInvalidUsername,
    /// The supplied password was invalid.
    AccountInvalidPassword,
    /// The account is disengaged / deregistered.
    AccountDisengaged,

    // --- firewall / NAT traversal (formerly citadel_wire::FirewallError) ---
    /// A UPnP operation failed.
    FirewallUpnp,
    /// A hole-punch operation failed.
    FirewallHolePunch,
    /// Firewall traversal was deliberately skipped.
    FirewallSkip,
    /// Firewall traversal was not applicable in this context.
    FirewallNotApplicable,
    /// All hole-punch attempts were exhausted.
    FirewallHolePunchExhausted,
    /// The local IP address could not be determined.
    FirewallLocalIpFail,

    // --- channels (formerly netbeam Callback/TrackedCallback errors) ---
    /// A channel send failed (receiver gone or full).
    ChannelSend,
    /// A channel receive failed (sender gone).
    ChannelRecv,
    /// An internal channel invariant was violated.
    ChannelInternal,

    // --- networking misc ---
    /// Failed to retrieve the public/external IP address (formerly async_ip).
    IpRetrieve,
    /// A Firebase RTDB operation failed (formerly firebase-rtdb).
    Rtdb,
}

impl ErrorCode {
    /// The canonical, static, human-readable message for this code. Per-occurrence context (ids,
    /// paths, wrapped error strings) is appended by [`super::NetworkError`]'s `detail`.
    pub const fn message(self) -> &'static str {
        match self {
            ErrorCode::Generic => "An error occurred",
            ErrorCode::Socket => "Socket error",
            ErrorCode::Timeout => "Operation timed out",
            ErrorCode::InvalidPacket => "Invalid packet",
            ErrorCode::InvalidPacketSize => "Invalid packet size",
            ErrorCode::InvalidRequest => "Invalid request",
            ErrorCode::InternalError => "Internal error",
            ErrorCode::NodeRemoteSend => "Failed to send request to the node remote",
            ErrorCode::ProperShutdown => "The session was shut down properly",
            ErrorCode::Io => "I/O error",
            ErrorCode::Encrypt => "Encryption error",
            ErrorCode::Decrypt => "Decryption error",
            ErrorCode::RekeyUpdate => "Rekey update error",
            ErrorCode::Ratchet => "Ratchet error",
            ErrorCode::OutOfBounds => "Value out of bounds",
            ErrorCode::BadSecuritySetting => "Bad security setting",
            ErrorCode::FatalCrypt => "Fatal cryptographic error",
            ErrorCode::SharedSecretNotLoaded => "Shared secret not loaded",
            ErrorCode::EncryptionFailure => "Encryption failure",
            ErrorCode::DecryptionFailure => "Decryption failure",
            ErrorCode::InvalidLength => "Invalid length",
            ErrorCode::UnsupportedAlgorithm => "Unsupported algorithm",
            ErrorCode::AccountClientExists => "Client account already exists",
            ErrorCode::AccountClientNonExists => "Client account does not exist",
            ErrorCode::AccountServerExists => "Server account already exists",
            ErrorCode::AccountServerNonExists => "Server account does not exist",
            ErrorCode::AccountInvalidUsername => "Invalid username",
            ErrorCode::AccountInvalidPassword => "Invalid password",
            ErrorCode::AccountDisengaged => "Account disengaged",
            ErrorCode::FirewallUpnp => "UPnP error",
            ErrorCode::FirewallHolePunch => "Hole-punch error",
            ErrorCode::FirewallSkip => "Firewall traversal skipped",
            ErrorCode::FirewallNotApplicable => "Firewall traversal not applicable",
            ErrorCode::FirewallHolePunchExhausted => "Hole-punch attempts exhausted",
            ErrorCode::FirewallLocalIpFail => "Failed to resolve the local IP address",
            ErrorCode::ChannelSend => "Channel send error",
            ErrorCode::ChannelRecv => "Channel receive error",
            ErrorCode::ChannelInternal => "Channel internal error",
            ErrorCode::IpRetrieve => "Failed to retrieve the IP address",
            ErrorCode::Rtdb => "Firebase RTDB error",
        }
    }

    /// The stable numeric error code (the `#[repr(u16)]` discriminant).
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}
