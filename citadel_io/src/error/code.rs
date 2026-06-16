//! The workspace-wide error-code registry.
//!
//! [`ErrorCode`] is a fieldless `#[repr(u16)]` enum: each variant is one *known* error across the
//! entire Citadel workspace, and its discriminant **is** the stable error code (0..=65_535). The
//! human-readable message is declared **once**, on the variant, via `#[form = "..."]` — a template
//! whose `{}` placeholders are filled (in order) by the positional arguments passed to the
//! [`crate::error!`] macro. The [`citadel_io_macros::ErrorRegistry`] derive turns those `#[form]`
//! attributes into `raw_string()` / `as_u16()` / `placeholder_count()`.
//!
//! Append-only: never renumber an existing variant (codes are stable). New errors go at the end.
//! Prefer adding a *specific* variant over reusing [`ErrorCode::Generic`].

use citadel_io_macros::ErrorRegistry;

/// A stable 2-byte error code; the discriminant is the canonical error code, and `#[form]` is its
/// message template. Never renumber existing variants.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, ErrorRegistry)]
pub enum ErrorCode {
    // --- general / protocol ---
    /// A generic, uncategorized error carrying an opaque message. Prefer a specific variant.
    #[form = "{}"]
    Generic = 0,
    /// A low-level socket error.
    #[form = "Socket error: {}"]
    Socket = 1,
    /// An operation exceeded its time budget.
    #[form = "Operation timed out: {}"]
    Timeout = 2,
    /// A received packet failed structural validation.
    #[form = "Invalid packet: {}"]
    InvalidPacket = 3,
    /// A packet's declared/actual size was rejected.
    #[form = "Invalid packet size: {}"]
    InvalidPacketSize = 4,
    /// A request was malformed or not permitted in the current state.
    #[form = "Invalid request: {}"]
    InvalidRequest = 5,
    /// An invariant was violated inside the protocol.
    #[form = "Internal error: {}"]
    InternalError = 6,
    /// Failed to hand a request to the node's remote.
    #[form = "Failed to send request to the node remote: {}"]
    NodeRemoteSend = 7,
    /// The session shut down cleanly (not a failure per se).
    #[form = "The session was shut down properly"]
    ProperShutdown = 8,
    /// A wrapped `std::io::Error`.
    #[form = "I/O error: {}"]
    Io = 9,

    // --- cryptography ---
    /// Encryption failed (with context).
    #[form = "Encryption error: {}"]
    Encrypt = 10,
    /// Decryption failed (with context).
    #[form = "Decryption error: {}"]
    Decrypt = 11,
    /// A rekey/ratchet-update step failed.
    #[form = "Rekey update error: {}"]
    RekeyUpdate = 12,
    /// A ratchet operation failed.
    #[form = "Ratchet error: {}"]
    Ratchet = 13,
    /// An index/length was outside the valid range.
    #[form = "Value out of bounds"]
    OutOfBounds = 14,
    /// The requested security setting was invalid or unsupported.
    #[form = "Bad security setting"]
    BadSecuritySetting = 15,
    /// An unrecoverable cryptographic fault.
    #[form = "Fatal cryptographic error: {}"]
    FatalCrypt = 16,

    // --- crypto types ---
    /// The shared secret has not been loaded yet.
    #[form = "Shared secret not loaded"]
    SharedSecretNotLoaded = 17,
    /// A generic encryption failure (no further context).
    #[form = "Encryption failure"]
    EncryptionFailure = 18,
    /// A generic decryption failure (no further context).
    #[form = "Decryption failure"]
    DecryptionFailure = 19,
    /// A buffer/key length was invalid.
    #[form = "Invalid length"]
    InvalidLength = 20,
    /// The requested algorithm is not supported.
    #[form = "Unsupported algorithm"]
    UnsupportedAlgorithm = 21,

    // --- accounts ---
    /// A client account already exists (cid).
    #[form = "Client account already exists: {}"]
    AccountClientExists = 22,
    /// The referenced client account does not exist (cid).
    #[form = "Client account does not exist: {}"]
    AccountClientNonExists = 23,
    /// A server account already exists (cid).
    #[form = "Server account already exists: {}"]
    AccountServerExists = 24,
    /// The referenced server account does not exist (cid).
    #[form = "Server account does not exist: {}"]
    AccountServerNonExists = 25,
    /// The supplied username was invalid.
    #[form = "Invalid username"]
    AccountInvalidUsername = 26,
    /// The supplied password was invalid.
    #[form = "Invalid password"]
    AccountInvalidPassword = 27,
    /// The account is disengaged / deregistered (cid).
    #[form = "Account disengaged: {}"]
    AccountDisengaged = 28,

    // --- firewall / NAT traversal ---
    /// A UPnP operation failed.
    #[form = "UPnP error: {}"]
    FirewallUpnp = 29,
    /// A hole-punch operation failed.
    #[form = "Hole-punch error: {}"]
    FirewallHolePunch = 30,
    /// Firewall traversal was deliberately skipped.
    #[form = "Firewall traversal skipped"]
    FirewallSkip = 31,
    /// Firewall traversal was not applicable in this context.
    #[form = "Firewall traversal not applicable"]
    FirewallNotApplicable = 32,
    /// All hole-punch attempts were exhausted.
    #[form = "Hole-punch attempts exhausted"]
    FirewallHolePunchExhausted = 33,
    /// The local IP address could not be determined.
    #[form = "Failed to resolve the local IP address"]
    FirewallLocalIpFail = 34,

    // --- channels ---
    /// A channel send failed (receiver gone or full).
    #[form = "Channel send error: {}"]
    ChannelSend = 35,
    /// A channel receive failed (sender gone).
    #[form = "Channel receive error"]
    ChannelRecv = 36,
    /// An internal channel invariant was violated.
    #[form = "Channel internal error: {}"]
    ChannelInternal = 37,

    // --- networking misc ---
    /// Failed to retrieve the public/external IP address.
    #[form = "Failed to retrieve the IP address: {}"]
    IpRetrieve = 38,
    /// A Firebase RTDB operation failed.
    #[form = "Firebase RTDB error: {}"]
    Rtdb = 39,
}
