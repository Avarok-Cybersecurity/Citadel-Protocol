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

    // --- crypt: rekey / ratchet progression (citadel_crypt) ---
    /// A ratchet version bump could not be applied.
    #[form = "Unable to progress past update_version"]
    RekeyVersionUpdateFailed = 40,
    /// Finishing the constructor failed on the bob-to-alice trigger path.
    #[form = "Unable to progress past finish_with_custom_cid for bob-to-alice trigger"]
    RekeyFinishBobToAliceFailed = 41,
    /// The Bob stage-0 step of a rekey failed.
    #[form = "Unable to progress past stage0_bob"]
    RekeyStage0BobFailed = 42,
    /// Finishing the constructor failed.
    #[form = "Unable to progress past finish_with_custom_cid"]
    RekeyFinishFailed = 43,
    /// Committing the new ratchet into the toolset failed.
    #[form = "Unable to progress past update_from"]
    RekeyUpdateFromFailed = 44,
    /// Committing the new ratchet into the toolset failed on the bob-to-alice trigger path.
    #[form = "Unable to progress past update_from for bob-to-alice trigger"]
    RekeyUpdateFromBobToAliceFailed = 45,
    /// A commit returned no transfer when one was expected (conflicting program state).
    #[form = "This should only be reached if triggered by a bob-to-alice transfer event, yet, conflicting program state"]
    RekeyUnexpectedNoneTransfer = 46,
    /// Ratchet deregistration was requested before the toolset reached capacity.
    #[form = "Cannot call for deregistration unless the map len is maxed out"]
    ToolsetDeregisterNotMaxed = 47,
    /// The version supplied to deregister did not match the oldest version.
    #[form = "Unable to deregister. Provided version: {}, expected version: {}"]
    ToolsetDeregisterVersionMismatch = 48,
    /// The ratchet carries no message-ratchet layers.
    #[form = "No message ratchets available"]
    NoMessageRatchets = 49,
    /// The requested security level exceeds the available ratchet layers.
    #[form = "Requested security level: {}. Resolved: {}. Only have max {} security levels"]
    SecurityLevelOutOfRange = 50,
    /// Encryption was requested over empty plaintext.
    #[form = "Empty input"]
    EmptyInput = 51,
    /// The rekey-trigger semaphore was closed.
    #[form = "Semaphore closed"]
    RekeySemaphoreClosed = 52,
    /// A rekey was requested while the rekey process is halted.
    #[form = "Rekey process is halted"]
    RekeyHalted = 53,
    /// A rekey attempt exhausted its stale-version retry budget.
    #[form = "Exceeded max stale version retries ({})"]
    RekeyStaleVersionRetriesExceeded = 54,
    /// The initial Alice transfer could not be produced.
    #[form = "Failed to get initial transfer"]
    RekeyInitialTransferFailed = 55,
    /// An offloaded (spawn_blocking) rekey step failed to join.
    #[form = "Join error on {}"]
    RekeyJoinError = 56,
    /// Sending a ratchet protocol message to the outbound sink failed.
    #[form = "Sink send error"]
    RekeySinkSendError = 57,
    /// The local rekey listener was dropped without the version advancing.
    #[form = "Local listener dropped without version advance"]
    RekeyListenerDropped = 58,
    /// A rekey protocol message did not arrive within the active timeout.
    #[form = "Rekey protocol message timeout — resetting for retry"]
    RekeyMessageTimeout = 59,
    /// The expected stacked ratchet could not be retrieved during a rekey.
    #[form = "Failed to get stacked ratchet"]
    RekeyStackedRatchetFailed = 60,
    /// Too many stale rekey protocol messages were received; a resync is required.
    #[form = "Too many stale rekey messages ({}), resynchronization needed. Peer: {}, Local: {}"]
    RekeyTooManyStaleResync = 61,
    /// The peer's rekey version barrier did not match the local one.
    #[form = "Rekey barrier mismatch (earliest/latest). Peer: ({}-{}) != Local: ({}-{})"]
    RekeyBarrierMismatch = 62,
    /// Too many stale rekey protocol messages were received (no resync context).
    #[form = "Too many stale rekey messages ({})"]
    RekeyTooManyStale = 63,
    /// The peer's rekey metadata did not match the local metadata.
    #[form = "Metadata mismatch ({}). Peer: {} != Local: {}"]
    RekeyMetadataMismatch = 64,
    /// An invalid rekey role transition to Leader was attempted.
    #[form = "Invalid role transition from {} to Leader"]
    RekeyInvalidRoleTransition = 65,
    /// Too many double-Loser rekey messages were received; a resync is required.
    #[form = "Too many double-Loser messages ({}), resynchronization needed"]
    RekeyTooManyDoubleLoser = 66,
    /// Too many unexpected BobToAlice messages while in the Loser role; a resync is required.
    #[form = "Too many unexpected BobToAlice while Loser ({}), resynchronization needed"]
    RekeyTooManyLoserBobToAlice = 67,
    /// A constructor was required for a BobToAlice message but none was loaded.
    #[form = "Unexpected BobToAlice message with no loaded local constructor for next_version {}"]
    RekeyNoConstructorForBobToAlice = 68,
    /// A Truncate message arrived while not in the Loser role.
    #[form = "Unexpected Truncate message since our role is not Loser, but {}"]
    RekeyUnexpectedTruncate = 69,
    /// A LoserCanFinish message arrived while not in the Loser role.
    #[form = "Unexpected LoserCanFinish message since our role is not Loser, but {}"]
    RekeyUnexpectedLoserCanFinish = 70,
    /// A LeaderCanFinish message arrived while not in the Leader role.
    #[form = "Unexpected LeaderCanFinish message since our role is not Leader, but {}"]
    RekeyUnexpectedLeaderCanFinish = 71,
    /// The local and peer versions disagreed at LeaderCanFinish.
    #[form = "Version mismatch in LeaderCanFinish. Local: {}, Peer: {}"]
    RekeyLeaderCanFinishVersionMismatch = 72,
    /// The rekey protocol stream ended unexpectedly.
    #[form = "Unexpected end of stream"]
    RekeyUnexpectedEndOfStream = 73,
    /// The Bob-side constructor could not be created during a rekey.
    #[form = "Failed to create bob constructor"]
    RekeyBobConstructorFailed = 74,
    /// An encrypted message-entropy-bank could not be retrieved during a rekey.
    #[form = "Unable to get encrypted_msg_entropy_banks"]
    RekeyEntropyBankMissing = 75,
    /// The message and scramble entropy-bank versions disagreed.
    #[form = "Message entropy_bank version != scramble entropy_bank version"]
    RekeyEntropyBankVersionMismatch = 76,
    /// The message and scramble entropy-bank cids disagreed.
    #[form = "Message entropy_bank cid != scramble entropy_bank cid"]
    RekeyEntropyBankCidMismatch = 77,
    /// The messenger outbound stream is no longer active.
    #[form = "Cannot send encrypted messages (stream died)"]
    MessengerStreamDied = 78,
    /// The ratchet manager's outbound stream died while sending.
    #[form = "Ratchet Manager's outbound stream died"]
    RatchetManagerStreamDied = 79,
    /// A decode/transient-id trailer had the wrong size.
    #[form = "Bad input size of {} (transient id)"]
    BadTransientIdSize = 80,
    /// A GroupReceiverConfig failed validation.
    #[form = "Invalid GroupReceiverConfig: {}"]
    InvalidGroupReceiverConfig = 81,
    /// A scrambler source could not yield its filename.
    #[form = "Unable to get filename"]
    SourceFilenameUnavailable = 82,
    /// A bytes source had already been exhausted.
    #[form = "Source has already been exhausted"]
    SourceExhausted = 83,
    /// The requested group size exceeded the maximum.
    #[form = "Maximum group size cannot be larger than {} bytes"]
    GroupSizeTooLarge = 84,
    /// Argon password hashing failed during autotuning.
    #[form = "Unable to hash password: {}"]
    ArgonHashFailed = 85,
}
