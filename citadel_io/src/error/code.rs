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

    // --- async_ip: IP resolution ---
    /// The internal (LAN) IP address could not be obtained.
    #[form = "Could not obtain internal IP"]
    IpInternalUnobtainable = 86,

    // --- citadel_wire: NAT traversal / hole-punch ---
    /// NAT type identification did not complete within its timeout.
    #[form = "NAT identification elapsed"]
    FirewallNatIdentTimeout = 87,
    /// The UDP hole-punch did not complete within its timeout.
    #[form = "Timeout while waiting for UDP penetration"]
    FirewallPenetrationTimeout = 88,
    /// The connection was reset while waiting for UDP hole-punch penetration.
    #[form = "Connection reset while waiting for UDP penetration"]
    FirewallConnectionReset = 89,
    /// A hole-punch step ran without its UDP socket having been loaded.
    #[form = "UDP socket not loaded"]
    FirewallUdpSocketNotLoaded = 90,
    /// The kill switch fired but no matching internal hole-punch values were found.
    #[form = "Kill switch called, but no matching values were found internally"]
    FirewallKillSwitchNoMatch = 91,

    // --- citadel_wire: UPnP ---
    /// UPnP port mapping was requested over a LAN IPv6 address, which is unsupported.
    #[form = "Detected LAN IPv6. Not yet implemented"]
    FirewallUpnpLanIpv6Unsupported = 92,

    // --- citadel_types: crypto parameter validation ---
    /// ML-KEM hybrid encryption was selected without the ML-KEM key-exchange algorithm.
    #[form = "Invalid crypto parameter combination. ML-KEM hybrid encryption must be paired with ML-KEM"]
    CryptoParamsHybridRequiresMlKem = 93,
    /// ML-KEM hybrid encryption was selected without a post-quantum signature scheme.
    #[form = "A post-quantum signature scheme must be selected when using ML-KEM hybrid encryption"]
    CryptoParamsHybridRequiresSig = 94,
    /// A raw `u8` could not be cast into the named crypto-parameter enum (value, enum name).
    #[form = "Cannot cast `{}` into {}"]
    CryptoParamEnumCastFailed = 95,

    // --- citadel_pqcrypto: signatures ---
    /// A signature operation was attempted with no signature algorithm selected.
    #[form = "No signature algorithm selected"]
    SigNoneSelected = 96,
    /// A signature key could not be deserialized (scheme, key kind).
    #[form = "Failed to deserialize {} {}"]
    SigKeyDeserializeFailed = 97,
    /// A signature object could not be decoded (scheme, object kind).
    #[form = "Failed to decode {} {}"]
    SigDecodeFailed = 98,
    /// Signature verification failed (scheme).
    #[form = "{} signature verification failed"]
    SigVerificationFailed = 99,
    /// A Falcon signing key had an invalid length.
    #[form = "Invalid Falcon signing key length"]
    FalconKeyLengthInvalid = 100,

    // --- citadel_pqcrypto: container / keystore ---
    /// The recursive keystore could not be computed during Bob construction.
    #[form = "Error while calculating recursive keystore: {}"]
    RecursiveKeystoreFailed = 101,
    /// A post-quantum container failed (de)serialization.
    #[form = "Deserialization failure"]
    ContainerSerdeFailed = 102,
    /// An in-place buffer window range was invalid.
    #[form = "Bad window range"]
    BadWindowRange = 103,
    /// An anti-replay-attack PID was rejected as already seen / invalid.
    #[form = "Anti-replay-attack: invalid"]
    AntiReplayInvalid = 104,
    /// The anti-replay-attack PID inscription had the wrong length.
    #[form = "Anti-replay-attack: Invalid inscription length"]
    AntiReplayBadLength = 105,
    /// A secret key could not be retrieved from a post-quantum container.
    #[form = "Unable to get secret key"]
    SecretKeyUnavailable = 106,
    /// A ciphertext could not be retrieved from a post-quantum container.
    #[form = "Unable to get ciphertext"]
    CiphertextUnavailable = 107,
    /// A KEM encapsulation step failed.
    #[form = "Failed encapsulate step"]
    EncapsulateFailed = 108,

    // --- citadel_pqcrypto: encoding / framing ---
    /// The trailing length field had the wrong byte count.
    #[form = "Bad sig_size_bytes length"]
    BadSigSizeBytesLength = 109,
    /// A decoded length field exceeded the available buffer (decoded, buffer len).
    #[form = "Decoded length = {}, yet, input buffer's len is only {}"]
    DecodedLengthExceedsBuffer = 110,
    /// A decoded signature length exceeded the buffer (sig len, buffer len).
    #[form = "Invalid signature length: {} > buffer length {}"]
    InvalidSignatureLength = 111,
    /// The ciphertext checksum did not match (computed, expected).
    #[form = "Invalid ciphertext checksum. {} != {}"]
    InvalidCiphertextChecksum = 112,
    /// The provided nonce was shorter than the cipher requires.
    #[form = "Nonce too short"]
    NonceTooShort = 113,
    /// A truncate was requested past the buffer length (requested len, buffer len).
    #[form = "Cannot truncate len={} when buffer len={}"]
    BufferTruncateOutOfRange = 114,
    /// The scrambler input length was not a multiple of the block size (len).
    #[form = "Invalid input len for scrambler: {}"]
    ScramblerInvalidInputLength = 115,
    /// A scrambler block had the wrong length.
    #[form = "Bad input buffer length"]
    ScramblerBadBlockLength = 116,

    // --- citadel_user: registration / account manager ---
    /// A backend database URL did not parse into a supported target.
    #[form = "Invalid database URL format. Please check documentation for preferred format"]
    BackendUrlInvalid = 117,
    /// The account manager could not establish a backend connection.
    #[form = "Unable to connect to remote database via account manager"]
    BackendNotConnected = 118,
    /// A client network account registration was attempted with a CID of 0.
    #[form = "Cannot register a client network account with a CID of 0"]
    RegisterCidZero = 119,
    /// The chosen username is already taken (username).
    #[form = "Username {} already exists!"]
    UsernameExists = 120,
    /// A cryptographically secure CNAC was requested with a CID of 0.
    #[form = "Cannot create a cryptographically secure CNAC with a CID of 0"]
    CnacCidZero = 121,

    // --- citadel_user: auth / credentials ---
    /// Argon hashing returned an unexpected (non-success) status (status).
    #[form = "Unable to hash input password: {}"]
    ArgonHashUnexpected = 122,
    /// The node was asked for a passwordless connection it does not support.
    #[form = "This node does not support passwordless connections"]
    PasswordlessUnsupported = 123,
    /// A password hash could not be produced.
    #[form = "Unable to hash password"]
    PasswordHashFailed = 124,
    /// Password validation was attempted on a personal (passwordless) account.
    #[form = "Account does not have password loaded; account is personal"]
    AccountNotPasswordProtected = 125,
    /// The supplied username length was outside the allowed range (min, max).
    #[form = "Username must be between {} and {} characters"]
    UsernameLengthOutOfRange = 126,
    /// The supplied username contained spaces.
    #[form = "Username cannot contain spaces. Use a period instead"]
    UsernameContainsSpaces = 127,
    /// The supplied password length was outside the allowed range (min, max).
    #[form = "Password must be between {} and {} characters"]
    PasswordLengthOutOfRange = 128,
    /// The supplied password contained spaces.
    #[form = "Password cannot contain spaces"]
    PasswordContainsSpaces = 129,
    /// The supplied full name length was outside the allowed range (min, max).
    #[form = "Full name must be between {} and {} characters"]
    FullNameLengthOutOfRange = 130,

    // --- citadel_user: client account / connection metadata ---
    /// Mutual-peer removal from the counterpart CNAC failed.
    #[form = "Could not remove self from other cnac"]
    PeerRemoveSelfFailed = 131,
    /// A connection target resolved to no socket address.
    #[form = "No socket address"]
    NoSocketAddress = 132,

    // --- citadel_user: backend selection / RE-VFS ---
    /// A backend address did not match any compiled-in backend (addr).
    #[form = "The addr '{}' is not a valid target (hint: ensure either 'redis', 'sql', 'filesystem', or 'opfs' features are enabled when compiling)"]
    BackendTargetInvalid = 133,
    /// The selected backend does not implement the RE-VFS protocol.
    #[form = "The target does not support the RE-VFS protocol"]
    RevfsUnsupported = 134,

    // --- citadel_user: file transfer ---
    /// A file-transfer target name was empty.
    #[form = "File transfer target name is empty"]
    FileTransferNameEmpty = 135,
    /// A file-transfer target name was rejected as unsafe (name).
    #[form = "File transfer target name {} is not permitted (possible path traversal)"]
    FileTransferNameInvalid = 136,
    /// A file transfer was requested without a target name.
    #[form = "File transfer type specified, yet, no target name given"]
    FileTransferNoTargetName = 137,
    /// A file transfer reported a failure status (reason).
    #[form = "File transfer failed: {}"]
    FileTransferFailed = 138,
    /// The file-transfer stream ended before completion.
    #[form = "Failed to receive file: stream ended"]
    FileReceiveStreamEnded = 139,
    /// A completed file reception yielded no save path.
    #[form = "Failed to receive file: no file path"]
    FileReceiveNoPath = 140,
    /// A receive was requested on a non-Receiver handle.
    #[form = "Cannot receive file: orientation is not Receiver"]
    FileReceiveWrongOrientation = 141,
    /// A transfer was requested on a non-Sender handle.
    #[form = "Cannot transfer file: orientation is not Sender"]
    FileTransferWrongOrientation = 142,
    /// A file transfer returned a save path where none was expected.
    #[form = "An unexpected error occurred: file transfer occurred, yet, returned a save path. Please report to developers"]
    FileTransferUnexpectedSavePath = 143,
    /// A file-transfer accept/decline response could not be delivered.
    #[form = "Failed to send response"]
    FileTransferResponseFailed = 144,

    // --- citadel_user: virtual path validation ---
    /// A virtual path was not an absolute remote encrypted directory (path).
    #[form = "Path {} is not a valid remote encrypted virtual directory"]
    VirtualPathNotRemoteDir = 145,
    /// A virtual path referred to a directory, not a file (path).
    #[form = "Path {} is a directory, not a file"]
    VirtualPathIsDirectory = 146,
    /// A virtual path contained a `..` traversal segment (path).
    #[form = "Path {} cannot contain '..' for security reasons"]
    VirtualPathTraversal = 147,

    // --- citadel_user: serialization ---
    /// A value could not be serialized (reason).
    #[form = "Serialization failed: {}"]
    SerializationFailed = 148,
    /// A value could not be deserialized (reason).
    #[form = "Deserialization failed: {}"]
    DeserializationFailed = 149,

    // --- citadel_user: backend/sql ---
    /// A SQL backend operation failed (reason).
    #[form = "Database operation failed: {}"]
    SqlOp = 150,
    /// A SQL backend operation was attempted before the connection was loaded.
    #[form = "Connection not loaded"]
    SqlConnectionNotLoaded = 151,
    /// A peer CID could not be decoded from a SQL row.
    #[form = "Failed to decode peer cid"]
    SqlDecodePeerCid = 152,
    /// A SQL column had an unexpected type (type info).
    #[form = "Expected blob or text, got {}"]
    SqlUnexpectedColumnType = 153,

    // --- citadel_user: backend/redis ---
    /// A Redis backend operation failed (reason).
    #[form = "Redis operation failed: {}"]
    RedisOp = 154,
    /// A Redis backend operation was attempted before the client was loaded.
    #[form = "Redis client not loaded"]
    RedisClientNotLoaded = 155,
    /// Redis pool `max_open` was configured below `max_idle`.
    #[form = "Max open must be greater than or equal to max_idle"]
    RedisMaxOpenLessThanIdle = 156,

    // --- citadel_user: external services ---
    /// An external service (Google auth / Firebase RTDB) call failed (reason).
    #[form = "External service error: {}"]
    ExternalService = 157,
    /// A Google services file was missing its private key.
    #[form = "Private key does not exist"]
    GooglePrivateKeyMissing = 158,
    /// A Google services file was missing its service email.
    #[form = "Service email not present"]
    GoogleServiceEmailMissing = 159,
}
