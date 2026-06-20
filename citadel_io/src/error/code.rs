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

    // --- citadel_proto: session ---
    /// A session-level lookup for a client account returned nothing.
    #[form = "Client does not exist"]
    SessionClientNotLoaded = 160,
    /// A session's zero-state (pre-connect handshake) could not be completed.
    #[form = "Unable to proceed past session zero-state. Stopping session: {}"]
    SessionZeroStateFailed = 161,
    /// The session's queue worker terminated unexpectedly.
    #[form = "Queue worker ended unexpectedly"]
    SessionQueueWorkerEnded = 162,
    /// A session's outbound writer stream was corrupted.
    #[form = "Writer stream corrupted"]
    SessionWriterStreamCorrupted = 163,
    /// The proposed connection credentials were not loaded.
    #[form = "Proposed credentials not loaded"]
    SessionProposedCredentialsNotLoaded = 164,
    /// The passwordless connection state was not loaded.
    #[form = "Passwordless state not loaded"]
    SessionPasswordlessStateNotLoaded = 165,
    /// The Alice-side ratchet could not be constructed during session setup.
    #[form = "Unable to construct Alice ratchet"]
    SessionAliceRatchetConstructionFailed = 166,
    /// The Alice-to-Bob transfer could not be constructed during session setup.
    #[form = "Unable to construct AliceToBob transfer"]
    SessionAliceToBobTransferFailed = 167,
    /// The session connect-mode was not loaded.
    #[form = "Connect mode not loaded"]
    SessionConnectModeNotLoaded = 168,
    /// The requested session security setting exceeds the registration setting.
    #[form = "The specified security setting for the session exceeds the registration security setting"]
    SessionSecurityExceedsRegistration = 169,
    /// The session's primary stream closed unexpectedly.
    #[form = "Primary stream closed"]
    SessionPrimaryStreamClosed = 170,
    /// The session's primary stream disconnected.
    #[form = "Primary stream disconnected"]
    SessionPrimaryStreamDisconnected = 171,
    /// A send through the session's primary stream failed (no further context).
    #[form = "Unable to send through primary stream"]
    SessionPrimaryStreamSendFailed = 172,
    /// The session's primary stream sender was absent.
    #[form = "Primary stream sender absent"]
    SessionPrimaryStreamSenderAbsent = 173,
    /// The session is not connected.
    #[form = "Session is not connected"]
    SessionNotConnected = 174,
    /// An outbound request was attempted while the session is not connected (ticket).
    #[form = "Attempted to send a request (ticket: {}) outbound, but the session is not connected"]
    SessionRequestNotConnected = 175,
    /// The session's implicated CID was not set.
    #[form = "Implicated CID not set"]
    SessionImplicatedCidNotSet = 176,
    /// A required configuration was invalid during session setup.
    #[form = "Invalid configuration"]
    SessionInvalidConfiguration = 177,
    /// The endpoint virtual-connection crypto could not be obtained.
    #[form = "Unable to get virtual connection crypto"]
    SessionVconnCryptoMissing = 178,
    /// The endpoint ratchet was missing for the outbound target.
    #[form = "Ratchet missing for endpoint"]
    SessionRatchetMissingForEndpoint = 179,
    /// A connection was unavailable (shutdown in progress or connection closed).
    #[form = "Connection unavailable (shutdown in progress or connection closed)"]
    SessionConnectionUnavailable = 180,
    /// HyperWAN functionality was requested but is not yet implemented.
    #[form = "HyperWAN functionality not yet implemented"]
    SessionHyperWanNotImplemented = 181,

    // --- citadel_proto: file transfer ---
    /// File transfer is disabled for the session (both nodes must use a filesystem backend).
    #[form = "File transfer is not enabled for this session. Both nodes must use a filesystem backend"]
    FileTransferSessionDisabled = 182,
    /// File transfer is disabled for the p2p session (both nodes must use a filesystem backend).
    #[form = "File transfer is not enabled for this p2p session. Both nodes must use a filesystem backend"]
    FileTransferP2pDisabled = 183,
    /// A file-transfer source object did not carry a path location.
    #[form = "The source object does not have a path location"]
    FileTransferSourceMissingPath = 184,
    /// HyperWAN functionality is not yet enabled for the file-header ACK path.
    #[form = "HyperWAN functionality not yet enabled for file-header ACK"]
    FileTransferHyperWanAckUnsupported = 185,
    /// An outbound file transfer was already started (missing start signal) (key).
    #[form = "Outbound file transfer {} already started (missing start signal)"]
    FileTransferAlreadyStarted = 186,
    /// Signalling the cryptscrambler to start failed (key).
    #[form = "Failed to signal cryptscrambler start for {}"]
    FileTransferScramblerStartFailed = 187,
    /// Sending the TransferBeginning status failed (key, reason).
    #[form = "Failed to send TransferBeginning status for {}: {}"]
    FileTransferBeginningStatusFailed = 188,
    /// Alerting the kernel of an ObjectTransferHandle failed (key, reason).
    #[form = "Failed to alert kernel of ObjectTransferHandle for {}: {}"]
    FileTransferHandleAlertFailed = 189,
    /// The OutboundFileTransfer entry did not exist (key).
    #[form = "Attempted to obtain OutboundFileTransfer for {}, but it didn't exist"]
    FileTransferOutboundMissing = 190,
    /// A stop signal was missing for an outbound file (key).
    #[form = "Missing stop signal for outbound file {}"]
    FileTransferStopSignalMissing = 191,
    /// Stopping the cryptscrambler failed (key).
    #[form = "Failed to stop cryptscrambler for {}"]
    FileTransferScramblerStopFailed = 192,
    /// A start signal was missing for an outbound file (key).
    #[form = "Missing start signal for outbound file {}"]
    FileTransferStartSignalMissing = 193,
    /// Halting the cryptscrambler failed (key).
    #[form = "Failed to halt cryptscrambler for {}"]
    FileTransferScramblerHaltFailed = 194,
    /// The file-transfer handle map did not contain the requested key (file key).
    #[form = "file_transfer_handle does not contain key for {}"]
    FileTransferHandleKeyMissing = 195,
    /// File transfer is not supported on this platform.
    #[form = "File transfer not supported on this platform"]
    FileTransferPlatformUnsupported = 196,
    /// A REVFS file could not be pulled because it has not yet synchronized with the filesystem.
    #[form = "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem"]
    RevfsFileNotSynchronized = 197,
    /// REVFS is not yet enabled for the given virtual-connection type (type).
    #[form = "REVFS is not yet enabled for virtual connections of type {}"]
    RevfsUnsupportedConnectionType = 198,

    // --- citadel_proto: inbound group/file reassembly ---
    /// An inbound group header carried an invalid security level (level).
    #[form = "Invalid security level {} in group header"]
    InboundInvalidSecurityLevel = 199,
    /// A group header implied a file transfer, but the file key mapped to nothing (file key).
    #[form = "The GROUP HEADER implied a file transfer, but key {} maps to nothing"]
    InboundGroupHeaderFileKeyMissing = 200,
    /// A duplicate group HEADER was detected (group id).
    #[form = "Duplicate group HEADER detected ({})"]
    InboundDuplicateGroupHeader = 201,
    /// The inbound-groups map did not contain the expected key (group key).
    #[form = "inbound_groups does not contain key for {}"]
    InboundGroupKeyMissing = 202,
    /// A payload packet was missing its first byte.
    #[form = "Bad payload packet [0]"]
    InboundBadPayloadPacket0 = 203,
    /// A payload packet was missing its second byte.
    #[form = "Bad payload packet [1]"]
    InboundBadPayloadPacket1 = 204,
    /// The true sequence number could not be derived from a payload packet.
    #[form = "Unable to obtain true_sequence"]
    InboundTrueSequenceUnavailable = 205,
    /// The inbound-groups map vanished on group completion (group key).
    #[form = "inbound_groups vanished for {} on complete"]
    InboundGroupVanishedOnComplete = 206,
    /// The inbound-files map did not contain the expected key (file key).
    #[form = "inbound_files does not contain key for {}"]
    InboundFileKeyMissing = 207,
    /// The inbound-files map vanished on completion.
    #[form = "inbound_files vanished on complete"]
    InboundFileVanishedOnComplete = 208,
    /// The reception-complete signal could not be sent.
    #[form = "reception_complete_tx err"]
    InboundReceptionCompleteSendFailed = 209,

    // --- citadel_proto: session manager ---
    /// A hypernode session for the given CID does not exist (session cid).
    #[form = "Hypernode session for {} does not exist"]
    SessionManagerSessionNotFound = 210,
    /// A subroutine could not be initiated because the CID is not an active session (session cid).
    #[form = "Unable to initiate subroutine for {} (not an active session)"]
    SessionManagerNotActiveSession = 211,
    /// A peer command could not be dispatched because the session was not found (session cid).
    #[form = "Session for {} not found in session manager. Failed to dispatch peer command"]
    SessionManagerDispatchSessionNotFound = 212,
    /// The session manager's UnboundedReceiver was not loaded.
    #[form = "UnboundedReceiver not loaded in session manager"]
    SessionManagerReceiverNotLoaded = 213,
    /// The shutdown signal could not be received.
    #[form = "Unable to receive shutdown signal"]
    SessionManagerShutdownRecvFailed = 214,
    /// A peer stream was absent during a session-manager operation.
    #[form = "Peer stream absent"]
    SessionManagerPeerStreamAbsent = 215,
    /// A peer session could not be found (target cid).
    #[form = "Unable to find peer session {}"]
    SessionManagerPeerSessionNotFound = 216,

    // --- citadel_proto: state container (rekey / groups / vconns) ---
    /// A rekey was requested while the session is not connected.
    #[form = "Cannot initiate rekey since the session is not connected"]
    StateRekeyNotConnected = 217,
    /// External-group functionality was requested but is not yet implemented.
    #[form = "External group functionality not yet implemented"]
    StateExternalGroupNotImplemented = 218,
    /// An unsupported variant was used as a group broadcast request (variant).
    #[form = "{} is not a valid group broadcast request"]
    StateInvalidGroupBroadcastRequest = 219,
    /// The C2S virtual-connection crypto was not loaded.
    #[form = "C2s not loaded"]
    StateC2sNotLoaded = 220,
    /// The CNAC was not loaded during a state-container operation.
    #[form = "CNAC not loaded"]
    StateCnacNotLoaded = 221,
    /// A group channel already existed locally.
    #[form = "Group channel already exists locally"]
    StateGroupChannelExists = 222,
    /// A virtual connection could not be upgraded.
    #[form = "Unable to upgrade virtual connection"]
    StateVconnUpgradeFailed = 223,
    /// A duplicate active virtual connection was dropped on a simultaneous-connect race (target cid).
    #[form = "Active vconn for peer {} already exists (simultaneous connect race); duplicate Kex result dropped"]
    StateVconnSimultaneousRace = 224,
    /// A virtual connection to the peer could not be found (target cid).
    #[form = "Unable to find virtual connection to peer {}"]
    StateVconnNotFound = 225,
    /// An endpoint container to the peer could not be accessed (target cid).
    #[form = "Unable to access endpoint container to peer {}"]
    StateEndpointContainerNotFound = 226,
    /// The implicated CID was not loaded.
    #[form = "Implicated CID not loaded"]
    StateImplicatedCidNotLoaded = 227,

    // --- citadel_proto: endpoint crypto accessor ---
    /// The peer session crypto was missing.
    #[form = "Peer session crypto missing"]
    EndpointPeerCryptoMissing = 228,
    /// The requested endpoint ratchet does not exist.
    #[form = "Ratchet does not exist"]
    EndpointRatchetMissing = 229,

    // --- citadel_proto: validation / packet ---
    /// An initial packet failed AEAD validation.
    #[form = "Unable to validate initial packet"]
    ValidationInitialPacketFailed = 230,
    /// The Bob-side container could not be created during validation.
    #[form = "Unable to create bob container"]
    ValidationBobContainerFailed = 231,
    /// The Bob stage-0 step could not be executed during validation.
    #[form = "Unable to execute stage0_bob"]
    ValidationStage0BobFailed = 232,
    /// The Bob constructor could not be finished during validation.
    #[form = "Unable to finish bob constructor"]
    ValidationBobConstructorFinishFailed = 233,
    /// A first-packet key was invalid.
    #[form = "Invalid first packet key"]
    InvalidFirstPacketKey = 234,
    /// The first packet of a stream could not be obtained.
    #[form = "Unable to get first packet"]
    FirstPacketUnavailable = 235,
    /// A group header could not be transmitted (reason).
    #[form = "Unable to transmit group header: {}"]
    GroupHeaderTransmitFailed = 236,

    // --- citadel_proto: packet processor (connect / register / preconnect / keep-alive) ---
    /// A channel signal was missing on the connect success path.
    #[form = "Channel signal missing"]
    ConnectChannelSignalMissing = 237,
    /// A client received a SUCCESS_ACK (server-only packet).
    #[form = "Received a SUCCESS_ACK as a client"]
    ConnectSuccessAckAsClient = 238,
    /// A keep-alive packet could not be sent (reason).
    #[form = "Unable to send keep-alive: {}"]
    KeepAliveSendFailed = 239,
    /// A pre-connect SYN referenced a CID that is not registered to this node (cid).
    #[form = "CID {} is not registered to this node"]
    PreconnectCidNotRegistered = 240,
    /// The incoming protocol semver could not be parsed.
    #[form = "Unable to parse incoming protocol semver"]
    PreconnectSemverParseFailed = 241,
    /// A bob transfer was malformed during registration.
    #[form = "Bad bob transfer"]
    RegisterBadBobTransfer = 242,
    /// The Bob stage-0 step could not be advanced during registration.
    #[form = "Unable to advance past stage0-bob"]
    RegisterStage0BobFailed = 243,
    /// The Bob constructor could not be finished during registration.
    #[form = "Unable to finish bob constructor"]
    RegisterBobConstructorFinishFailed = 244,
    /// The Alice constructor could not be finished during registration.
    #[form = "Unable to finish alice constructor"]
    RegisterAliceConstructorFinishFailed = 245,
    /// A spawned task failed to join (reason).
    #[form = "Join error: {}"]
    TaskJoinFailed = 246,

    // --- citadel_proto: peer ---
    /// The p2p stopper fired, indicating the stream was replaced or discarded.
    #[form = "p2p stopper triggered"]
    P2pStopperTriggered = 247,
    /// The P2P session was dropped.
    #[form = "P2P Session dropped"]
    P2pSessionDropped = 248,
    /// The P2P listener returned None (stream dead).
    #[form = "P2P Listener returned None"]
    P2pListenerReturnedNone = 249,
    /// The caller lacks permission to make this group call.
    #[form = "User does not have permissions to make this call"]
    PeerPermissionDenied = 250,
    /// The kernel TX channel is dead (reason).
    #[form = "Kernel TX is dead: {}"]
    PeerKernelTxDead = 251,
    /// The queue handler signalled shutdown.
    #[form = "Queue handler signalled shutdown"]
    QueueHandlerShutdown = 252,

    // --- citadel_proto: kernel ---
    /// A notifier was overwritten in the kernel communicator.
    #[form = "Overwrote previous notifier"]
    KernelNotifierOverwritten = 253,
    /// The kernel disconnected from the hypernode instance.
    #[form = "kernel disconnected from hypernode instance"]
    KernelDisconnected = 254,
    /// The primary session listener died.
    #[form = "Primary session listener died"]
    KernelPrimaryListenerDied = 255,
    /// An outbound request used a zero CID (request).
    #[form = "Cannot use zero-cid for outbound requests. Invalid: {}"]
    KernelZeroCidRequest = 256,

    // --- citadel_proto: native UDP / IO ---
    /// The HDP session no longer exists.
    #[form = "HdpSession no longer exists"]
    UdpHdpSessionGone = 257,
    /// A UDP channel could not be sent through its sender.
    #[form = "Unable to send UdpChannel through"]
    UdpChannelSendFailed = 258,
    /// The state container had no UDP sender while loading a UDP channel.
    #[form = "Tried loading UDP channel, but, the state container had no UDP sender"]
    UdpStateContainerNoSender = 259,
    /// The state container had an invalid configuration while loading a UDP channel (TCP first).
    #[form = "Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first"]
    UdpStateContainerInvalidConfig = 260,
    /// The peer KEM state was absent while loading a UDP channel.
    #[form = "Tried loading the peer kem state, but was absent"]
    UdpPeerKemStateAbsent = 261,
    /// A UDP operation referenced an invalid virtual target.
    #[form = "Invalid virtual target"]
    UdpInvalidVirtualTarget = 262,
    /// The UDP sink could not receive outbound requests.
    #[form = "UDP sink unable to receive outbound requests"]
    UdpSinkRecvFailed = 263,
    /// A session already exists for the given CID (disconnect before reconnecting) (cid).
    #[form = "Session for CID {} already exists. Disconnect first before reconnecting."]
    SessionManagerSessionAlreadyExists = 264,
    /// A provisional outbound connection to the given peer is already in progress (peer addr).
    #[form = "Localhost is already trying to connect to {}"]
    SessionManagerProvisionalConnectionExists = 265,

    // --- citadel_sdk: builder / node ---
    /// A node could not be built from its configuration (reason).
    #[form = "Failed to build node: {}"]
    NodeBuildFailed = 266,
    /// The default server transport config could not be created (reason).
    #[form = "Failed to create default server config: {}"]
    NodeDefaultServerConfigFailed = 267,

    // --- citadel_sdk: remote-ext ---
    /// A supplied socket address could not be resolved to a usable address.
    #[form = "Invalid socket addr"]
    RemoteInvalidSocketAddr = 268,
    /// A registration request was rejected by the server (reason).
    #[form = "{}"]
    RemoteRegisterFailure = 269,
    /// The session was disconnected during an operation (reason).
    #[form = "{}"]
    RemoteDisconnected = 270,
    /// The internal kernel stream died while awaiting a response (operation).
    #[form = "Internal kernel stream died ({})"]
    RemoteKernelStreamDied = 271,
    /// A connect attempt failed (reason).
    #[form = "{}"]
    RemoteConnectFailed = 272,
    /// An unexpected response was received while connecting (response).
    #[form = "[connect] An unexpected response occurred: {}"]
    RemoteConnectUnexpectedResponse = 273,
    /// The requested target pair could not be found.
    #[form = "Target pair not found"]
    RemoteTargetPairNotFound = 274,
    /// The active-sessions query stream died.
    #[form = "Stream died"]
    RemoteSessionStreamDied = 275,
    /// The SDK sessions could not be queried.
    #[form = "Failed to query SDK sessions"]
    RemoteQuerySessionsFailed = 276,
    /// The referenced user does not exist locally.
    #[form = "User does not exist"]
    RemoteUserDoesNotExist = 277,
    /// A file-transfer handle failed while streaming (reason).
    #[form = "{}"]
    RemoteFileTransferFailed = 278,
    /// A file-transfer stream died before completion.
    #[form = "File transfer stream died"]
    RemoteFileTransferStreamDied = 279,
    /// A virtual path was invalid for a RE-VFS operation (reason).
    #[form = "{}"]
    RemoteRevfsInvalidVirtualPath = 280,
    /// An invalid response was received from the protocol during a RE-VFS operation.
    #[form = "Received invalid response from protocol"]
    RemoteRevfsInvalidResponse = 281,
    /// A RE-VFS file-transfer stream died before completion.
    #[form = "REVFS File transfer stream died"]
    RemoteRevfsFileTransferStreamDied = 282,
    /// A RE-VFS delete stream died before completion.
    #[form = "REVFS Delete stream died"]
    RemoteRevfsDeleteStreamDied = 283,
    /// A peer did not respond to a connection request in time.
    #[form = "Peer did not respond in time"]
    RemotePeerNoResponse = 284,
    /// A peer declined the connection request.
    #[form = "Peer declined to connect"]
    RemotePeerDeclined = 285,
    /// A P2P connection timed out waiting for PeerChannelCreated (timeout seconds).
    #[form = "P2P connection timed out after {}s waiting for PeerChannelCreated"]
    RemoteP2pConnectTimeout = 286,
    /// No username could be found for the local user.
    #[form = "Unable to find username for local user"]
    RemoteLocalUsernameMissing = 287,
    /// A deregister operation ended unexpectedly.
    #[form = "Deregister ended unexpectedly"]
    RemoteDeregisterEndedUnexpectedly = 288,
    /// A deregistration request was rejected (status=false).
    #[form = "Unable to deregister: status=false"]
    RemoteDeregisterFailed = 289,
    /// No valid disconnect event was received.
    #[form = "Unable to receive valid disconnect event"]
    RemoteDisconnectEventMissing = 290,
    /// External group peer functionality is not enabled.
    #[form = "External group peer functionality not enabled"]
    RemoteExternalGroupPeerUnsupported = 291,
    /// A create-group operation ended unexpectedly.
    #[form = "Create_group ended unexpectedly"]
    RemoteCreateGroupEndedUnexpectedly = 292,
    /// An account could not be found for a local user while creating a group (account, local user).
    #[form = "Account {} not found for local user {}"]
    RemoteGroupAccountNotFound = 293,
    /// A list-owned-groups operation ended unexpectedly.
    #[form = "List_members ended unexpectedly"]
    RemoteListGroupsEndedUnexpectedly = 294,
    /// A list-sessions operation ended unexpectedly.
    #[form = "List_sessions ended unexpectedly"]
    RemoteListSessionsEndedUnexpectedly = 295,
    /// A rekey operation failed (reason).
    #[form = "Rekey failed: {}"]
    RemoteRekeyFailed = 296,
    /// A rekey operation ended unexpectedly.
    #[form = "Rekey ended unexpectedly"]
    RemoteRekeyEndedUnexpectedly = 297,
    /// External group peers are not yet supported.
    #[form = "External group peers are not supported yet"]
    RemoteExternalGroupPeerUnsupportedYet = 298,
    /// The locked target is not a peer.
    #[form = "Target is not a peer"]
    RemoteTargetNotPeer = 299,
    /// A target_cid of 0 was used without supplying a username.
    #[form = "target_cid=0, yet, no username was provided"]
    RemoteTargetCidZeroNoUsername = 300,
    /// RE-VFS can only be used with the Kyber/ML-KEM KEM.
    #[form = "RE-VFS can only be used with Kyber KEM"]
    RemoteRevfsRequiresKyber = 301,
    /// RE-VFS cannot be used with this remote type.
    #[form = "RE-VFS cannot be used with this remote type"]
    RemoteRevfsUnsupportedRemote = 302,
    /// A one-shot accessor function was already called.
    #[form = "This function has already been called"]
    RemoteFunctionAlreadyCalled = 303,

    // --- citadel_sdk: responses ---
    /// The local username implied by a peer signal could not be found.
    #[form = "Unable to find local username implied by signal"]
    ResponseLocalUsernameMissing = 304,
    /// An input signal was not a valid PostRegister.
    #[form = "Input signal is not a valid PostRegister"]
    ResponseNotPostRegister = 305,
    /// An input signal was not a valid PostConnect.
    #[form = "Input signal is not a valid PostConnect"]
    ResponseNotPostConnect = 306,
    /// An input signal was not a group invitation.
    #[form = "Input signal is not a group invitation"]
    ResponseNotGroupInvitation = 307,
    /// A response event was improperly formed (missing ticket).
    #[form = "This event was improperly formed"]
    ResponseEventImproperlyFormed = 308,

    // --- citadel_sdk: prefabs / client ---
    /// An address could not be resolved while building connection settings.
    #[form = "No address found"]
    BuilderNoAddress = 309,
    /// A username was required but not provided while building connection settings.
    #[form = "No username found"]
    BuilderNoUsername = 310,
    /// A password was required but not provided while building connection settings.
    #[form = "No password found"]
    BuilderNoPassword = 311,
    /// An alias was required but not provided while building connection settings.
    #[form = "No alias found"]
    BuilderNoAlias = 312,
    /// An invalid socket address was specified while resolving a target.
    #[form = "Invalid socket address specified"]
    BuilderInvalidSocketAddress = 313,
    /// A user is not registered to the local user during group creation (peer, local user).
    #[form = "[create] User {} is not registered to {}"]
    BroadcastCreateUserNotRegistered = 314,
    /// A user is not registered to the local user during a group join (owner, local user).
    #[form = "User {} is not registered to {}"]
    BroadcastJoinUserNotRegistered = 315,
    /// A group owner has not created the expected group yet (owner, group id).
    #[form = "Owner {} has not created group {}"]
    BroadcastOwnerGroupMissing = 316,
    /// A message group could not be created.
    #[form = "Unable to create a message group"]
    BroadcastCreateGroupFailed = 317,
    /// A broadcast subscription/registration stream ended unexpectedly (stream).
    #[form = "{} ended unexpectedly"]
    BroadcastStreamEndedUnexpectedly = 318,

    // --- citadel_sdk: prefabs / server ---
    /// A test server ended prematurely (result).
    #[form = "Server ended prematurely: {}"]
    PrefabServerEndedPrematurely = 319,
    /// A hyper HTTP error occurred in the internal service (reason).
    #[form = "Hyper error: {}"]
    InternalServiceHyperError = 320,
    /// An internal-service response did not match the request.
    #[form = "Response did not match request"]
    InternalServiceResponseMismatch = 321,

    // --- citadel_sdk: net / serverless ---
    /// The kernel stopped before a serverless connection was established.
    #[form = "Kernel stopped before connection established"]
    ServerlessKernelStoppedEarly = 322,

    // --- citadel_proto: group CGKA (zero-trust TreeKEM) ---
    /// Failed to (de)serialize a TreeKEM CGKA artifact.
    #[form = "Group CGKA serialization failed for {}"]
    ProtoGroupCgkaSerialization = 323,
    /// A non-owner attempted a committer-only operation (Add/Remove).
    #[form = "Only the group owner may commit membership changes"]
    ProtoGroupCgkaNotOwner = 324,
    /// The group's CGKA state is not present (not yet bootstrapped, or unknown group).
    #[form = "Group CGKA state is not initialized"]
    ProtoGroupCgkaNoState = 325,
}
