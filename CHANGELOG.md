# Changelog

## Unreleased

### Added

- **A server chooses whether transient accounts are allowed.** A transient account is a session
  with its own CID that the server never persists and that has no password
  (`AuthenticationRequest::transient`, `ServerConnectionSettingsBuilder::transient`).
  - `NodeBuilder::with_transient_accounts(bool)` says it on the builder. Without the call they
    are allowed, as before: a deliberate default, approved for the product, not a fallback.
  - The option sets the one field the protocol reads, `ServerMiscSettings::allow_transient_connections`.
    With `with_server_misc_settings` as well, `false` wins whatever the settings hold, and `true`
    against settings that say `false` fails the build with `ErrorCode::NodeTransientAccountsConflict`.
    A peer given the option fails the build with `ErrorCode::NodeTransientAccountsNotServer`.
  - **A refusal is named.** A server that disallows them now answers a transient request with
    `ErrorCode::PasswordlessUnsupported` (code 123) in its registration FAILURE, so
    `NodeResult::into_result` (and every `connect`) returns that code instead of a `Generic` error
    whose text says so. The message is now "This server does not allow transient accounts". No
    protocol change: every peer the version gate admits reads coded refusals.
  - Docs say "transient account" where they said "passwordless" or "anonymous".
- **Resume credentials: signing in again without the account's factors.**
  - **Asking.** A full sign-in asks for one with `SignInFactors::with_resume_lifetime`; the
    connection carries it (`CitadelClientServerConnection::resume`) with the moment it expires
    (`ResumeCredential::valid_until_utc`, Unix milliseconds, UTC). `SignInFactors::resume` signs
    in with it: no password and no security-key touch.
  - **What it is.** The device draws an ML-KEM-1024 key; the server answers with a grant, an
    HMAC-SHA3-256 over the account, the grant's times, a hash of the account's sign-in state and
    the device key's fingerprint, under a key derived from the tenant's OPRF seed. To resume, the
    server checks the grant against itself and the account's record, then challenges the device
    key as it challenges any factor. It stores nothing for a grant and keeps no list of them.
  - **The server's limit.** `PqAuthServerSettings::with_resume(ResumePolicy::new(max))`. There is
    no default: a server without a policy issues and honours none. The challenge tells the client
    the maximum, the client asks for no more, and the server grants no more whatever is asked. A
    maximum lowered later shortens the grants already issued.
  - **Refusals, by name.** `ErrorCode::ResumeCredentialExpired` past the expiry (the client
    refuses its own expired credential before anything is sent; the server refuses one
    regardless). `ErrorCode::ResumeCredentialRevoked` once the account's password, policy or set
    of keys has changed. A forged or altered grant, or one without its device key, is an ordinary
    `PqSignInFailed`.
  - **Never renewed.** A sign-in with a credential is given no new one, and a recovery session is
    given none.
  - **A session's own change.** `SignInManagementExt::change_sign_in` sends the device's
    credential with the change and gets it back bound to the account as the change leaves it,
    expiring when it always did.
  - `FactorKind::ResumeKey` is exported by `@avarok/citadel-protocol-types` (0.15.2).
- **A refused connect is named by its code.** A connect FAILURE carries its `ErrorCode`, and
  `NodeResult::into_result` rebuilds the error under it, as a refused registration already was;
  `ConnectFail::error_code` holds it. A wrong password is `PqSignInFailed`, not a `Generic` error
  whose text says so.
- **Protocol 0.12.6.** Sign-in messages and connect STAGE0 changed layout, so a node takes part
  only with nodes at 0.12.6 or later.
- **Group state that outlives the session, and the account's device.**
  - **Local state.** A client keeps each ordinary group's TreeKEM state in its account store
    (`peer::group_state_store`). A returning session resumes it (`ResumeMembership`,
    `ResumeOwnership`) instead of rejoining.
  - **Replay on return.** The server replays, oldest first, what it held for the member while it
    was away, then marks the end of the replay (`Resumed`). One lock orders every group fan-out
    against a replay.
  - **Sealed copy at the server.** The state is also kept at the server, sealed under the
    account's RE-VFS key (`RevfsKeySource`, derived from the recovery or identity seed;
    `peer::group_backup`). An account recovered on a new device with its phrase resumes its
    groups and reads what was sent while it was away.
  - **Leaf replacement.** It then replaces its leaf, so the device it left reads nothing from the
    owner's next epoch on.
- **Group sends are answered per member.** `MessageResponse::delivery` is a `GroupDelivery`:
  - `Relayed` lists the members it reached now, the members it is held for, and each member it did
    not reach, with the reason (`NotDelivered::{Offline, BacklogFull, Unreachable}`);
  - `NotRelayed` says why it reached no one.
- **Bounded group backlogs.**
  - `NodeBuilder::with_group_mail_limits(GroupMailLimits { max_age, max_messages, max_bytes })`
    sets what a server holds per away member and group. Without it a server holds
    `GroupMailLimits::default()`: 7 days, 1000 messages, 16 MiB.
  - `MessageGroupOptions::retention` asks for less than `max_age`, never more.
  - A message past a member's cap is not held for that member, and the sender's `GroupDelivery`
    says so. Group control is always held.
- **Groups tell the application how they end and come back.**
  - `GroupBroadcast::Disconnected { key, reason }` carries a `GroupEndReason`: `ClosedByOwner`,
    `Removed`, or `HierarchyOwnerGone` (a command hierarchy ends when its owner leaves; its ranks
    are the owner's alone, so the members may start a new group).
  - `GroupBroadcast::Restored { key, source }` is told once per group when a session gets it back:
    `GroupStateSource::{ThisDevice, Backup, Rejoined, Refounded}`.
  - `GroupDelivery`, `NotDelivered`, `NotRelayed`, `GroupMessageRefusal`, `GroupEndReason` and
    `GroupStateSource` are exported by `@avarok/citadel-protocol-types`.
- **An owner restored from the account's backup replaces its own leaf.** A Commit with an
  `Update` proposal replaces the leaf's KEM and signing keys; the epoch it leaves stays readable
  for the other members. Every commit now replaces the committer's signing key with its KEM key
  (`UpdatePath::leaf_sig_public`).
- **A group passes to its highest-cid member when its owner leaves, closes it or deletes its
  account.** The server records the successor at once, whether or not it is online, and the group
  keeps relaying: the owner is not needed for that. A successor that was away takes over when it
  resumes, from the state it kept: it reads everything held for it, then commits the departed
  owner out (`Resumed` carries the group's owner and members). Nothing held for anyone is
  dropped. An owner that is only offline, however long, is not succeeded. A command hierarchy
  ends with its owner instead (`HierarchyOwnerGone`).
- **Group rows are keyed by group id** (`<creator cid>-<mgid>`, under the owner's account) and move
  with ownership, so a group outlives its creator's account. A row in any other format is refused
  by name at startup.
- **Group traffic is handled in the order it arrived.** A session's group broadcasts are handled
  one after another, on the server and on every member, so one sender's messages reach every
  member in the order it sent them.
- **Group messages are signed by their sender.** Each leaf carries an ML-DSA-65 key derived from
  its leaf secret, and every application message and hierarchy frame is signed under it.
  - A member delivers a message only when its signer is the sender the server relays, and opens
    each message once (a replay window per epoch, sender and incarnation).
  - The server relays a group message as from the session that sent it, and refuses one from a
    non-member (`GroupMessageRefusal::NotAMember`).
  - A state read back sends under a fresh incarnation, which is part of the message key, so no
    message key is used twice.

- **P2P key exchanges signed by each account's identity key.** Each end signs its stage of a P2P
  key exchange (the initiator its Stage0, the responder its Stage1) with its account's ML-DSA-65
  identity key, over a transcript naming both CIDs, the connection id, the digests of the stages
  as their senders wrote them, and the signer's role (`proto::peer::kex_auth`). The other end
  checks the signature, then the key against the one pinned for the peer. A node gets the keys and
  the pins from the application through the `P2pKexIdentity` port
  (`NodeBuilder::with_p2p_kex_identity`); a node given none signs and checks nothing. A peer seen
  first is pinned; a stage signed by another key is refused (`P2pKexPeerKeyChanged`) and reported
  to the port, and the pair connects once the application pins the presented key; an unsigned
  stage from a pinned peer is refused (`P2pKexSignatureMissing`); a stage that does not verify is
  refused (`P2pKexSignatureInvalid`). A peer with no pin and no signature (an older node, an
  account with no identity key) connects as before. `PeerChannel::peer_kex_identity()` reports
  `Signed { identity_key }` or `Unsigned`. Wire: `PeerSignal::Kex` gains an appended `auth` field,
  ignored by older nodes; gate `P2P_KEX_SIGNED_SINCE` (0.12.4, the shared bump).
  `KernelExecutorArguments` gains `p2p_kex_identity`.
- **P2P path outcomes.** Every background upgrade attempt of a peer connection reports a
  `PathAttemptOutcome`: the attempt number, the plan, the path it attached (`Direct`, `Turn` or
  `ServerRelay`), and every stage (`Coordination`, `Direct`, `Turn`) with its time and, for each
  that did not connect, a typed `StageFailure` (e.g. `NatIncompatible`, `NotConfigured`,
  `PunchFailed`, `AllocationFailed`, `Timeout`), plus the NAT class of both peers (`NatClass`, no
  addresses). Read it from `PeerChannel::path_outcomes()` / `P2pPathCell::last_outcome()`, or from
  the new unsolicited `NodeResult::PeerPathOutcome` event, one per attempt. Measurement only:
  connection establishment is unchanged.
- **Traffic counters by path and class.** Every peer connection counts the bytes it sends and
  receives on each path: `PeerChannel::path_bytes()` / `P2pPathCell::bytes()` return a
  `PathBytesSnapshot` (`direct`, `turn`, `server_relay`, each a `ByteCount { tx, rx }`) covering
  every route the connection has had. Every node counts its traffic by class:
  `NodeRemote::traffic()` returns a `NodeTrafficSnapshot` (`direct`, `turn`, `relayed_p2p`,
  `client_server`, `group_broadcast`). On a server, `relayed_p2p` is the P2P traffic it forwards
  between its clients, told apart from client-server and group-broadcast traffic by each packet's
  header only, never its payload. Counters are monotonic atomics; reading them takes no lock.
  They count Citadel packet bytes (a P2P route's UDP channel datagrams included), not the
  framing QUIC or TURN add around them; client-server UDP is not counted.
- **Path policies** (`citadel_types::proto`, re-exported from both preludes). A `PathPolicy` is a
  server's path precedence: exactly one `PathRule { kind, enabled, attempt_timeout, cost_weight,
  classes }` per `PathKind` (`Direct`, `PeerRelay`, `Turn`, `ServerRelay`), in order, plus the
  `PathClasses` (`Control`, `Msg`, `File`, `Media`) no path may carry. `PathPolicy::new(rules,
  denied)` refuses, with a typed `PathPolicyError`, a policy that misses or repeats a kind, sets an
  attempt timeout outside 1–60 s, leaves the server relay disabled or without `Control`, enables a
  rule after the server relay, leaves a class with no enabled path without denying it, or denies a
  class a path still carries. There is no `Default`. A policy read off the wire is validated again.
  `effective_plan(policy, a, b, PairFeasibility)` narrows a policy to one peer pair from both
  peers' `PathOffer`s (`PathRestrictions`, TURN readiness), NAT feasibility and forwarder
  availability, symmetrically, into an `EffectivePlan`.
- **Servers stamp each peer pair's path plan; both peers execute it.** Each peer key exchange
  carries both peers' `PathOffer`s (a `TurnPolicy::RelayOnly` TURN config refuses Direct and
  PeerRelay; holding any TURN config is TURN readiness), and the server relaying it stamps the
  pair's `EffectivePlan`: its policy narrowed by both offers and by the pair's NAT compatibility.
  Both peers then try the planned paths in policy order, each for its rule's `attempt_timeout`,
  instead of the fixed 30 s per stage; retries and hysteresis are unchanged. A pair with either
  peer, or the server, below `PATH_POLICY_SINCE` gets no plan and plans exactly as before. The
  stamped `forwarder` is always `None` until PeerRelay exists. `PathPlanKind` gains
  `TurnThenDirect`, for a policy that puts TURN first.
- **Class gating.** A connection with a stamped plan carries on each path only the classes the
  plan gives it (`ClassGates`, read with `P2pPathCell::class_gates()` / `permits(class)` and
  `PeerChannel::path_permits(class)`). Refused with `ErrorCode::PathClassDenied` where the current
  path may not carry the class: a message (`PeerChannelSendHalf::send`), a file transfer to the
  peer, and a `MediaEndpoint` (so a policy that keeps media off the server relay refuses the call
  instead of relaying it). Key exchange and signalling always ride the server relay. Without a
  stamped plan every class rides every path, as before.
- **Ephemeral groups and per-group message limits.** `MessageGroupOptions` gains `ephemeral`
  and `limits`, both off by default (groups behave exactly as before). The server of an
  `ephemeral` group relays its broadcasts (messages, member changes) only to members online at
  the time and mails none to an offline member. A group created with
  `limits: Some(GroupMessageLimits::new(max_message_bytes, max_messages_per_second)?)` has each
  message held to them by its server: one whose relayed ciphertext exceeds the size cap, or past
  its sender's rate in a one-second window, reaches nobody, and its sender's group channel
  receives `GroupBroadcast::MessageRefused { key, refusal }` with a typed `GroupMessageRefusal`
  (`TooLarge { bytes, max_bytes }`, `RateLimited { max_per_second }`). A sender below
  `GROUP_RELAY_OPTIONS_SINCE` (0.12.2) gets `MessageResponse { success: false }` instead. A client
  refuses to create a group with either option on a server below that version
  (`ErrorCode::GroupRelayOptionsUnsupported`), which would ignore them. Both options are stored in
  the group registry. The server's mailbox byte map
  is now public as `PEER_MAILBOX_MAP`; it remains unbounded.

### Fixed

- **Groups: a member's sends are paced by the server's answers, so a join is not left waiting
  behind them.**
  - The server handles one session's group broadcasts in the order they arrived, and a
    member's acknowledgement of a Commit comes after every message it sent before it. A joiner's
    Welcome waits for that acknowledgement. Nothing limited how many messages a sender could
    queue ahead of it, so a busy member could keep a joiner waiting longer the faster it sent.
  - Now a session may have at most `GROUP_SEND_WINDOW` (32) group messages written to the server
    and not yet answered. `GroupChannelSendHalf::send_message` waits for a place beyond that, and
    an answer (`MessageResponse` or `MessageRefused`) frees one. A message that is never written
    frees its place at once. When the session ends, a waiting send reports the message
    undelivered (`NotRelayed::SessionEnded`), as before.
  - **Behaviour change.** A session's group sends are limited to 32 per round trip to the server:
    about 320 a second at 100 ms. A burst of more than 32 messages waits about one round trip
    for each further 32. The window is per session, across all of its groups, and places go to
    senders in the order they asked. A sender with many small operations should put several in
    one message.
  - The bound: a member's acknowledgement of a Commit is handled after at most 32 of its own
    group messages, and the relayed Commit reaches the member after at most 32 answers.

- **Account layer** (`citadel_user`):
  - Registering two accounts as peers on the server takes one account lock at a time, so two
    registrations of the same pair in opposite orders always finish; registering an account as
    its own peer is refused with `ErrorCode::PeerRegisterSelf`.
  - Deleting an account removes it from its peers for good: the filesystem and OPFS backends
    re-save each surviving peer (previously the deleted CID came back after a restart) and remove
    the account's `virtual/<cid>` directory; every backend drops the values survivors stored about
    the account (SQL: the `post_cid_delete` trigger, plus `post_cid_delete_bytemap` on MySQL).
  - A password is accepted at login exactly as it was registered: registration and every login,
    legacy and post-quantum, ignore surrounding whitespace through one rule
    (`ProposedCredentials::password_transform`). Previously a password registered with a leading
    or trailing space was always refused.
  - The SQL backend no longer reads a `LOCALHOST_TESTING` environment variable; only the
    `localhost-testing` feature shrinks its pool.
- **Argon2 profile** (`citadel_crypt`, `citadel_user`): the default parameters are the same in
  every build (they were 1 MiB / 1 pass under `debug_assertions`, and stored with each account);
  a node that wants cheaper hashing passes `NodeBuilder::with_server_argon_settings` explicitly.
  A floor (`ARGON_FLOOR_*`, OWASP's 19 MiB / 2 passes / 1 lane; `ArgonSettings::meets_floor`)
  is checked at each legacy login: a stored hash below it is replaced, after it verified, by one
  under the server's settings (`AccountManager::verify_legacy_login`), when those meet the floor.
  `KsfParams::FLOOR` reads the same constants.

### Breaking

- **`GroupChannel::new` is crate-private.** Channels come only from the session that opens them,
  which now hands each one the session's send window.

- **Groups (protocol 0.12.5; older nodes are refused by name).**
  - **Delivery reports.** `MessageResponse { success }` is now `MessageResponse { key, delivery }`.
  - **Leaving is explicit.** Dropping a `GroupChannel` (or its receiving half) no longer leaves
    the group: it closes the channel on this node only, and the member stays in the group, as the
    owner if it was one. A crash, reconnect or dropped handle never hands a group away. Leave with
    `GroupChannel::leave()`. A group whose channel was dropped reaches the kernel as
    `GroupEvent`s; a restore opens a new channel.
  - **Group lifecycle.** `GroupBroadcast::Disconnected` gains `reason: GroupEndReason`; new
    `GroupBroadcast::Restored`. TreeKEM: `Proposal::Update`, `UpdatePath::leaf_sig_public`.
  - **Group configuration.** `NodeBuilder::with_group_mail_limits` (optional, defaulting to
    `GroupMailLimits::default()`). `MessageGroupOptions` gains `retention`.
  - **Message API.**
    - `GroupState::decrypt_message` returns an `OpenedMessage { sender_cid, plaintext }`;
      `GroupCgkaState::decrypt_message` returns `(sender, plaintext)`.
    - `AppCiphertext` gains `signature` and `incarnation`.
    - Signatures add about 3.3 KB to each group message, which counts toward the group's caps.
  - **Wire.**
    - `RestoreMembership`, `RestoreOwnership` and `Welcome` carry `tree`.
    - New `ResumeMembership`, `ResumeOwnership`, `Resumed { key, owner, members }`, `KeepState`,
      `FetchState` and `KeptState`.
    - `InboundGroupMessage` has no `sender`: the server sets it.

- **Sessions default to ML-KEM-1024, and nothing else defaults a KEM.** `KemAlgorithm`,
  `CryptoParameters` and `SessionSecuritySettings` no longer implement `Default`, and
  `ConstructorOpts` takes its `CryptoParameters` rather than an `Option`. The one default is
  `DEFAULT_SESSION_CRYPTO_PARAMS` (AES-256-GCM, `MlKem1024Fips203`, no signature), applied by
  `SessionSecuritySettingsBuilder` and `default_session_security_settings()`, both in the proto and
  SDK preludes. A sum of algorithms builds `CryptoParameters` only once it names a KEM
  (`KemAlgorithm::X + EncryptionAlgorithm::Y`, or `EncryptionAlgorithm::Y + KemAlgorithm::X`);
  `From<EncryptionAlgorithm>` and `From<SigAlgorithm>` are gone, and
  `CryptoParameters::new(encryption, kem, signature)` names all three. Both ends take the suite
  from what the initiator sends. Accounts keep the suite they registered with.
- **The round-3 KEM is removed.** `KemAlgorithm::MlKem` (Kyber768-90s through `kyber-pke`) and
  `KemAlgorithm::is_libcrux` are gone; the KEMs are `MlKem768Fips203` (1) and `MlKem1024Fips203`
  (2). `0` is unassigned: `KemAlgorithm::try_from(0)` and a `CryptoParameters` byte naming it are
  refused with `CryptoParamEnumCastFailed`. `kyber-pke` and `pqc_kyber` are no longer
  dependencies. The TypeScript `KemAlgorithm` lists the two FIPS 203 KEMs.
- **`MlKemHybrid` runs on every KEM.** `EncryptionAlgorithmExt::max_ciphertext_len` takes the
  session's KEM and bounds the real length (plaintext included) by less than one scramble block;
  `plaintext_length` returns `None` for the hybrid scheme, whose body is padded.
  `get_max_packet_size` and `generate_scrambler_metadata` take `CryptoParameters`.
- **RE-VFS runs on every KEM.** `ErrorCode::RemoteRevfsRequiresKyber` is no longer returned.
- **TreeKEM keys every tree on ML-KEM-1024 alone.** A `KeyPackage` is its `leaf`, keyed on
  ML-KEM-1024. `suite_of` and `suite_of_ciphertext` refuse any other KEM by name, and a key
  package, an added leaf or a path key of another KEM is refused before it changes the group.
  `Proposal::Add` carries the inserted `leaf: LeafNode`. `kem_keypair_from_seed`,
  `kem_encapsulate` and `kem_decapsulate` name their suite; `node_keypair_from_path_secret`,
  `hpke_open`, `generate_update_path`, `HierarchyScheme::node_keypair`, `DheEnvelope::seal` and
  `HierarchyMember::seal_message` take none.
- `BackendType` no longer implements `Default`. Use `BackendType::platform_default()`, which
  returns `ErrorCode::BackendHomeDirUnavailable` instead of panicking when there is no usable home
  directory; `NodeBuilder::build` returns that error when no backend is set.
- `NodeResult` has a new variant, `PeerPathOutcome`; an exhaustive `match` on `NodeResult` needs
  an arm for it (a wildcard arm already covers it).
- `PlatformOps::p2p_hole_punch` resolves to an `AttemptReport` instead of `bool`.
- **A server requires a path policy.** `NodeBuilder::with_path_policy(PathPolicy)` is required
  for `NodeType::Server`; `build` fails with `ErrorCode::NodePathPolicyMissing` without it, and with
  `NodePathPolicyNotServer` when a peer sets one. There is no default policy. The server sends its
  policy to each client in connect SUCCESS (clients and servers at `PATH_POLICY_SINCE` = 0.12.2;
  `PATCH_VERSION` is now 2): it arrives as `ConnectSuccess::path_policy` and
  `CitadelClientServerConnection::path_policy` (`None` from an older server). Migration: build each
  server with an explicit policy, for example every `PathKind` in `PathKind::ALL` order, enabled,
  30 s attempts, `PathClasses::ALL`. `ServerOnlySessionInitSettings` gains `path_policy`, and
  `ConnectSuccess` / `CitadelClientServerConnection` gain `path_policy` (struct literals and
  exhaustive patterns need it).
- `MessageGroupOptions` gains `ephemeral: bool` and `limits: Option<GroupMessageLimits>`; a struct
  literal needs both (or `..Default::default()`). `GroupBroadcast` gains `MessageRefused`; an
  exhaustive `match` needs an arm for it.

- **STUN servers are required configuration.** The built-in list of public STUN servers is gone.
  Every node must call `NodeBuilder::with_stun_servers` with at least three distinct `host:port`
  endpoints; `build` fails with `StunServersError::Missing`, `TooFew`, `Duplicate` or `Unparseable`
  otherwise. Previously an absent list silently used third-party servers, and any list of exactly
  three strings was accepted unchecked. Migration: pass the servers your deployment uses, e.g.
  `.with_stun_servers(["stun1.example.com:3478", "stun2.example.com:3478", "stun3.example.com:3478"])`,
  or parse an operator-supplied list with `"a:3478,b:3478,c:3478".parse::<StunServers>()?`.
  - `citadel_wire`: `NatType::identify`, `NatType::identify_timeout` and
    `NatType::get_reflexive_addr` take `&StunServers`; `HolePunchConfigContainer::new` no longer
    takes STUN servers, and `EndpointHolePunchExt::begin_udp_hole_punch` /
    `UdpHolePuncher::new{,_timeout}` take them instead.
  - `citadel_proto`: `KernelExecutorArguments::stun_servers` is a `StunServers`.
  - `citadel_sdk`: `BrowserConnection::new` takes the node's `StunServers`. On WASM the entries are
    handed to the browser's ICE agent as `stun:` URLs.
