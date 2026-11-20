# Changelog

## Unreleased

### Added

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
  the group registry, which still reads rows written before them. The server's mailbox byte map
  is now public as `PEER_MAILBOX_MAP`; it remains unbounded.

### Fixed

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

- **Sessions default to ML-KEM-1024, and nothing else defaults a KEM.** `KemAlgorithm`,
  `CryptoParameters` and `SessionSecuritySettings` no longer implement `Default`, and
  `ConstructorOpts` takes its `CryptoParameters` rather than an `Option`. The one default is
  `DEFAULT_SESSION_CRYPTO_PARAMS` (AES-256-GCM, `MlKem1024Fips203`, no signature), applied by
  `SessionSecuritySettingsBuilder` and `default_session_security_settings()`, both in the proto and
  SDK preludes. A sum of algorithms builds `CryptoParameters` only once it names a KEM
  (`KemAlgorithm::X + EncryptionAlgorithm::Y`, or `EncryptionAlgorithm::Y + KemAlgorithm::X`);
  `From<EncryptionAlgorithm>` and `From<SigAlgorithm>` are gone, and
  `CryptoParameters::new(encryption, kem, signature)` names all three. Every node from protocol
  0.10.1 on runs ML-KEM-1024, and both ends take the suite from what the initiator sends, so an
  older node still connects; to reach a node older than 0.10.1, name `KemAlgorithm::MlKem`.
  Accounts keep the suite they registered with. The round-3 suite (`MlKem`) stays for nodes before
  0.12.4 and is to be retired once every supported node is at 0.12.4 or later.
- **`MlKemHybrid` runs on every KEM**, the FIPS 203 suites included; a node before 0.12.4 refuses
  that combination, so name `MlKem` with hybrid encryption to reach one.
- **RE-VFS runs on every KEM.** `ErrorCode::RemoteRevfsRequiresKyber` is no longer returned.
- **TreeKEM keys on ML-KEM-1024 where every member can.** A `KeyPackage` carries an
  ML-KEM-1024 leaf key beside its round-3 one (`current_kem_public`, appended so an earlier owner
  ignores it); an owner inserts it, and re-keys its path on ML-KEM-1024 while every other member's
  leaf is on it, on round 3 while any is not. Hierarchy messages are sealed on the suite
  `GroupState::sealing_suite()` names. `Proposal::Add` carries the inserted `leaf: LeafNode`
  (encoded as before). `kem_keypair_from_seed`, `kem_encapsulate` and `kem_decapsulate` name their
  suite; `HierarchyScheme::node_keypair`, `DheEnvelope::seal` and `HierarchyMember::seal_message`
  take one.
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
