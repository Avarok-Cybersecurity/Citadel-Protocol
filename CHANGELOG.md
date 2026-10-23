# Changelog

## Unreleased

### Added

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

### Breaking

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
