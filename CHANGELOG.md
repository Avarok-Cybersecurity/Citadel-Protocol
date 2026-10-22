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

### Breaking

- `NodeResult` has a new variant, `PeerPathOutcome`; an exhaustive `match` on `NodeResult` needs
  an arm for it (a wildcard arm already covers it).
- `PlatformOps::p2p_hole_punch` resolves to an `AttemptReport` instead of `bool`.

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
