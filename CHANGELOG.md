# Changelog

## Unreleased

### Breaking

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
