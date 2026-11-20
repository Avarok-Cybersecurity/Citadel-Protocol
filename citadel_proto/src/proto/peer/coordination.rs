//! What both ends of a coordination endpoint (the C2S hole-punch endpoint and a P2P connection's
//! campaign endpoint) agree on: the netbeam wire they speak, and the topic of each operation that
//! one side may run while the other has moved on.

use netbeam::sync::wire::{Topic, WireRevision};

/// The wire both ends of every coordination endpoint speak. Every node this node takes part with
/// speaks it (`version_gate`).
pub(crate) const COORDINATION_WIRE: WireRevision = WireRevision::Exchanged;

/// The readiness sync after a punch succeeded locally, which the peer makes only if its own
/// punch did.
#[cfg(not(target_family = "wasm"))]
pub(crate) const DIRECT_READY: Topic = Topic::new(0x5032_0001);
/// The relayed stage's signalling stream.
#[cfg(not(target_family = "wasm"))]
pub(crate) const TURN_SIGNALLING: Topic = Topic::new(0x5032_0002);
/// The rendezvous before a retry.
pub(crate) const RETRY_RENDEZVOUS: Topic = Topic::new(0x5032_0003);
/// Waiting, parked, for either side to re-arm the campaign.
pub(crate) const PARKED: Topic = Topic::new(0x5032_0004);
/// Waiting, on a direct route, for either side to lose it.
pub(crate) const PATH_LOST: Topic = Topic::new(0x5032_0005);
