//! What both ends of a coordination endpoint (the C2S hole-punch endpoint and a P2P connection's
//! campaign endpoint) agree on: the netbeam wire they speak, and the topic of each operation that
//! one side may run while the other has moved on.

use crate::constants::{protocol_version_at_least, EXCHANGED_SUBSCRIPTIONS_SINCE};
use netbeam::sync::wire::{Topic, WireRevision};

/// The wire to speak with a node of `adjacent_version`. Each end computes it from the other's
/// version, so the two agree exactly when both are at or above the revision, or either is not.
pub(crate) fn coordination_wire(adjacent_version: Option<u32>) -> WireRevision {
    if protocol_version_at_least(adjacent_version, EXCHANGED_SUBSCRIPTIONS_SINCE) {
        WireRevision::Exchanged
    } else {
        WireRevision::CountPaired
    }
}

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

#[cfg(test)]
mod tests {
    use super::coordination_wire;
    use crate::constants::PROTOCOL_VERSION;
    use embedded_semver::prelude::*;
    use netbeam::sync::wire::WireRevision;

    fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
        Some(Semver::new(major, minor, patch).to_u32().unwrap())
    }

    #[test]
    fn two_current_nodes_exchange_ids() {
        assert_eq!(
            coordination_wire(Some(*PROTOCOL_VERSION)),
            WireRevision::Exchanged
        );
    }

    #[test]
    fn an_older_or_unknown_node_gets_the_count_paired_wire() {
        assert_eq!(
            coordination_wire(version(0, 12, 2)),
            WireRevision::CountPaired
        );
        assert_eq!(coordination_wire(None), WireRevision::CountPaired);
    }
}
