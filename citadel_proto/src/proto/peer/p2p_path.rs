//! Which network path a P2P connection runs over, and the per-attempt decision of which paths to
//! try.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use citadel_wire::udp_traversal::turn_relay::{TurnPolicy, TurnRelayConfig};

/// The path carrying a P2P connection's traffic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum P2pPath {
    /// A direct (hole-punched) QUIC connection between the peers.
    Direct,
    /// A QUIC connection through a TURN relay: the reliable channel and the UDP channel both
    /// cross the relay, never the Citadel server.
    Turn,
    /// No P2P connection: the reliable channel is relayed through the Citadel server and no UDP
    /// channel exists.
    ServerRelay,
}

/// How an established P2P connection is carried; recorded into a [`P2pPathCell`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum P2pRoute {
    Direct,
    /// `relayed_both`: each peer sends through its own allocation (relay-to-relay), so every
    /// packet egresses two TURN servers.
    Turn {
        relayed_both: bool,
    },
}

const DIRECT: u8 = 0;
const TURN_ONE_ALLOCATION: u8 = 1;
const SERVER_RELAY: u8 = 2;
const TURN_BOTH_ALLOCATIONS: u8 = 3;

/// Shared, live view of a virtual connection's [`P2pPath`], read by the application's channel and
/// written when a P2P connection is (or is not) established.
#[derive(Clone, Debug)]
pub struct P2pPathCell(Arc<AtomicU8>);

impl P2pPathCell {
    /// Every virtual connection starts server-relayed: the channel exists before any P2P attempt.
    pub(crate) fn server_relayed() -> Self {
        Self(Arc::new(AtomicU8::new(SERVER_RELAY)))
    }

    pub fn get(&self) -> P2pPath {
        match self.0.load(Ordering::Acquire) {
            DIRECT => P2pPath::Direct,
            TURN_ONE_ALLOCATION | TURN_BOTH_ALLOCATIONS => P2pPath::Turn,
            _ => P2pPath::ServerRelay,
        }
    }

    /// True when the path is [`P2pPath::Turn`] through two allocations (both peers relayed), for
    /// accounting double TURN egress.
    pub fn relayed_both(&self) -> bool {
        self.0.load(Ordering::Acquire) == TURN_BOTH_ALLOCATIONS
    }

    pub(crate) fn set(&self, route: P2pRoute) {
        let v = match route {
            P2pRoute::Direct => DIRECT,
            P2pRoute::Turn {
                relayed_both: false,
            } => TURN_ONE_ALLOCATION,
            P2pRoute::Turn { relayed_both: true } => TURN_BOTH_ALLOCATIONS,
        };
        self.0.store(v, Ordering::Release);
    }
}

/// What to try for one P2P attempt, decided identically on both peers from their own TURN config
/// and the (symmetric) NAT-compatibility verdict.
#[derive(Clone, Debug)]
pub(crate) enum P2pPlan {
    /// Hole punch; nothing to fall back to.
    DirectOnly,
    /// Hole punch; on failure, relay through TURN.
    DirectThenRelay(TurnRelayConfig),
    /// Skip the hole punch and relay through TURN.
    RelayOnly(TurnRelayConfig),
    /// No P2P attempt: the NATs are incompatible and no TURN config was supplied.
    ServerOnly,
}

pub(crate) fn plan_p2p(direct_impossible: bool, turn: Option<TurnRelayConfig>) -> P2pPlan {
    match turn {
        None if direct_impossible => P2pPlan::ServerOnly,
        None => P2pPlan::DirectOnly,
        Some(cfg) if direct_impossible || cfg.policy == TurnPolicy::RelayOnly => {
            P2pPlan::RelayOnly(cfg)
        }
        Some(cfg) => P2pPlan::DirectThenRelay(cfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(policy: TurnPolicy) -> TurnRelayConfig {
        TurnRelayConfig::new(vec![], policy)
    }

    #[test]
    fn plans_follow_policy_and_nat_verdict() {
        assert!(matches!(plan_p2p(false, None), P2pPlan::DirectOnly));
        assert!(matches!(plan_p2p(true, None), P2pPlan::ServerOnly));
        assert!(matches!(
            plan_p2p(false, Some(cfg(TurnPolicy::Fallback))),
            P2pPlan::DirectThenRelay(_)
        ));
        assert!(matches!(
            plan_p2p(true, Some(cfg(TurnPolicy::Fallback))),
            P2pPlan::RelayOnly(_)
        ));
        assert!(matches!(
            plan_p2p(false, Some(cfg(TurnPolicy::RelayOnly))),
            P2pPlan::RelayOnly(_)
        ));
    }

    #[test]
    fn path_cell_round_trips() {
        let cell = P2pPathCell::server_relayed();
        let view = cell.clone();
        assert_eq!(
            (view.get(), view.relayed_both()),
            (P2pPath::ServerRelay, false)
        );
        for (route, path, both) in [
            (P2pRoute::Direct, P2pPath::Direct, false),
            (
                P2pRoute::Turn {
                    relayed_both: false,
                },
                P2pPath::Turn,
                false,
            ),
            (P2pRoute::Turn { relayed_both: true }, P2pPath::Turn, true),
        ] {
            cell.set(route);
            assert_eq!((view.get(), view.relayed_both()), (path, both));
        }
    }
}
