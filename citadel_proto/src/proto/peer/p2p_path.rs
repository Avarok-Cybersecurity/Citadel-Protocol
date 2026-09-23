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

impl P2pPath {
    fn to_u8(self) -> u8 {
        match self {
            P2pPath::Direct => 0,
            P2pPath::Turn => 1,
            P2pPath::ServerRelay => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => P2pPath::Direct,
            1 => P2pPath::Turn,
            _ => P2pPath::ServerRelay,
        }
    }
}

/// Shared, live view of a virtual connection's [`P2pPath`], read by the application's channel and
/// written when a P2P connection is (or is not) established.
#[derive(Clone, Debug)]
pub struct P2pPathCell(Arc<AtomicU8>);

impl P2pPathCell {
    /// Every virtual connection starts server-relayed: the channel exists before any P2P attempt.
    pub(crate) fn server_relayed() -> Self {
        Self(Arc::new(AtomicU8::new(P2pPath::ServerRelay.to_u8())))
    }

    pub fn get(&self) -> P2pPath {
        P2pPath::from_u8(self.0.load(Ordering::Acquire))
    }

    pub(crate) fn set(&self, path: P2pPath) {
        self.0.store(path.to_u8(), Ordering::Release);
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
        assert_eq!(view.get(), P2pPath::ServerRelay);
        for p in [P2pPath::Direct, P2pPath::Turn, P2pPath::ServerRelay] {
            cell.set(p);
            assert_eq!(view.get(), p);
        }
    }
}
