//! The path half of a peer key exchange: each peer's offer, and the plan the server stamps.
//!
//! Each Kex stage carries a [`KexPath`]. Stage0 (Alice) carries Alice's [`PathOffer`]. Stage1
//! (Bob) carries Alice's offer, echoed, and Bob's. Stage2 (Alice) carries Alice's offer and Bob's,
//! echoed. The server relaying Stage1 and Stage2, holding both offers, stamps the pair's
//! [`EffectivePlan`] into each from the same inputs: its policy, both offers, and the pair's NAT
//! feasibility. So Alice (reading Stage1) and Bob (reading Stage2) execute the same plan.
//!
//! An older peer sends no `KexPath`, and an older server drops it while relaying. Then no plan is
//! stamped, or none survives, and both peers plan alone as before (`p2p_plan::plan_p2p`).
//! Pure: no I/O.

use citadel_types::proto::{
    effective_plan, EffectivePlan, PairFeasibility, PathKind, PathOffer, PathPolicy,
    PathRestrictions,
};
use citadel_wire::udp_traversal::turn_relay::{TurnPolicy, TurnRelayConfig};
use serde::{Deserialize, Serialize};

use crate::constants::{protocol_version_at_least, PATH_POLICY_SINCE};

/// The path half of one Kex stage.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct KexPath {
    /// The offer of the peer that sent Stage0.
    pub initiator: Option<PathOffer>,
    /// The offer of the peer that answered with Stage1.
    pub responder: Option<PathOffer>,
    /// The pair's plan, as the server stamped it. A peer never sets it; the server overwrites it.
    pub plan: Option<EffectivePlan>,
}

/// This peer's offer for an attempt, from the TURN config the application supplied for it. A
/// `RelayOnly` config refuses the paths that reveal this peer's address to the other: Direct,
/// and PeerRelay (whose forwarder learns both).
pub(crate) fn local_offer(turn: Option<&TurnRelayConfig>) -> PathOffer {
    let restrictions = match turn {
        Some(cfg) if cfg.policy == TurnPolicy::RelayOnly => {
            PathRestrictions::denying(&[PathKind::Direct, PathKind::PeerRelay])
                .expect("the server relay is not refused")
        }
        _ => PathRestrictions::NONE,
    };
    PathOffer {
        restrictions,
        turn_ready: turn.is_some(),
    }
}

/// Server: the path half to relay. When the stage carries both offers and the server has a
/// policy, the pair's plan is stamped from them and `pair` (the pair's feasibility, `None` when
/// it cannot be told, e.g. the target's session is gone); otherwise any plan is cleared, so a
/// peer can never forge one.
pub(crate) fn stamp(
    policy: Option<&PathPolicy>,
    path: Option<KexPath>,
    pair: impl FnOnce() -> Option<PairFeasibility>,
) -> Option<KexPath> {
    let mut path = path?;
    path.plan = match (policy, path.initiator, path.responder) {
        (Some(policy), Some(a), Some(b)) => pair().map(|pair| effective_plan(policy, &a, &b, pair)),
        _ => None,
    };
    Some(path)
}

/// Peer: the plan to execute from a received stage, if the server stamped one and the peer that
/// built the stage takes part in path policies.
pub(crate) fn stamped_plan(
    path: Option<&KexPath>,
    sender_version: Option<u32>,
) -> Option<EffectivePlan> {
    if !protocol_version_at_least(sender_version, PATH_POLICY_SINCE) {
        return None;
    }
    path?.plan.clone()
}

#[cfg(test)]
#[path = "kex_path_tests.rs"]
mod tests;
