//! The plan one pair of peers executes: the server's [`PathPolicy`] narrowed by both peers'
//! [`PathRestrictions`] and by what is feasible for the pair.
//!
//! The server computes it with [`effective_plan`] at the pair's key exchange and stamps it into
//! the exchange, so both peers execute the same plan. The function is symmetric in the two
//! peers' offers: either peer may be the one that started the exchange.
use super::path_policy::{PathClasses, PathKind, PathPolicy, PathPolicyError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Paths a peer refuses to use, whatever the server allows: for example Direct and PeerRelay
/// for a user who never wants a peer to learn their IP address.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathRestrictions(u8);

impl PathRestrictions {
    /// Refuses nothing: the peer uses every path the server's policy allows.
    pub const NONE: PathRestrictions = PathRestrictions(0);

    /// Refuses every path in `kinds`. The server relay cannot be refused: every connection starts
    /// on it and key exchange rides it.
    pub fn denying(kinds: &[PathKind]) -> Result<Self, PathPolicyError> {
        let mut bits = 0;
        for kind in kinds {
            if *kind == PathKind::ServerRelay {
                return Err(PathPolicyError::ServerRelayMustCarryControl);
            }
            bits |= kind.bit();
        }
        Ok(Self(bits))
    }

    pub fn denies(self, kind: PathKind) -> bool {
        kind != PathKind::ServerRelay && self.0 & kind.bit() != 0
    }
}

/// What one peer brings to its key exchange: what it refuses, and whether it holds a TURN
/// relay configuration for this attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathOffer {
    pub restrictions: PathRestrictions,
    pub turn_ready: bool,
}

/// One path of an [`EffectivePlan`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedPath {
    pub kind: PathKind,
    /// How long one attempt at this path may take.
    pub attempt_timeout: Duration,
    /// Which classes of traffic may ride it.
    pub classes: PathClasses,
}

/// The paths one pair of peers may use, in the order their campaign tries them. Always ends with
/// [`PathKind::ServerRelay`], which needs no attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePlan {
    pub paths: Vec<PlannedPath>,
    /// The member forwarding this pair's traffic on [`PathKind::PeerRelay`]. Always `None`
    /// until peer relaying exists.
    pub forwarder: Option<u64>,
}

impl EffectivePlan {
    /// The paths to attempt, in order: every planned path before the server relay.
    pub fn upgrades(&self) -> impl Iterator<Item = &PlannedPath> {
        self.paths
            .iter()
            .take_while(|p| p.kind != PathKind::ServerRelay)
    }

    /// The classes `kind` may carry for this pair; none when the plan does not include it.
    pub fn classes_on(&self, kind: PathKind) -> PathClasses {
        self.paths
            .iter()
            .find(|p| p.kind == kind)
            .map(|p| p.classes)
            .unwrap_or(PathClasses::NONE)
    }
}

/// What the server knows about a pair beyond their offers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PairFeasibility {
    /// Whether the two peers' NATs admit a hole punch.
    pub direct: bool,
    /// The member that would forward for the pair, if any.
    pub forwarder: Option<u64>,
}

/// The plan for a pair: each enabled rule of `policy`, in order up to and including the server
/// relay, kept only when neither peer refuses it and the pair can use it. Direct needs NATs that
/// admit a hole punch; PeerRelay needs a forwarder; Turn needs both peers to hold a TURN config.
pub fn effective_plan(
    policy: &PathPolicy,
    a: &PathOffer,
    b: &PathOffer,
    pair: PairFeasibility,
) -> EffectivePlan {
    let feasible = |kind: PathKind| match kind {
        PathKind::Direct => pair.direct,
        PathKind::PeerRelay => pair.forwarder.is_some(),
        PathKind::Turn => a.turn_ready && b.turn_ready,
        PathKind::ServerRelay => true,
    };
    let mut paths = Vec::with_capacity(policy.rules().len());
    for rule in policy.rules().iter().filter(|r| r.enabled) {
        let refused = a.restrictions.denies(rule.kind) || b.restrictions.denies(rule.kind);
        if !refused && feasible(rule.kind) {
            paths.push(PlannedPath {
                kind: rule.kind,
                attempt_timeout: rule.attempt_timeout,
                classes: rule.classes,
            });
        }
        if rule.kind == PathKind::ServerRelay {
            break;
        }
    }
    let forwarder = pair
        .forwarder
        .filter(|_| paths.iter().any(|p| p.kind == PathKind::PeerRelay));
    EffectivePlan { paths, forwarder }
}
