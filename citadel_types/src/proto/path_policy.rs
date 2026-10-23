//! Which network paths a server lets its peers use, in which order, and for which traffic.
//!
//! A [`PathPolicy`] is the server operator's precedence: an ordered list with exactly one
//! [`PathRule`] per [`PathKind`]. Each rule says whether the path may be used, how long one
//! attempt at it may take, and which [`PathClass`]es of traffic may ride it. The server sends its
//! policy to each client at connect, and at each peer key exchange stamps the pair's
//! [`EffectivePlan`](super::EffectivePlan): the policy narrowed by both peers' restrictions and by
//! what is feasible for that pair.
//!
//! There is no default policy. [`PathPolicy::new`] validates every rule and refuses a policy that
//! leaves a class of traffic with nowhere to go unless the policy denies that class outright.
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use super::path_policy_error::PathPolicyError;

/// A network path a peer connection can take.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathKind {
    /// A hole-punched QUIC connection between the peers.
    Direct,
    /// The peers' own end-to-end QUIC connection forwarded by a third member that holds direct
    /// paths to both. Not yet executed: no forwarder is ever planned.
    PeerRelay,
    /// A QUIC connection through a TURN relay.
    Turn,
    /// The Citadel server's packet relay. Always available: every connection starts on it, and
    /// key exchange and signalling ride it.
    ServerRelay,
}

impl PathKind {
    pub const ALL: [PathKind; 4] = [
        PathKind::Direct,
        PathKind::PeerRelay,
        PathKind::Turn,
        PathKind::ServerRelay,
    ];

    pub(crate) const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A class of traffic, for deciding which paths may carry it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathClass {
    /// Key exchange, path signalling and other protocol control traffic.
    Control,
    /// Application messages on the peer channel.
    Msg,
    /// File and object transfers.
    File,
    /// Real-time media.
    Media,
}

impl PathClass {
    pub const ALL: [PathClass; 4] = [
        PathClass::Control,
        PathClass::Msg,
        PathClass::File,
        PathClass::Media,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A set of [`PathClass`]es.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathClasses(u8);

impl PathClasses {
    pub const NONE: PathClasses = PathClasses(0);
    pub const ALL: PathClasses = PathClasses::of(&PathClass::ALL);

    /// The set holding exactly `classes`.
    pub const fn of(classes: &[PathClass]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < classes.len() {
            bits |= classes[i].bit();
            i += 1;
        }
        PathClasses(bits)
    }

    pub const fn contains(self, class: PathClass) -> bool {
        self.0 & class.bit() != 0
    }

    pub const fn union(self, other: PathClasses) -> Self {
        PathClasses((self.0 | other.0) & PathClasses::ALL.0)
    }

    pub const fn intersection(self, other: PathClasses) -> Self {
        PathClasses(self.0 & other.0 & PathClasses::ALL.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 & PathClasses::ALL.0 == 0
    }

    /// The classes in this set, in [`PathClass::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = PathClass> {
        PathClass::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }
}

/// One path's entry in a [`PathPolicy`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    pub kind: PathKind,
    /// Whether peers may use this path at all.
    pub enabled: bool,
    /// How long one attempt at this path may take before the campaign moves to the next rule.
    /// Within [`MIN_ATTEMPT_TIMEOUT`]..=[`MAX_ATTEMPT_TIMEOUT`].
    pub attempt_timeout: Duration,
    /// The operator's relative cost of carrying a byte on this path, for planners and reports.
    pub cost_weight: u32,
    /// Which classes of traffic may ride this path.
    pub classes: PathClasses,
}

/// The shortest attempt timeout a rule may set.
pub const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// The longest attempt timeout a rule may set.
pub const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// A server's validated path precedence. Order is precedence: the campaign tries the enabled
/// rules before the server relay in this order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPathPolicy")]
pub struct PathPolicy {
    rules: Vec<PathRule>,
    denied: PathClasses,
}

/// A policy as read off the wire, before [`PathPolicy::new`] checks it.
#[derive(Deserialize)]
struct UncheckedPathPolicy {
    rules: Vec<PathRule>,
    denied: PathClasses,
}

impl TryFrom<UncheckedPathPolicy> for PathPolicy {
    type Error = PathPolicyError;

    fn try_from(value: UncheckedPathPolicy) -> Result<Self, Self::Error> {
        PathPolicy::new(value.rules, value.denied)
    }
}

impl PathPolicy {
    /// Validates `rules` (in precedence order) and `denied`, the classes no path may carry.
    pub fn new(rules: Vec<PathRule>, denied: PathClasses) -> Result<Self, PathPolicyError> {
        for kind in PathKind::ALL {
            match rules.iter().filter(|r| r.kind == kind).count() {
                0 => return Err(PathPolicyError::MissingKind(kind)),
                1 => {}
                _ => return Err(PathPolicyError::DuplicateKind(kind)),
            }
        }
        for rule in &rules {
            if !(MIN_ATTEMPT_TIMEOUT..=MAX_ATTEMPT_TIMEOUT).contains(&rule.attempt_timeout) {
                return Err(PathPolicyError::TimeoutOutOfRange {
                    kind: rule.kind,
                    timeout: rule.attempt_timeout,
                });
            }
        }
        let relay_at = rules
            .iter()
            .position(|r| r.kind == PathKind::ServerRelay)
            .expect("checked above");
        let relay = &rules[relay_at];
        if !relay.enabled || !relay.classes.contains(PathClass::Control) {
            return Err(PathPolicyError::ServerRelayMustCarryControl);
        }
        if let Some(late) = rules[relay_at + 1..].iter().find(|r| r.enabled) {
            return Err(PathPolicyError::UnreachableAfterServerRelay(late.kind));
        }
        let enabled = || rules.iter().filter(|r| r.enabled);
        for class in PathClass::ALL {
            let carrier = enabled().find(|r| r.classes.contains(class));
            match (denied.contains(class), carrier) {
                (true, Some(rule)) => {
                    return Err(PathPolicyError::DeniedClassAllowed {
                        class,
                        kind: rule.kind,
                    })
                }
                (false, None) => return Err(PathPolicyError::ClassUncovered(class)),
                _ => {}
            }
        }
        Ok(Self { rules, denied })
    }

    /// Every rule, in precedence order.
    pub fn rules(&self) -> &[PathRule] {
        &self.rules
    }

    /// The classes no path may carry.
    pub fn denied(&self) -> PathClasses {
        self.denied
    }

    /// The rule for `kind`. A valid policy has exactly one.
    pub fn rule(&self, kind: PathKind) -> &PathRule {
        self.rules
            .iter()
            .find(|r| r.kind == kind)
            .expect("a validated policy has a rule for every kind")
    }
}
