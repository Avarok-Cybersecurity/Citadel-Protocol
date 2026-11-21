//! How a node keeps its links. Chosen once, when the node is built, and required (PCND): no
//! builder picks one for the caller.
//!
//! `Legacy` is the behaviour every node had before the RobustConnectionManager. `Managed` turns on
//! what the manager's lanes have landed so far, each behind it until the last lane deletes
//! `Legacy` (§12.4). Both build on every target: the mode is a runtime value, never a `cfg`, so a
//! debug and a release build of one node behave alike.

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use citadel_io::ErrorCode;
use citadel_link::{Clock, LinkPolicy, PolicyError};

/// How this node keeps its links.
#[derive(Clone)]
pub enum LinkManagerMode {
    /// Today's behaviour: a connect runs to its end once requested, its deadlines read the
    /// runtime's own timers, and a P2P pair runs the campaign.
    Legacy,
    /// The RobustConnectionManager: a connect can be aborted by the ticket that started it
    /// (`NodeRequest::AbortLink`), the deadlines of a login read [`ManagedLinks::clock`], and a
    /// P2P pair whose other end is `Managed` too is kept under [`ManagedLinks::policy`].
    Managed(ManagedLinks),
}

impl LinkManagerMode {
    pub fn managed(&self) -> Option<&ManagedLinks> {
        match self {
            LinkManagerMode::Legacy => None,
            LinkManagerMode::Managed(links) => Some(links),
        }
    }
}

impl Debug for LinkManagerMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkManagerMode::Legacy => write!(f, "Legacy"),
            LinkManagerMode::Managed(links) => write!(f, "Managed({links:?})"),
        }
    }
}

/// What a managed node is built with. Every field is required. The policy is shared, not
/// inlined: it is larger than every other mode, and a node clones its mode for each reader.
#[derive(Clone)]
pub struct ManagedLinks {
    clock: Arc<dyn Clock>,
    policy: Arc<LinkPolicy>,
}

/// A managed configuration the node refuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ManagedLinksError {
    /// The policy failed [`LinkPolicy::validate`]; a zero `reattach_grace` is one such policy,
    /// since it would refuse every reattach while claiming to allow them.
    Policy(PolicyError),
}

impl std::fmt::Display for ManagedLinksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedLinksError::Policy(err) => write!(f, "invalid LinkPolicy: {err:?}"),
        }
    }
}

impl std::error::Error for ManagedLinksError {}

impl From<ManagedLinksError> for citadel_io::NetworkError {
    fn from(err: ManagedLinksError) -> Self {
        citadel_io::error!(ErrorCode::LinkPolicyInvalid, err.to_string())
    }
}

impl ManagedLinks {
    /// `clock` is what every managed deadline reads ([`RuntimeClock`](super::RuntimeClock) in a
    /// running node). `policy` bounds every link the manager keeps, including the reattach grace
    /// a server holds a dropped session's seal for (§5.2; the owner chose 5 minutes, Q2).
    pub fn new(clock: Arc<dyn Clock>, policy: LinkPolicy) -> Result<Self, ManagedLinksError> {
        policy.validate().map_err(ManagedLinksError::Policy)?;
        Ok(ManagedLinks {
            clock,
            policy: Arc::new(policy),
        })
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn policy(&self) -> &LinkPolicy {
        &self.policy
    }

    /// The policy's `reattach_grace`: read from the policy, so it has one source.
    pub fn reattach_grace(&self) -> Duration {
        self.policy.reattach_grace
    }
}

impl Debug for ManagedLinks {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedLinks")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::link::test_policy::policy;
    use crate::proto::link::RuntimeClock;

    fn clock() -> Arc<dyn Clock> {
        Arc::new(RuntimeClock::new())
    }

    #[test]
    fn a_zero_reattach_grace_is_refused() {
        let zero = LinkPolicy {
            reattach_grace: Duration::ZERO,
            ..policy()
        };
        assert_eq!(
            ManagedLinks::new(clock(), zero).err(),
            Some(ManagedLinksError::Policy(PolicyError::ZeroWait(
                "reattach_grace"
            )))
        );
        let links = ManagedLinks::new(clock(), policy()).unwrap();
        assert_eq!(links.reattach_grace(), policy().reattach_grace);
        assert_eq!(links.policy(), &policy());
    }

    #[test]
    fn a_managed_node_needs_a_valid_policy() {
        let mut invalid = policy();
        invalid.heal.backoff.first_wait = Duration::ZERO;
        assert!(matches!(
            ManagedLinks::new(clock(), invalid),
            Err(ManagedLinksError::Policy(PolicyError::ZeroWait("heal")))
        ));
        let err = citadel_io::NetworkError::from(ManagedLinks::new(clock(), invalid).unwrap_err());
        assert_eq!(err.code(), ErrorCode::LinkPolicyInvalid);
    }
}
