//! Which code keeps a node's links existing (§12.4): the paths of today (`Legacy`: the P2P
//! campaign, the application's redials) or the RobustConnectionManager (`Managed`). Required at
//! node construction, with no default (PCND), so both modes build on every run and every test
//! names the one it exercises; lane L9 deletes `Legacy` and the knob.

use citadel_link::{LinkPolicy, PolicyError};

/// The mode a node runs its links in.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LinkManagerMode {
    /// Today's code paths, unchanged.
    Legacy,
    /// Every link is kept by a `RobustConnectionManager` under the node's `LinkPolicy`.
    Managed,
}

/// The mode with what it needs: a `Managed` node is refused without a valid policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkManagerConfig {
    mode: LinkManagerMode,
    policy: Option<LinkPolicy>,
}

/// Why a link-manager configuration was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkManagerConfigError {
    /// `Managed` needs a `LinkPolicy`.
    MissingPolicy,
    /// A policy was given to a `Legacy` node, which would ignore it.
    UnusedPolicy,
    Policy(PolicyError),
}

impl std::fmt::Display for LinkManagerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPolicy => write!(f, "a Managed link manager needs a LinkPolicy"),
            Self::UnusedPolicy => write!(f, "a Legacy link manager takes no LinkPolicy"),
            Self::Policy(err) => write!(f, "invalid LinkPolicy: {err:?}"),
        }
    }
}

impl std::error::Error for LinkManagerConfigError {}

impl LinkManagerConfig {
    pub fn new(
        mode: LinkManagerMode,
        policy: Option<LinkPolicy>,
    ) -> Result<Self, LinkManagerConfigError> {
        match (mode, policy.as_ref()) {
            (LinkManagerMode::Managed, None) => return Err(LinkManagerConfigError::MissingPolicy),
            (LinkManagerMode::Legacy, Some(_)) => return Err(LinkManagerConfigError::UnusedPolicy),
            (LinkManagerMode::Managed, Some(policy)) => {
                policy.validate().map_err(LinkManagerConfigError::Policy)?
            }
            (LinkManagerMode::Legacy, None) => {}
        }
        Ok(LinkManagerConfig { mode, policy })
    }

    pub fn mode(&self) -> LinkManagerMode {
        self.mode
    }

    /// The policy of a `Managed` node; `None` for `Legacy`.
    pub fn policy(&self) -> Option<&LinkPolicy> {
        self.policy.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_link::{Backoff, FlapPolicy, HealPolicy};
    use std::time::Duration;

    fn policy(first_wait: Duration) -> LinkPolicy {
        let s = Duration::from_secs;
        LinkPolicy {
            heal: HealPolicy {
                backoff: Backoff {
                    first_wait,
                    factor: 2,
                    max_wait: s(60),
                },
                max_attempts: Some(3),
                give_up_after: None,
            },
            reattach_grace: s(60),
            flap: FlapPolicy {
                window: s(60),
                max_transitions: 3,
                hold: s(10),
            },
            direct_rendezvous_budget: s(5),
            rendezvous_deadline: s(10),
            seal_deadline: s(10),
            probe_interval: None,
            settings_deadline: s(10),
            loser_redial_wait: s(1),
            rearm: Backoff {
                first_wait: s(5),
                factor: 2,
                max_wait: s(60),
            },
        }
    }

    #[test]
    fn a_managed_node_needs_a_valid_policy_and_a_legacy_node_takes_none() {
        let valid = policy(Duration::from_secs(1));
        let mode = LinkManagerMode::Managed;
        assert_eq!(
            LinkManagerConfig::new(mode, None),
            Err(LinkManagerConfigError::MissingPolicy)
        );
        assert!(matches!(
            LinkManagerConfig::new(mode, Some(policy(Duration::ZERO))),
            Err(LinkManagerConfigError::Policy(_))
        ));
        let managed = LinkManagerConfig::new(mode, Some(valid)).expect("valid");
        assert_eq!(managed.policy(), Some(&valid));
        assert_eq!(
            LinkManagerConfig::new(LinkManagerMode::Legacy, Some(valid)),
            Err(LinkManagerConfigError::UnusedPolicy)
        );
        let legacy = LinkManagerConfig::new(LinkManagerMode::Legacy, None).expect("valid");
        assert_eq!(legacy.policy(), None);
    }
}
