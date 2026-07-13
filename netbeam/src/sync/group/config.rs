//! Explicit configuration for a group lock. Every field is required (no `Default`):
//! lease/timing values are safety-liveness tradeoffs the caller must choose consciously.

use crate::sync::group::error::GroupLockError;
use crate::sync::group::{fnv1a, MemberId};
use std::time::Duration;

/// Configuration shared by every member of one lock group. All members MUST construct
/// an identical config (same members, owner, and durations); a digest of the config
/// travels in every packet and mismatching packets are dropped, so a misconfigured
/// deployment fails fast instead of silently running split semantics.
#[derive(Clone, Debug)]
pub struct GroupLockConfig {
    members: Vec<MemberId>,
    local_id: MemberId,
    initial_value_owner: MemberId,
    lease_duration: Duration,
    renew_interval: Duration,
    steal_grace: Duration,
    acquire_timeout: Duration,
    round_timeout: Duration,
    cas_backoff_base: Duration,
    waiter_poll_interval: Duration,
    digest: u64,
}

impl GroupLockConfig {
    /// All parameters are mandatory.
    ///
    /// - `members`: full static membership (deduplicated, order-insensitive), `n >= 2`.
    /// - `local_id`: this process's member id; must be in `members`.
    /// - `initial_value_owner`: the member that supplies the initial value; must be in `members`.
    /// - `lease_duration`: how long a grant stays valid without a successful renew.
    /// - `renew_interval`: cadence of holder renews; must be `< lease_duration / 2`.
    /// - `steal_grace`: extra margin observers wait beyond `lease_duration` before
    ///   stealing a stagnant holder (absorbs clock-rate skew + renew-round latency).
    /// - `acquire_timeout`: default bound for `lock()`/`read()`/`write()`.
    /// - `round_timeout`: how long one consensus round waits for a majority of replies.
    /// - `cas_backoff_base`: base delay (±50% jitter) between dueling-proposer retries.
    /// - `waiter_poll_interval`: waiter re-poll cadence (nudge-loss backstop and
    ///   waiter heartbeat via queue-entry refresh).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        members: Vec<MemberId>,
        local_id: MemberId,
        initial_value_owner: MemberId,
        lease_duration: Duration,
        renew_interval: Duration,
        steal_grace: Duration,
        acquire_timeout: Duration,
        round_timeout: Duration,
        cas_backoff_base: Duration,
        waiter_poll_interval: Duration,
    ) -> Result<Self, GroupLockError> {
        let mut members = members;
        members.sort_unstable();
        let pre_dedup = members.len();
        members.dedup();
        if members.len() != pre_dedup {
            return Err(GroupLockError::InvalidConfig(
                "duplicate member ids".to_string(),
            ));
        }
        if members.len() < 2 {
            return Err(GroupLockError::InvalidConfig(
                "a lock group requires at least 2 members".to_string(),
            ));
        }
        if !members.contains(&local_id) {
            return Err(GroupLockError::InvalidConfig(
                "local_id is not in the member set".to_string(),
            ));
        }
        if !members.contains(&initial_value_owner) {
            return Err(GroupLockError::InvalidConfig(
                "initial_value_owner is not in the member set".to_string(),
            ));
        }
        for (name, d) in [
            ("lease_duration", lease_duration),
            ("renew_interval", renew_interval),
            ("acquire_timeout", acquire_timeout),
            ("round_timeout", round_timeout),
            ("cas_backoff_base", cas_backoff_base),
            ("waiter_poll_interval", waiter_poll_interval),
        ] {
            if d.is_zero() {
                return Err(GroupLockError::InvalidConfig(format!(
                    "{name} must be non-zero"
                )));
            }
        }
        if renew_interval * 2 >= lease_duration {
            return Err(GroupLockError::InvalidConfig(
                "renew_interval must be < lease_duration / 2".to_string(),
            ));
        }

        let digest = Self::compute_digest(
            &members,
            initial_value_owner,
            &[
                lease_duration,
                renew_interval,
                steal_grace,
                round_timeout,
                waiter_poll_interval,
            ],
        );

        Ok(Self {
            members,
            local_id,
            initial_value_owner,
            lease_duration,
            renew_interval,
            steal_grace,
            acquire_timeout,
            round_timeout,
            cas_backoff_base,
            waiter_poll_interval,
            digest,
        })
    }

    /// Digest over the fields that must agree across members. Locally-scoped knobs
    /// (`local_id`, `acquire_timeout`, `cas_backoff_base`) are deliberately excluded.
    fn compute_digest(members: &[MemberId], owner: MemberId, durations: &[Duration]) -> u64 {
        let mut bytes = Vec::with_capacity(members.len() * 8 + durations.len() * 16 + 8);
        for m in members {
            bytes.extend_from_slice(&m.0.to_le_bytes());
        }
        bytes.extend_from_slice(&owner.0.to_le_bytes());
        for d in durations {
            bytes.extend_from_slice(&d.as_nanos().to_le_bytes());
        }
        fnv1a(&bytes)
    }

    pub fn members(&self) -> &[MemberId] {
        &self.members
    }

    pub fn local_id(&self) -> MemberId {
        self.local_id
    }

    pub fn initial_value_owner(&self) -> MemberId {
        self.initial_value_owner
    }

    /// Majority threshold: `floor(n/2) + 1` of the configured membership.
    pub fn majority(&self) -> usize {
        self.members.len() / 2 + 1
    }

    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    pub fn renew_interval(&self) -> Duration {
        self.renew_interval
    }

    pub fn steal_grace(&self) -> Duration {
        self.steal_grace
    }

    pub fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }

    pub fn round_timeout(&self) -> Duration {
        self.round_timeout
    }

    pub fn cas_backoff_base(&self) -> Duration {
        self.cas_backoff_base
    }

    pub fn waiter_poll_interval(&self) -> Duration {
        self.waiter_poll_interval
    }

    pub fn digest(&self) -> u64 {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(members: Vec<u64>, local: u64, owner: u64) -> Result<GroupLockConfig, GroupLockError> {
        GroupLockConfig::new(
            members.into_iter().map(MemberId).collect(),
            MemberId(local),
            MemberId(owner),
            Duration::from_millis(1000),
            Duration::from_millis(200),
            Duration::from_millis(300),
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_millis(50),
            Duration::from_millis(250),
        )
    }

    #[test]
    fn validation() {
        assert!(cfg(vec![1, 2, 3], 1, 2).is_ok());
        assert!(cfg(vec![1], 1, 1).is_err());
        assert!(cfg(vec![1, 1, 2], 1, 2).is_err());
        assert!(cfg(vec![1, 2], 3, 1).is_err());
        assert!(cfg(vec![1, 2], 1, 3).is_err());
    }

    #[test]
    fn digest_ignores_local_knobs_but_not_membership() {
        let a = cfg(vec![1, 2, 3], 1, 2).unwrap();
        let b = cfg(vec![1, 2, 3], 3, 2).unwrap();
        let c = cfg(vec![1, 2, 4], 1, 2).unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn majority_math() {
        assert_eq!(cfg(vec![1, 2], 1, 1).unwrap().majority(), 2);
        assert_eq!(cfg(vec![1, 2, 3], 1, 1).unwrap().majority(), 2);
        assert_eq!(cfg(vec![1, 2, 3, 4], 1, 1).unwrap().majority(), 3);
        assert_eq!(cfg(vec![1, 2, 3, 4, 5], 1, 1).unwrap().majority(), 3);
    }
}
