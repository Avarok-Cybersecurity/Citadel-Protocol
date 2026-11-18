//! A link's timing and heal bounds. Required at `OpenLink`; there are no defaults (PCND): the
//! agent reads them from its config, SDK prefabs take them as a constructor argument. There is
//! no randomness either (owner Q4): both ends run the same policy, the Leader heals first and the
//! Loser waits a fixed [`LinkPolicy::loser_redial_wait`] more.

use std::time::Duration;

/// An exponential wait with no jitter: `first_wait * factor^n`, capped at `max_wait`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Backoff {
    pub first_wait: Duration,
    pub factor: u32,
    pub max_wait: Duration,
}

/// How a lost link heals and when it gives up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HealPolicy {
    /// The wait before each heal attempt after the first (the first is immediate).
    pub backoff: Backoff,
    /// Give up after this many heal attempts; `None` never gives up on a count.
    pub max_attempts: Option<u32>,
    /// Give up once the link has been down this long; `None` never gives up on time.
    pub give_up_after: Option<Duration>,
}

/// Hysteresis for a link that keeps dropping (§9.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlapPolicy {
    /// The window transitions are counted in.
    pub window: Duration,
    /// More Up-to-Degraded transitions than this inside `window` engage the hold.
    pub max_transitions: u32,
    /// How long the link stays degraded before healing again once the hold engages.
    pub hold: Duration,
}

/// Every bound of one link. Each field must be given explicitly: the type has no `Default`.
///
/// ```compile_fail
/// let _ = citadel_link::LinkPolicy::default();
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkPolicy {
    pub heal: HealPolicy,
    /// How long a seal may be reattached after a drop (both ends; owner Q2: 5 minutes).
    pub reattach_grace: Duration,
    pub flap: FlapPolicy,
    /// How long a direct re-rendezvous may take before falling back to the server (§5.3).
    pub direct_rendezvous_budget: Duration,
    /// How long a rendezvous through the server may take.
    pub rendezvous_deadline: Duration,
    /// How long one seal (a handshake or a reattach) may take.
    pub seal_deadline: Duration,
    /// How often a live link is probed; `None` relies on the transport's own keep-alive.
    pub probe_interval: Option<Duration>,
    /// How long a reseal for a settings change may take before the live incarnation is kept.
    pub settings_deadline: Duration,
    /// The Loser's extra wait before it heals, so the Leader's dial arrives first (§5.4).
    pub loser_redial_wait: Duration,
    /// The wait between attempts to move a link off the server relay onto a P2P route.
    pub rearm: Backoff,
}

/// A policy that cannot bound a link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    ZeroWait(&'static str),
    ZeroFactor(&'static str),
    MaxBelowFirst(&'static str),
    ZeroMaxAttempts,
    ZeroFlapWindow,
    ZeroDeadline(&'static str),
}

impl Backoff {
    /// The wait before retry `n` (0-based): `first_wait * factor^n`, capped at `max_wait`.
    pub fn wait(&self, n: u32) -> Duration {
        let first = self.first_wait.as_millis();
        let grown = u128::from(self.factor)
            .checked_pow(n)
            .and_then(|scale| first.checked_mul(scale))
            .unwrap_or(u128::MAX);
        let capped = grown.min(self.max_wait.as_millis());
        Duration::from_millis(u64::try_from(capped).unwrap_or(u64::MAX))
    }

    fn validate(&self, name: &'static str) -> Result<(), PolicyError> {
        if self.first_wait.is_zero() {
            return Err(PolicyError::ZeroWait(name));
        }
        if self.factor == 0 {
            return Err(PolicyError::ZeroFactor(name));
        }
        if self.max_wait < self.first_wait {
            return Err(PolicyError::MaxBelowFirst(name));
        }
        Ok(())
    }
}

fn nonzero(span: Duration, err: PolicyError) -> Result<(), PolicyError> {
    if span.is_zero() {
        Err(err)
    } else {
        Ok(())
    }
}

impl LinkPolicy {
    /// Fails fast on a policy that would let a link wait forever, never wait, or never heal.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.heal.backoff.validate("heal")?;
        self.rearm.validate("rearm")?;
        if self.heal.max_attempts == Some(0) {
            return Err(PolicyError::ZeroMaxAttempts);
        }
        if let Some(after) = self.heal.give_up_after {
            nonzero(after, PolicyError::ZeroDeadline("give_up_after"))?;
        }
        nonzero(self.flap.window, PolicyError::ZeroFlapWindow)?;
        nonzero(self.flap.hold, PolicyError::ZeroWait("flap.hold"))?;
        nonzero(self.reattach_grace, PolicyError::ZeroWait("reattach_grace"))?;
        nonzero(
            self.loser_redial_wait,
            PolicyError::ZeroWait("loser_redial_wait"),
        )?;
        if let Some(every) = self.probe_interval {
            nonzero(every, PolicyError::ZeroWait("probe_interval"))?;
        }
        let deadlines = [
            (self.direct_rendezvous_budget, "direct_rendezvous_budget"),
            (self.rendezvous_deadline, "rendezvous_deadline"),
            (self.seal_deadline, "seal_deadline"),
            (self.settings_deadline, "settings_deadline"),
        ];
        for (span, name) in deadlines {
            nonzero(span, PolicyError::ZeroDeadline(name))?;
        }
        Ok(())
    }

    /// The wait before heal attempt `attempt` (1-based) for a side with `role`: the first is
    /// immediate for the Leader; every later one backs off; the Loser always waits the fixed
    /// `loser_redial_wait` more, so the Leader's dial arrives first (§5.4, owner Q4).
    pub fn heal_wait(&self, attempt: u32, role: crate::Role) -> Duration {
        let backoff = match attempt {
            0 | 1 => Duration::ZERO,
            n => self.heal.backoff.wait(n - 2),
        };
        match role {
            crate::Role::Leader => backoff,
            crate::Role::Loser => backoff.saturating_add(self.loser_redial_wait),
        }
    }
}
