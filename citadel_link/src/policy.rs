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

/// Every bound of one link. Each field must be given explicitly.
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
