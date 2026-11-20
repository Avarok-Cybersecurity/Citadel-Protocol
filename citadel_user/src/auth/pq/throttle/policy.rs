//! The throttle's limits, and what an attempt is and costs.

use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// How much wider the username-only key's limits are than a (username, network) key's.
pub const PER_USER_FACTOR: u32 = 3;
/// What one recovery attempt counts for, against a sign-in's one.
pub const RECOVERY_COST: u32 = 2;

/// The server's limits. Every field is required: there is no default policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThrottlePolicy {
    /// Failed proofs a (username, network) key may make in one window before it is locked out.
    pub max_failures: u32,
    /// Attempts a (username, network) key may start in one window, failed or not.
    pub max_starts_per_window: u32,
    pub window_ms: u64,
    /// The first lockout's length; each further lockout of the same key doubles it.
    pub lockout_base_ms: u64,
    pub lockout_max_ms: u64,
    /// How many keys the server tracks at once. Past it, idle keys are forgotten first, then the
    /// least recently seen unlocked one; a locked key is never forgotten early.
    pub max_tracked_keys: usize,
}

impl ThrottlePolicy {
    /// Five failures or twenty starts per fifteen minutes; a lockout of one minute, doubling to
    /// an hour; a hundred thousand tracked keys.
    pub const RECOMMENDED: Self = Self {
        max_failures: 5,
        max_starts_per_window: 20,
        window_ms: 15 * 60 * 1000,
        lockout_base_ms: 60 * 1000,
        lockout_max_ms: 60 * 60 * 1000,
        max_tracked_keys: 100_000,
    };

    pub fn validate(&self) -> Result<(), AccountError> {
        let invalid = |reason: &'static str| error!(ErrorCode::SignInThrottlePolicyInvalid, reason);
        if self.max_failures == 0 || self.max_starts_per_window == 0 {
            return Err(invalid("a limit of zero admits nothing"));
        }
        if self.window_ms == 0 || self.lockout_base_ms == 0 {
            return Err(invalid("a window or lockout of zero locks nothing"));
        }
        if self.lockout_max_ms < self.lockout_base_ms {
            return Err(invalid("the longest lockout is shorter than the first"));
        }
        if self.max_tracked_keys < 2 {
            return Err(invalid("an attempt needs two keys tracked"));
        }
        Ok(())
    }
}

/// What is being attempted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// A sign-in, or a step-up inside a session.
    SignIn,
    /// A recovery with the phrase or a code.
    Recovery,
}

impl Attempt {
    pub(super) fn cost(self) -> u32 {
        match self {
            Self::SignIn => 1,
            Self::Recovery => RECOVERY_COST,
        }
    }
}

/// Whether an attempt may go ahead.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Admit,
    /// Locked out, or over the start limit. Answer as for a failed proof.
    Refuse,
}
