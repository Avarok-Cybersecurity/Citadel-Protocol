//! How long a hole punch may take, and how that time is split between its attempts.

use crate::udp_traversal::udp_hole_puncher::MAX_RETRIES;
use std::time::Duration;

/// How long a hole punch may take: [`MAX_RETRIES`] attempts of [`PunchBudget::attempt`] each,
/// with opening the control stream counted against the whole.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PunchBudget {
    attempt: Duration,
}

impl PunchBudget {
    pub const fn per_attempt(attempt: Duration) -> Self {
        Self { attempt }
    }

    /// Every attempt inside a stage of `stage`, which also has to hold what follows a punch (the
    /// readiness sync and a handshake over the punched socket): the stage is split into one slice
    /// per attempt and one for that. Both peers derive the same split from the same stage, so a
    /// retry runs on both or on neither.
    pub fn within_stage(stage: Duration) -> Self {
        Self::per_attempt(stage / (MAX_RETRIES as u32 + 1))
    }

    pub fn attempt(&self) -> Duration {
        self.attempt
    }

    pub fn total(&self) -> Duration {
        self.attempt.saturating_mul(MAX_RETRIES as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::{PunchBudget, MAX_RETRIES};
    use std::time::Duration;

    /// Every attempt fits the stage with a slice to spare for what follows the punch. The
    /// previous fixed 20 s attempts against a 30 s stage meant the third never ran, and either
    /// end could find the stage over while the other still retried.
    #[test]
    fn every_attempt_fits_inside_the_stage_with_room_for_the_handshake() {
        for secs in [1, 5, 30, 60] {
            let stage = Duration::from_secs(secs);
            let budget = PunchBudget::within_stage(stage);
            assert!(
                budget.total() + budget.attempt() <= stage,
                "stage {stage:?}"
            );
            assert_eq!(budget.total(), budget.attempt() * MAX_RETRIES as u32);
            assert!(budget.attempt() > Duration::ZERO, "stage {stage:?}");
        }
    }
}
