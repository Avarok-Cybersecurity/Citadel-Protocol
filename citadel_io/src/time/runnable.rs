//! Budgets counted in time the caller could run, not in wall-clock time.
//!
//! A wall-clock budget is spent by anything that stops the caller running: a loaded machine, a
//! frozen process, a browser's one thread busy hashing. A punch's receive window and a test's hang
//! guard both ran out that way while the work they bounded had not had its time. These count only
//! ticks the caller actually got to run, so a stall counts as one tick, whatever its length, while
//! a caller that runs freely and still waits (a real hang) spends the budget at its nominal length.

use super::{interval, Duration, MissedTickBehavior};
use std::future::Future;

const TICK: Duration = Duration::from_millis(50);

/// Ends once the caller has had `window` of time in which it could run.
pub async fn runnable_window(window: Duration) {
    let mut ticks = interval(TICK);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick completes at once; each one after it is one TICK of runnable time.
    for _ in 0..=window.as_millis().div_ceil(TICK.as_millis()) {
        ticks.tick().await;
    }
}

/// `work` did not finish within its budget of runnable time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnableElapsed(pub Duration);

impl std::fmt::Display for RunnableElapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not finished within {:?} of runnable time", self.0)
    }
}

impl std::error::Error for RunnableElapsed {}

/// `work`'s output, or [`RunnableElapsed`] once `budget` of runnable time has passed without it.
pub async fn runnable_timeout<F: Future>(
    budget: Duration,
    work: F,
) -> Result<F::Output, RunnableElapsed> {
    let window = std::pin::pin!(runnable_window(budget));
    let work = std::pin::pin!(work);
    match futures::future::select(work, window).await {
        futures::future::Either::Left((output, _)) => Ok(output),
        futures::future::Either::Right(((), _)) => Err(RunnableElapsed(budget)),
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "runnable_tests.rs"]
mod tests;
