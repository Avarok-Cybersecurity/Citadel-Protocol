//! A punch's receive window, counted in time the puncher could run.
//!
//! The window was a wall-clock timeout. When the executor stalled for longer than the window
//! (a loaded machine, or a browser's one thread hashing), both peers' windows ran out during the
//! stall. Their SYNs and SYN_ACKs were already in the sockets, but neither peer got to read them.

use citadel_io::time::{interval, Duration, MissedTickBehavior};

const TICK: Duration = Duration::from_millis(50);

/// Ends once the caller has had `window` of time in which it could run. A stall counts as one
/// tick, whatever its length.
pub(crate) async fn runnable_window(window: Duration) {
    let mut ticks = interval(TICK);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick completes at once; each one after it is one TICK of runnable time.
    for _ in 0..=window.as_millis().div_ceil(TICK.as_millis()) {
        ticks.tick().await;
    }
}

#[cfg(test)]
#[path = "runnable_window_tests.rs"]
mod tests;
