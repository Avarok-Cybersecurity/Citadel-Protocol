//! The runtime's clock behind `citadel_link`'s `Clock` port: what a running node passes to
//! `ManagedLinks`, and what the P2P manager reads through `ManagedLinks::clock`. A test passes
//! its own, so a deadline can be crossed without waiting for it.

use citadel_io::time::Instant;
use citadel_link::{Clock, Millis};
use citadel_negotiation::ports::BoxFuture;

/// Milliseconds since the clock was made, from the runtime's monotonic timer.
pub struct RuntimeClock {
    origin: Instant,
}

impl RuntimeClock {
    pub fn new() -> Self {
        RuntimeClock {
            origin: Instant::now(),
        }
    }
}

impl Default for RuntimeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for RuntimeClock {
    fn now(&self) -> Millis {
        Millis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Sleeps to the absolute instant `at` names, so a sleep started late still wakes on time.
    fn sleep_until(&self, at: Millis) -> BoxFuture<'static, ()> {
        let deadline = self
            .origin
            .checked_add(std::time::Duration::from_millis(at.0));
        Box::pin(async move {
            match deadline {
                Some(deadline) => citadel_io::time::sleep_until(deadline).await,
                // Beyond the representable future: never.
                None => std::future::pending().await,
            }
        })
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;

    #[citadel_io::tokio::test(start_paused = true)]
    async fn the_clock_sleeps_until_the_instant_it_names() {
        let clock = RuntimeClock::new();
        assert_eq!(clock.now(), Millis(0));
        clock.sleep_until(Millis(1_500)).await;
        assert_eq!(clock.now(), Millis(1_500));
    }
}
