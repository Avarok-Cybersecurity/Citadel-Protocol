//! The runtime's clock behind `citadel_link`'s `Clock` port: what a running node passes to
//! `ManagedLinks`. A test passes its own, so a deadline can be crossed without waiting for it.

use citadel_io::time::{Duration, Instant};
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

    fn sleep_until(&self, at: Millis) -> BoxFuture<'static, ()> {
        let wait = Duration::from_millis(at.0.saturating_sub(self.now().0));
        Box::pin(citadel_io::time::sleep(wait))
    }
}
