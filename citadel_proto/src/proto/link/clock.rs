//! The production `Clock` port: milliseconds since the clock was made, on the runtime's timer.

use citadel_io::time::Instant;
use citadel_link::{Clock, Millis};
use citadel_negotiation::ports::BoxFuture;

/// Time as the runtime keeps it. Each link's manager reads one, so its `Millis` start at 0.
pub(crate) struct RuntimeClock {
    origin: Instant,
}

impl RuntimeClock {
    pub(crate) fn start() -> Self {
        RuntimeClock {
            origin: Instant::now(),
        }
    }
}

impl Clock for RuntimeClock {
    fn now(&self) -> Millis {
        Millis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[citadel_io::tokio::test(start_paused = true)]
    async fn the_clock_sleeps_until_the_instant_it_names() {
        let clock = RuntimeClock::start();
        assert_eq!(clock.now(), Millis(0));
        clock.sleep_until(Millis(1_500)).await;
        assert_eq!(clock.now(), Millis(1_500));
    }
}
