//! How a node keeps its links. Chosen once, when the node is built, and required (PCND): no
//! builder picks one for the caller.
//!
//! `Legacy` is the behaviour every node had before the RobustConnectionManager. `Managed` turns on
//! what the manager's lanes have landed so far, each behind it until the last lane deletes
//! `Legacy` (§12.4). Both build on every target: the mode is a runtime value, never a `cfg`, so a
//! debug and a release build of one node behave alike.

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use citadel_link::Clock;

/// How this node keeps its links.
#[derive(Clone)]
pub enum LinkManagerMode {
    /// Today's behaviour: a connect runs to its end once requested, and its deadlines read the
    /// runtime's own timers.
    Legacy,
    /// The RobustConnectionManager: a connect can be aborted by the ticket that started it
    /// (`NodeRequest::AbortLink`), and the deadlines of a login read [`ManagedLinks::clock`].
    Managed(ManagedLinks),
}

impl LinkManagerMode {
    pub fn managed(&self) -> Option<&ManagedLinks> {
        match self {
            LinkManagerMode::Legacy => None,
            LinkManagerMode::Managed(links) => Some(links),
        }
    }
}

impl Debug for LinkManagerMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkManagerMode::Legacy => write!(f, "Legacy"),
            LinkManagerMode::Managed(links) => write!(f, "Managed({links:?})"),
        }
    }
}

/// What a managed node is built with. Every field is required.
#[derive(Clone)]
pub struct ManagedLinks {
    clock: Arc<dyn Clock>,
    reattach_grace: Duration,
}

/// A managed configuration the node refuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ManagedLinksError {
    /// A grace of zero would refuse every reattach while claiming to allow them.
    ZeroReattachGrace,
}

impl std::fmt::Display for ManagedLinksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedLinksError::ZeroReattachGrace => write!(f, "reattach_grace must be above zero"),
        }
    }
}

impl std::error::Error for ManagedLinksError {}

impl ManagedLinks {
    /// `clock` is what every managed deadline reads ([`RuntimeClock`](super::RuntimeClock) in a
    /// running node). `reattach_grace` is how long a server holds a dropped session's seal for a
    /// reattach, and a client keeps its own (§5.2; the owner chose 5 minutes, Q2).
    pub fn new(clock: Arc<dyn Clock>, reattach_grace: Duration) -> Result<Self, ManagedLinksError> {
        if reattach_grace.is_zero() {
            return Err(ManagedLinksError::ZeroReattachGrace);
        }
        Ok(ManagedLinks {
            clock,
            reattach_grace,
        })
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn reattach_grace(&self) -> Duration {
        self.reattach_grace
    }
}

impl Debug for ManagedLinks {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedLinks")
            .field("reattach_grace", &self.reattach_grace)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::link::RuntimeClock;

    #[test]
    fn a_zero_reattach_grace_is_refused() {
        let clock: Arc<dyn Clock> = Arc::new(RuntimeClock::new());
        assert_eq!(
            ManagedLinks::new(clock.clone(), Duration::ZERO).err(),
            Some(ManagedLinksError::ZeroReattachGrace)
        );
        let links = ManagedLinks::new(clock, Duration::from_secs(300)).unwrap();
        assert_eq!(links.reattach_grace(), Duration::from_secs(300));
    }
}
