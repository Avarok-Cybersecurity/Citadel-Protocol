//! The protocol's side of the RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md` §2.1): the
//! node-wide mode that selects it, the clock it reads, and the C2S pieces of lane L1 (cancelling
//! an in-flight connect, §9.1). The decisions live in `citadel_link`; this module is its I/O.

mod clock;
mod mode;

pub use clock::RuntimeClock;
pub use mode::{LinkManagerMode, ManagedLinks, ManagedLinksError};

/// The port a managed node's deadlines read, and the time it speaks in.
pub use citadel_link::{Clock, Millis};
/// The future a [`Clock`] sleeps with.
pub use citadel_negotiation::ports::BoxFuture;
