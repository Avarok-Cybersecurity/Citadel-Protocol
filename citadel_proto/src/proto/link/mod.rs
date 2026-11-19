//! The protocol's side of the RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md` §2.1): the
//! node-wide mode that selects it, the clock it reads, and the C2S pieces of lane L1 (cancelling
//! an in-flight connect, §9.1). The decisions live in `citadel_link`; this module is its I/O.

mod abort;
mod c2s_establisher;
mod clock;
mod deadline;
mod mode;
// The frames, proof and admission rule are whole and tested; the stream swap that would carry
// them under a held session is not built yet (lane L1 report, design gap 1). `expect`, so the
// allowance fails the build the moment that integration uses them.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "the §5.2 stream swap is not integrated yet"
    )
)]
pub(crate) mod reattach;

pub use abort::AbortGuard;
pub(crate) use abort::{until_aborted, InFlightConnects};
pub(crate) use c2s_establisher::{C2sEstablisher, C2sPath};
pub use clock::RuntimeClock;
pub(crate) use deadline::{login_deadline, LoginDeadline};
pub use mode::{LinkManagerMode, ManagedLinks, ManagedLinksError};

/// The port a managed node's deadlines read, and the time it speaks in.
pub use citadel_link::{Clock, Millis};
/// The future a [`Clock`] sleeps with.
pub use citadel_negotiation::ports::BoxFuture;
