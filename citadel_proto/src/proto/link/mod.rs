//! The protocol's side of the RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md` §2.1): the
//! node-wide mode that selects it, the clock it reads, the C2S pieces of lane L1 (cancelling an
//! in-flight connect, §9.1), and lane L2's P2P manager. Each kind of link reaches the kernel in
//! one order, path → seal → deliver, through the `citadel_link::LinkEstablisher` contract, and a
//! [`manager`] keeps it existing while the user keeps it open. The decisions live in
//! `citadel_link`; this module is its I/O.

mod abort;
mod c2s_establisher;
mod clock;
mod deadline;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod manager;
mod mode;
pub(crate) mod p2p;
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
#[cfg(test)]
pub(crate) mod test_policy;

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
