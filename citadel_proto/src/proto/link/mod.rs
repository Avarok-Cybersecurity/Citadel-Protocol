//! The RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md` §2): each kind of link reaches
//! the kernel in one order, path → seal → deliver, through the `citadel_link::LinkEstablisher`
//! contract, and a [`manager`] keeps it existing while the user keeps it open.

#[cfg(not(target_family = "wasm"))]
pub(crate) mod clock;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod manager;
pub mod mode;
pub(crate) mod p2p;
