//! The establishers of the RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md` §2): each
//! kind of link reaches the kernel in one order, path → seal → deliver, through the
//! `citadel_link::LinkEstablisher` contract.

pub(crate) mod p2p;
