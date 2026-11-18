//! R-DIAL: the stronger-offer rule, in one place.
//!
//! The rule is SDK1's `citadel_types::proto::stronger_offer` (Citadel-Protocol PR #377), used as
//! is: this crate re-exports it and defines the key profile's merge through it, so crossed dials
//! and crossed in-band proposals can never disagree about which offer is stronger.

pub use citadel_types::proto::stronger_offer;
