//! A pure, glare-safe negotiator for in-session settings between two Citadel peers.
//!
//! One [`Negotiator`] per `(connection, setting)` turns two peers' concurrent intentions into
//! one agreed value: a deterministic [`Setting::merge`] when both propose at once (for the key
//! profile, R-DIAL's stronger offer), a fixed leader (the lower CID) to execute it, an epoch per
//! agreed change, and a deliberate, reasoned fallback when the change cannot be made in band.
//! The core does no I/O: no clock (time is an argument), no randomness, no async runtime. The
//! [`ports`] are what a shell implements around it. Design: `NEGOTIATION-LAYER.md`.

mod core;
pub mod frame;
mod ids;
mod io;
pub mod merge;
mod policy;
pub mod ports;
mod setting;
pub mod settings;

#[cfg(any(test, feature = "harness"))]
pub mod schedule;

pub use crate::core::{ConfigError, Negotiator, NegotiatorConfig, REORDER_WINDOW};
pub use frame::{
    ApplyEvidence, CapabilityBits, Envelope, Frame, Hello, PeerSupport, RejectReason,
    RenegotiationReason,
};
pub use ids::{Cid, ConnectionId, Epoch, Millis, Role, SettingId};
pub use io::{
    Command, Input, KeyExchangeOutcome, NegotiationEvent, NegotiationState, ViolationKind,
};
pub use policy::{NegotiationPolicy, PolicyError};
pub use setting::{
    decode_value, encode_value, is_below, value_digest, ApplyPath, Setting, ValueCodecError,
};
