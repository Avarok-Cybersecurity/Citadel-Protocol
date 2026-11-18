//! The pure core of the Citadel RobustConnectionManager (`ROBUST-CONNECTION-MANAGER.md`).
//!
//! A link (C2S, or one peer pair) is established in one enforced order, path → seal → deliver
//! ([`typestate`]), through one [`LinkEstablisher`] per kind of link. While the user keeps it
//! open, [`LinkCore`] keeps it existing: it heals drops (reattaching the live seal, reusing the
//! punched socket, migrating QUIC, or punching afresh, §3.3), decides locally how a settings
//! change is applied (`decision::decide`, §4), reports one path outcome per establishment (§6), and on a
//! true close returns, through the [`outbox`], every payload it never delivered (§7).
//!
//! Nothing here reads a clock (time is an argument; the [`Clock`] port is the shell's), draws
//! randomness, spawns, sleeps or touches a socket. It builds for `wasm32-unknown-unknown`.

mod core;
pub mod decision;
mod establisher;
pub mod event;
mod kind;
pub mod outbox;
pub mod path;
pub mod plan;
pub mod policy;
pub mod typestate;

#[cfg(any(test, feature = "harness"))]
pub mod schedule;

pub use crate::core::{
    BufferMode, ConfigError, LinkCommand, LinkConfig, LinkCore, LinkInput, LinkState, LiveRoute,
    RendezvousVia,
};
pub use citadel_negotiation::ports::Clock;
pub use decision::{
    FloorChange, LinkSettings, PeerCaps, ReestablishWhy, SealParams, SettingsDecision,
};
pub use establisher::{
    Fut, KernelChannel, LinkEstablisher, MaybeSend, MaybeSync, PathHandle, SealedSession,
    StableHandle,
};
pub use event::{
    CloseReason, CloseSummary, DisconnectReason, LinkDegraded, LinkEvent, LossCause,
    PathAttemptOutcome, SealRefusal, ShutdownReason,
};
pub use kind::{
    Cid, ConnectionId, Epoch, Incarnation, LinkKind, Millis, Role, RouteId, SettingId, Ticket,
};
pub use path::{
    NatClass, PathPlanKind, PathReport, PathStage, RouteKind, ServerTransport, StageFailure,
    StageOutcome,
};
pub use plan::{PathPlan, PathTrigger, PunchReuse, TimedStage, TurnConfig};
pub use policy::{Backoff, FlapPolicy, HealPolicy, LinkPolicy, PolicyError};
pub use typestate::{
    Delivered, Link, PathFailure, Pathed, RetireReason, SealFailure, Sealed, Stage, Unpathed,
};
