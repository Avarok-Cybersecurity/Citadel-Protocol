//! `LinkCore::step(now, LinkInput) -> Vec<LinkCommand>`: the one place a link's decisions are
//! made (§3). It reads no clock (time is an argument), draws no randomness and does no I/O; the
//! manager in `citadel_proto` runs it in a loop and dispatches what it returns.

mod io;
mod state;

pub use io::{BufferMode, LinkCommand, LinkInput, RendezvousVia};
pub use state::{LinkState, LiveRoute};

use std::collections::VecDeque;
use std::time::Duration;

use crate::decision::{LinkSettings, PeerCaps};
use crate::kind::{ConnectionId, Incarnation, LinkKind, Millis};
use crate::path::StageOutcome;
use crate::plan::{PathPlan, PathTrigger, PunchReuse};
use crate::policy::{LinkPolicy, PolicyError};

/// Everything a link is constructed with. Every field is required (PCND).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkConfig {
    pub kind: LinkKind,
    pub connection: ConnectionId,
    pub policy: LinkPolicy,
    /// What both ends support (the intersection of the two `Hello`s).
    pub caps: PeerCaps,
    /// The settings the first seal is built with.
    pub settings: LinkSettings,
    /// C2S: the dial plan (one `Dial` stage). P2P: `None`; the plan arrives with the rendezvous.
    pub plan: Option<PathPlan>,
}

/// A configuration the core refuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Policy(PolicyError),
    /// A C2S link needs a plan of exactly one `Dial` stage.
    ServerPlan,
    /// A P2P link's plan arrives with its rendezvous, never at construction.
    PeerPlanAtStart,
    /// Both ends of the pair have the same CID: no Leader exists.
    NoRole,
}

/// The attempt in flight: what its outcome will say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) number: u32,
    pub(crate) trigger: PathTrigger,
    pub(crate) reuse: PunchReuse,
    pub(crate) started: Millis,
    pub(crate) stages: Vec<StageOutcome>,
    pub(crate) started_at: Vec<Duration>,
    /// When the link went down, for the outcome's downtime; `None` for a first establishment.
    pub(crate) down_since: Option<Millis>,
    /// The incarnation this attempt will seal (or reattach) as.
    pub(crate) incarnation: Incarnation,
    /// The adapter's report once a path opened.
    pub(crate) opened: Option<crate::path::PathReport>,
}

/// A seal kept after its path died, for a reattach within the grace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) incarnation: Incarnation,
    pub(crate) lost_at: Millis,
}

/// One link's pure state machine.
#[derive(Clone, Debug)]
pub struct LinkCore {
    pub(crate) cfg: LinkConfig,
    pub(crate) settings: LinkSettings,
    pub(crate) plan: Option<PathPlan>,
    pub(crate) state: LinkState,
    pub(crate) wake: Option<Millis>,
    /// Attempts started over the link's life (the outcome's `attempt`).
    pub(crate) attempts: u32,
    pub(crate) attempt: Option<Attempt>,
    /// A side attempt to move a live link off the server relay (or back onto a direct route).
    pub(crate) side: Option<(Attempt, usize)>,
    /// The highest incarnation issued.
    pub(crate) issued: Option<Incarnation>,
    pub(crate) held: Option<Held>,
    /// Delivered and not yet retired.
    pub(crate) live: Vec<Incarnation>,
    pub(crate) sealed_count: u32,
    pub(crate) ever_up: bool,
    pub(crate) rebinding: Option<PathTrigger>,
    pub(crate) flaps: VecDeque<Millis>,
}
