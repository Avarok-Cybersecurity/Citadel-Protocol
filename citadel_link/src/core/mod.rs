//! `LinkCore::step(now, LinkInput) -> Vec<LinkCommand>`: the one place a link's decisions are
//! made (§3). It reads no clock (time is an argument), draws no randomness and does no I/O; the
//! manager in `citadel_proto` runs it in a loop and dispatches what it returns.

mod close;
mod dispatch;
mod heal;
mod io;
mod open;
mod outcome;
mod respond;
mod seal;
mod settings;
mod side;
mod stages;
mod state;
mod up;

pub use io::{BufferMode, LinkCommand, LinkInput, RendezvousVia};
pub use state::{LinkState, LiveRoute};

use std::collections::VecDeque;
use std::time::Duration;

use crate::decision::{LinkSettings, PeerCaps};
use crate::event::LossCause;
use crate::kind::{ConnectionId, Incarnation, LinkKind, Millis, Role, SettingId};
use crate::path::{NatClass, PathReport, PathStage, StageOutcome};
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
    /// This node's NAT as identified at boot; updated by `NatChanged` and every path report.
    pub local_nat: NatClass,
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
    /// Each stage that ran, with when it started relative to `started`.
    pub(crate) stages: Vec<(StageOutcome, Duration)>,
    /// When the link went down, for the outcome's downtime; `None` for a first establishment.
    pub(crate) down_since: Option<Millis>,
    /// The incarnation this attempt will seal (or reattach) as.
    pub(crate) incarnation: Incarnation,
    /// The adapter's report once a path opened.
    pub(crate) opened: Option<PathReport>,
    /// The stage running and when it must end.
    pub(crate) stage: usize,
    pub(crate) stage_started: Millis,
}

/// The heal an attempt belongs to: where it returns when it fails.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Heal {
    pub(crate) lost_at: Millis,
    pub(crate) cause: LossCause,
    pub(crate) attempt: u32,
}

/// A seal kept after its path died, for a reattach within the grace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) incarnation: Incarnation,
    pub(crate) lost_at: Millis,
}

/// A side attempt on a live link: moving it off the server relay onto a P2P route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Side {
    pub(crate) attempt: Attempt,
    pub(crate) deadline: Millis,
}

/// One link's pure state machine.
#[derive(Clone, Debug)]
pub struct LinkCore {
    pub(crate) cfg: LinkConfig,
    pub(crate) role: Role,
    pub(crate) settings: LinkSettings,
    pub(crate) plan: Option<PathPlan>,
    pub(crate) local_nat: NatClass,
    pub(crate) state: LinkState,
    pub(crate) reported_wake: Option<Millis>,
    /// Attempts started over the link's life (the outcome's `attempt`).
    pub(crate) attempts: u32,
    pub(crate) attempt: Option<Attempt>,
    pub(crate) heal: Option<Heal>,
    pub(crate) side: Option<Side>,
    pub(crate) rearm_at: Option<Millis>,
    pub(crate) rearm_failures: u32,
    pub(crate) probe_at: Option<Millis>,
    /// The highest incarnation issued.
    pub(crate) issued: Option<Incarnation>,
    pub(crate) held: Option<Held>,
    /// Delivered and not yet retired.
    pub(crate) live: Vec<Incarnation>,
    /// Retired, answer outstanding.
    pub(crate) retiring: Vec<Incarnation>,
    pub(crate) sealed_count: u32,
    pub(crate) ever_up: bool,
    pub(crate) rebinding: Option<PathTrigger>,
    /// The setting whose change the current reseal or re-establishment carries out.
    pub(crate) changing: Option<SettingId>,
    pub(crate) flaps: VecDeque<Millis>,
}

impl LinkCore {
    /// A dormant link. Fails fast on a policy or plan that cannot bound it (PCND).
    pub fn new(cfg: LinkConfig) -> Result<Self, ConfigError> {
        cfg.policy.validate().map_err(ConfigError::Policy)?;
        let role = cfg.kind.role().ok_or(ConfigError::NoRole)?;
        match (cfg.kind, &cfg.plan) {
            (LinkKind::Server, Some(plan))
                if plan.stages.len() == 1 && plan.stages[0].stage == PathStage::Dial => {}
            (LinkKind::Server, _) => return Err(ConfigError::ServerPlan),
            (LinkKind::Peer { .. }, Some(_)) => return Err(ConfigError::PeerPlanAtStart),
            (LinkKind::Peer { .. }, None) => {}
        }
        Ok(LinkCore {
            role,
            settings: cfg.settings,
            plan: cfg.plan.clone(),
            local_nat: cfg.local_nat,
            cfg,
            state: LinkState::Dormant,
            reported_wake: None,
            attempts: 0,
            attempt: None,
            heal: None,
            side: None,
            rearm_at: None,
            rearm_failures: 0,
            probe_at: None,
            issued: None,
            held: None,
            live: Vec::new(),
            retiring: Vec::new(),
            sealed_count: 0,
            ever_up: false,
            rebinding: None,
            changing: None,
            flaps: VecDeque::new(),
        })
    }

    pub fn state(&self) -> &LinkState {
        &self.state
    }

    /// The settings of the live incarnation (`from` of the next decision).
    pub fn settings(&self) -> LinkSettings {
        self.settings
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    /// When the shell must deliver the next `Tick`; `None` when nothing is timed.
    pub fn next_wake(&self) -> Option<Millis> {
        match &self.state {
            LinkState::Resolving { deadline, .. }
            | LinkState::Opening { deadline, .. }
            | LinkState::Sealing { deadline, .. }
            | LinkState::Reattaching { deadline, .. }
            | LinkState::Resealing { deadline, .. } => Some(*deadline),
            LinkState::Degraded { next_at, .. } => *next_at,
            LinkState::Up { .. } => [
                self.side.as_ref().map(|s| s.deadline),
                self.rearm_at,
                self.probe_at,
            ]
            .into_iter()
            .flatten()
            .min(),
            LinkState::Dormant | LinkState::Closing { .. } | LinkState::Closed { .. } => None,
        }
    }

    /// One step: every input in, the commands that follow out. Nothing happens after `Closed`.
    pub fn step(&mut self, now: Millis, input: LinkInput) -> Vec<LinkCommand> {
        let mut out = Vec::new();
        if matches!(self.state, LinkState::Closed { .. }) {
            return out;
        }
        self.dispatch(now, input, &mut out);
        let wake = self.next_wake();
        if wake != self.reported_wake {
            self.reported_wake = wake;
            if let Some(at) = wake {
                out.push(LinkCommand::ScheduleWake(at));
            }
        }
        out
    }
}
