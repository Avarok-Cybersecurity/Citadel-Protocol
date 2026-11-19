//! The harness's vocabulary: the two sides, what each holds, what is outstanding, and what can
//! happen next.

use crate::core::LinkCommand;
use crate::decision::LinkSettings;
use crate::event::{LinkEvent, LossCause};
use crate::kind::{Incarnation, RouteId};
use crate::plan::{PathPlan, PunchReuse, TimedStage};
use crate::LinkCore;

/// A is the lower CID (the Leader), B the higher (the Loser).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// A port call a side's shell made and the world has not answered yet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Meet {
        attempt: u32,
    },
    Open {
        attempt: u32,
        stage: TimedStage,
        reuse: PunchReuse,
    },
    Seal {
        incarnation: Incarnation,
    },
    Reattach {
        incarnation: Incarnation,
    },
    Retire {
        incarnation: Incarnation,
    },
    Probe,
    Rebind {
        route: RouteId,
    },
}

#[derive(Clone, Debug)]
pub struct Party {
    pub core: LinkCore,
    pub ops: Vec<Op>,
    /// Every command, in order.
    pub commands: Vec<LinkCommand>,
    pub events: Vec<LinkEvent>,
    /// Every input's commands, one entry per step, for the per-step invariants.
    pub steps: Vec<Vec<LinkCommand>>,
}

/// What the simulated network lets through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    pub server_up: bool,
    pub direct_works: bool,
    pub turn_works: bool,
    pub rebind_works: bool,
    /// The plan a rendezvous hands both sides.
    pub plan: PathPlan,
}

/// One thing that can happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Start(Side),
    /// Answers outstanding op `i` of a side; `false` makes it fail whatever the network allows.
    Resolve(Side, usize, bool),
    /// The live path dies under both ends.
    Lose(LossCause),
    NatChange(Side),
    Interface(Side),
    /// The negotiator agreed these settings (one `SettingsAgreed` to both ends; §4.4).
    Agree(LinkSettings),
    /// Both sides asked at once; the negotiator's merge is R-DIAL's stronger offer.
    AgreeBoth(LinkSettings, LinkSettings),
    Tick(Side),
    Suspend(Side),
    Resume(Side),
    Shutdown(Side),
    Reachable(Side),
    ServerDown,
    ServerUp,
    DirectDown,
    DirectUp,
}
