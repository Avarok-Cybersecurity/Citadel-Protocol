//! The states of one link (§3.1). Public and inspectable: the shell and the tests read them;
//! only [`LinkCore::step`](super::LinkCore::step) changes them.

use crate::decision::SealParams;
use crate::event::{CloseReason, LossCause};
use crate::kind::{Epoch, Incarnation, Millis, RouteId};
use crate::path::RouteKind;

/// Where a live link runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LiveRoute {
    pub route: RouteId,
    pub kind: RouteKind,
    pub migratable: bool,
}

/// One link's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Constructed, not started.
    Dormant,
    /// A rendezvous is in flight (P2P).
    Resolving { attempt: u32, deadline: Millis },
    /// One stage of a path is opening; `stage` indexes the plan.
    Opening {
        attempt: u32,
        stage: usize,
        deadline: Millis,
    },
    /// A fresh seal is running on the path just opened.
    Sealing {
        attempt: u32,
        incarnation: Incarnation,
        deadline: Millis,
    },
    /// The held seal is moving onto the path just opened.
    Reattaching {
        attempt: u32,
        incarnation: Incarnation,
        deadline: Millis,
    },
    /// Delivered; the kernel's handle is live.
    Up {
        incarnation: Incarnation,
        route: LiveRoute,
        since: Millis,
    },
    /// Not carrying traffic; sends are held; healing per the policy. `next_at` is `None` while
    /// suspended or while a probe is out.
    Degraded {
        lost_at: Millis,
        cause: LossCause,
        attempt: u32,
        next_at: Option<Millis>,
        paused: bool,
    },
    /// Make-before-break on the live path for a settings change (§4).
    Resealing {
        live: Incarnation,
        route: LiveRoute,
        next: Incarnation,
        epoch: Epoch,
        params: SealParams,
        deadline: Millis,
    },
    /// Retiring every incarnation; `retiring` answers are outstanding.
    Closing { reason: CloseReason, retiring: u32 },
    /// Terminal; the close was reported exactly once.
    Closed { reason: CloseReason },
}
