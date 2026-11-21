//! Everything that goes into the core and everything it asks for (§2.3). The shell turns every
//! port result into a [`LinkInput`] and every [`LinkCommand`] into a port call; it never decides.

use crate::decision::{LinkSettings, SealParams};
use crate::event::{DisconnectReason, LinkEvent, LossCause, ShutdownReason};
use crate::kind::{Epoch, Incarnation, RouteId, SettingId};
use crate::path::{NatClass, PathReport, StageFailure};
use crate::plan::{PathPlan, PathTrigger, PunchReuse, TimedStage};
use crate::typestate::{PathFailure, RetireReason, SealFailure};
use crate::Millis;

/// Every event a link reacts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkInput {
    /// `OpenLink`.
    Start,
    /// P2P: the rendezvous of `attempt` met the peer; `plan` is the pair's plan (the stamped one,
    /// or the one this peer made alone).
    Met {
        attempt: u32,
        plan: PathPlan,
    },
    /// P2P: the rendezvous of `attempt` failed.
    MeetFailed {
        attempt: u32,
        failure: StageFailure,
    },
    PathOpened {
        attempt: u32,
        report: PathReport,
    },
    PathFailed {
        attempt: u32,
        failure: PathFailure,
    },
    Sealed {
        incarnation: Incarnation,
    },
    SealFailed {
        incarnation: Incarnation,
        failure: SealFailure,
    },
    /// The deliver step finished (informational: deliver cannot fail).
    Delivered {
        incarnation: Incarnation,
    },
    /// The incarnation's path stopped carrying traffic.
    LinkLost {
        incarnation: Incarnation,
        cause: LossCause,
    },
    /// The peer announced a deliberate close on the lane.
    PeerClosing {
        reason: Option<DisconnectReason>,
    },
    NatChanged {
        local: NatClass,
    },
    InterfaceChanged,
    /// The answer to `Rebind`.
    Rebound {
        route: RouteId,
        ok: bool,
    },
    /// Browser visibility or OS sleep.
    Suspended,
    Resumed,
    /// The negotiator agreed a new value; the core decides how to apply it (§4).
    SettingsAgreed {
        epoch: Epoch,
        setting: SettingId,
        agreed: LinkSettings,
    },
    /// P2P: the peer healed first and dialled this side; `report` is the path it opened and
    /// `incarnation` the one its handshake seals (the initiator names it, so both ends agree).
    /// Naming the incarnation this side holds after a drop asks for a reattach of that seal.
    PeerOffer {
        incarnation: Incarnation,
        report: PathReport,
    },
    /// P2P: the peer came online (an inbound PostRegister or PostConnect).
    PeerReachable,
    /// The answer to `Probe`.
    ProbeResult {
        ok: bool,
    },
    /// The answer to `Retire`: the incarnation's undelivered payloads are in the outbox.
    Retired {
        incarnation: Incarnation,
    },
    /// A wake the core asked for.
    Tick,
    Shutdown {
        reason: ShutdownReason,
    },
}

/// Whether the kernel's stable handle carries sends to a live incarnation or holds them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BufferMode {
    /// Sends go to the current incarnation; the outbox replays what it held, in order.
    Live,
    /// Sends are held in the outbox up to its budget (healing).
    Hold,
}

/// Where a rendezvous goes (§5).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RendezvousVia {
    /// Through the Citadel server (PostConnect).
    Server,
    /// Directly, to the peer's last rendezvous card (lane L6).
    Direct,
}

/// Everything the core asks the shell to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkCommand {
    /// Open one stage of a path.
    OpenPath {
        attempt: u32,
        stage: TimedStage,
        trigger: PathTrigger,
        reuse: PunchReuse,
        deadline: Millis,
    },
    Rendezvous {
        attempt: u32,
        via: RendezvousVia,
        deadline: Millis,
    },
    /// A fresh handshake on the path just opened (or forked), as `incarnation`.
    Seal {
        incarnation: Incarnation,
        params: SealParams,
        deadline: Millis,
    },
    /// Move the held seal of `incarnation` onto the path just opened.
    Reattach {
        incarnation: Incarnation,
        deadline: Millis,
    },
    Deliver {
        incarnation: Incarnation,
    },
    /// Open a second session lane on the live path for `next`; a `Seal` follows.
    ForkPath {
        live: Incarnation,
        next: Incarnation,
    },
    /// Point the stable handle at `to`; both ends switch at this point.
    Cutover {
        from: Incarnation,
        to: Incarnation,
    },
    Retire {
        incarnation: Incarnation,
        reason: RetireReason,
    },
    /// Close whatever path is open and not delivered.
    ClosePath,
    /// The direct route is gone: move the live seal onto the server relay (and replay).
    FallBackToRelay,
    /// A side attempt opened a P2P route: attach it under the live seal.
    AttachRoute {
        route: RouteId,
    },
    /// Migrate the route's QUIC connection to a fresh local socket.
    Rebind {
        route: RouteId,
    },
    Probe,
    Buffer(BufferMode),
    Report(LinkEvent),
    ScheduleWake(Millis),
}
