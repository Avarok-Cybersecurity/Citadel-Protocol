//! What a link reports to the kernel (§6, §7): one path outcome per establishment attempt, one
//! `LinkDegraded` per drop, and one close summary when the link truly closes.

use std::time::Duration;

use citadel_negotiation::RenegotiationReason;

use crate::kind::{Cid, ConnectionId, Incarnation, LinkKind, Millis, RouteId, SettingId};
use crate::path::{NatClass, PathPlanKind, RouteKind, StageOutcome};
use crate::plan::{PathTrigger, PunchReuse};

/// Why a live link stopped carrying traffic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LossCause {
    /// Reader EOF, a keep-alive or QUIC idle timeout: the path died, nothing else changed.
    Transient,
    /// The direct route went away while the server relay stayed up (P2P).
    RouteLost,
    /// The local NAT changed and the route could not migrate.
    NatChanged,
    /// A local interface changed and the route could not migrate.
    InterfaceChanged,
    /// A settings change needs a new path (§4 `Reestablish`).
    Settings,
    /// The peer is offline (P2P).
    PeerOffline,
    /// The server could not be reached, or did not answer a rendezvous.
    Unreachable,
    /// More drops than the flap policy allows inside its window (§9.3).
    Flapping,
}

/// One path attempt of a link: the protocol's `PathAttemptOutcome`, moved here and extended
/// (§6.1). Lane L3 makes `citadel_proto` re-export it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathAttemptOutcome {
    /// The peer's CID, or 0 for the server (`C2S_IDENTITY_CID`).
    pub peer_cid: Cid,
    /// 1 for a link's first attempt; every attempt after it adds one.
    pub attempt: u32,
    pub plan: PathPlanKind,
    /// The route the attempt attached; `None` when it attached none.
    pub path: Option<RouteKind>,
    /// Every stage, in stage order, including those not tried (with the reason).
    pub stages: Vec<StageOutcome>,
    pub local_nat: NatClass,
    /// `None` on a C2S link (the server's NAT is not measured).
    pub peer_nat: Option<NatClass>,
    pub link: LinkKind,
    pub trigger: PathTrigger,
    pub punch: PunchReuse,
    pub incarnation: Option<Incarnation>,
    pub route_id: Option<RouteId>,
    /// From the link going down to this establishment; `None` for the first one.
    pub downtime: Option<Duration>,
    /// When each stage of `stages` started, relative to the attempt's start; aligned with
    /// `stages` (zero for a stage that was not tried).
    pub stage_started_at: Vec<Duration>,
}

/// The link stopped carrying traffic and is healing; sends are held (§6.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkDegraded {
    pub link: LinkKind,
    pub connection: ConnectionId,
    pub incarnation: Option<Incarnation>,
    pub cause: LossCause,
    pub since: Millis,
}

/// Why the local side shut a link.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ShutdownReason {
    /// `CloseLink`, or the node shutting down.
    Shutdown,
    /// `AbandonSession`.
    Abandon,
    /// `AbortLink`: an in-flight connect was cancelled (§9.1).
    Aborted,
}

/// Why a seal was refused for good.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SealRefusal {
    /// The offer was below this node's or the peer's policy.
    BelowPolicy,
    /// The credentials were refused.
    BadCredentials,
}

/// Why a P2P connection was closed on purpose: `citadel_proto`'s `DisconnectReason`, moved here
/// so the core can name it (lane L1 makes the protocol re-export it; the serde shape is the
/// same, so the wire is unchanged).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DisconnectReason {
    /// A setting could not be changed on the live connection: the closing side redials at the
    /// agreed value. The peer should wait to be dialled rather than redial itself.
    Renegotiation {
        setting: SettingId,
        reason: RenegotiationReason,
    },
}

/// Why a link truly closed (§7.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    Local(ShutdownReason),
    /// The peer closed on purpose; `None` when it gave no reason.
    Peer(Option<DisconnectReason>),
    Refused(SealRefusal),
    /// The heal policy gave up on a link that was up before.
    GaveUp {
        after: Duration,
        attempts: u32,
    },
    /// The heal policy gave up on a link that was never up.
    Unreachable {
        attempts: u32,
    },
}

/// The core's part of the `Disconnect` it reports exactly once, on `Closed`. The shell adds the
/// outbox's drain to it ([`crate::outbox::LinkDisconnect`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CloseSummary {
    pub link: LinkKind,
    pub connection: ConnectionId,
    pub reason: CloseReason,
    /// How many incarnations this link was sealed as.
    pub incarnations: u32,
}

/// Everything a link reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkEvent {
    Path(PathAttemptOutcome),
    Degraded(LinkDegraded),
    Closed(CloseSummary),
}
