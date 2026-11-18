//! What one path attempt tries, in which order, and for how long, and why it ran. Absorbs
//! `citadel_proto`'s `p2p_plan` (the stages) and the plan half of `p2p_outcome_context` (which
//! stages a plan does not try, and why). Pure: no I/O, no clock.

use std::time::Duration;

use crate::event::LossCause;
use crate::kind::SettingId;
use crate::path::PathStage;

/// The attempt timeout of each stage of a plan made without a stamped plan (an older peer or
/// server): the hole punch with its QUIC handshake, and one relay attempt.
pub const LEGACY_DIRECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const LEGACY_TURN_TIMEOUT: Duration = Duration::from_secs(30);

/// A stage and how long it may take.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimedStage {
    pub stage: PathStage,
    pub timeout: Duration,
}

/// The stages of one attempt, in order. A P2P plan's upgrade stages (Direct, Turn) are followed
/// by the server relay, which every pair has while the server is up; a C2S plan is one dial.
/// The TURN config itself stays with the adapter: the plan only says *that* TURN is tried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPlan {
    pub stages: Vec<TimedStage>,
    /// Whether this peer held a TURN config when the plan was made, for reporting why a plan
    /// without a Turn stage does not try one.
    pub turn_configured: bool,
    /// Whether both NATs are unpredictable (no punch can work), for the same report.
    pub direct_impossible: bool,
}

/// What a TURN config must say for planning. `citadel_wire`'s `TurnRelayConfig` implements it
/// in the adapter, so the policy is read from its one definition.
pub trait TurnConfig {
    /// `TurnPolicy::RelayOnly`: never punch, relay only.
    fn relay_only(&self) -> bool;
}

/// Why a path attempt ran (§6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathTrigger {
    /// The link's first establishment.
    Initial,
    /// A heal after the link was lost.
    LinkLost { cause: LossCause },
    /// The local NAT changed while the link was up.
    NatChanged,
    /// A local interface changed while the link was up.
    InterfaceChanged,
    /// A settings change needed a new seal or a new path (§4).
    SettingsChange(SettingId),
    /// The peer healed first and this side accepted its dial.
    PeerInitiated,
    /// An upgrade from the server relay to a P2P route.
    Rearm,
}

/// How the path of an establishment relates to the one before it (§6.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PunchReuse {
    /// A new hole punch.
    Fresh,
    /// A fresh seal on the socket that was already punched.
    ReusedSocket,
    /// QUIC migrated the live connection to a new local socket (a rebind).
    Migrated,
    /// The existing seal on a new path (`REATTACH`).
    Reattached,
    /// No punch is involved: a C2S stream or the server relay.
    NotNeeded,
}
