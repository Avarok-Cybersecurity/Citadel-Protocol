//! What goes into [`Negotiator::step`](crate::Negotiator::step) and what comes out.

use crate::frame::{Envelope, RejectReason, RenegotiationReason};
use crate::ids::{Epoch, SettingId};

/// How one key round ended, as the `KeyExchange` port reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyExchangeOutcome {
    /// Toolset version `version` now carries the agreed profile.
    Applied {
        version: u32,
    },
    /// A plain rekey won the ratchet contention; the toolset advanced to `version` without it.
    Superseded {
        version: u32,
    },
    /// The peer refused the round (its profile check failed).
    Refused(String),
    Failed(String),
}

/// Everything the core reacts to. Time is passed beside it, never read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input<S> {
    /// The local user (or the agent on its behalf) wants the setting at this value.
    Request(S),
    /// The local user withdraws its pending proposal.
    Cancel,
    /// A frame from the peer.
    Recv(Envelope),
    /// The key round for `epoch` ended.
    KeyOutcome {
        epoch: Epoch,
        outcome: KeyExchangeOutcome,
    },
    /// The local apply of `epoch` ended.
    LocalOutcome {
        epoch: Epoch,
        result: Result<(), String>,
    },
    /// The local minimum for this peer changed (the shell's preference store is the source).
    SetMinimum(S),
    /// The shell could not hand a frame to the lane: the lane is gone.
    SendFailed,
    /// The shell's wake-up at [`Negotiator::next_wake`](crate::Negotiator::next_wake).
    Tick,
}

/// What the core asks the shell to do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command<S> {
    /// Deliver this envelope to the peer on the in-channel lane.
    Send(Envelope),
    /// Run one steered ratchet round building `epoch` with this profile (Leader only).
    ApplyKeyEpoch { epoch: Epoch, value: S },
    /// Apply this value locally, then feed `Input::LocalOutcome`.
    ApplyLocal { epoch: Epoch, value: S },
    /// The peer has retired everything before `epoch`: refuse message frames below it.
    RaiseFloor { epoch: Epoch },
    /// Disconnect with this reason. Issued by the side that originated the fallback.
    Drop {
        reason: RenegotiationReason,
        next: S,
    },
    /// Tell the account's windows (agent) or the kernel (SDK).
    Report(NegotiationEvent<S>),
}

/// One reported change of a negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiationEvent<S> {
    pub setting: SettingId,
    pub epoch: Epoch,
    pub state: NegotiationState<S>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationState<S> {
    Proposed {
        value: S,
        by_us: bool,
    },
    /// Also reported for a glare-merged value this side did not propose.
    Accepted {
        agreed: S,
    },
    Applied {
        agreed: S,
        version: Option<u32>,
    },
    Rejected {
        reason: RejectReason,
        proposed: S,
    },
    /// The connection is being dropped deliberately. `we_redial` is the redial rule as the core
    /// decides it: the Leader redials, except toward a legacy peer, where the requester does.
    FellBack {
        reason: RenegotiationReason,
        next: S,
        we_redial: bool,
    },
    Violation {
        kind: ViolationKind,
    },
}

/// Message-layer violations. `BelowFloor` and `LevelBelowAgreed` are raised by the SDK receive
/// path (§5.3 C4/C5); the core raises `Misrouted` for a frame of another setting.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ViolationKind {
    BelowFloor,
    LevelBelowAgreed,
    Desync,
    Misrouted,
}
