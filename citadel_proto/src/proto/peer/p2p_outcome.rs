//! What each P2P upgrade attempt did: which path won, how long it took, and why every stage that
//! did not connect failed or was not tried. One [`PathAttemptOutcome`] is published per attempt,
//! on the connection's path cell (`PeerChannel::path_outcomes`) and to the kernel as
//! [`NodeResult::PeerPathOutcome`](crate::proto::node_result::NodeResult::PeerPathOutcome).
//! Measurement only: nothing here changes how a connection is established.

use std::fmt;
use std::time::Duration;

use citadel_wire::nat_class::NatClass;

use super::p2p_path::{P2pPath, P2pRoute};
use crate::proto::remote::Ticket;

/// A stage of an upgrade attempt, in the order an attempt runs them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PathStage {
    /// The peers meeting over the server relay before a punch: registering the coordination
    /// endpoint (before the first attempt) or the rendezvous of a retry.
    Coordination,
    /// The UDP hole punch and the QUIC handshake over it (a WebRTC DataChannel on WASM).
    Direct,
    /// The QUIC connection through a TURN relay.
    Turn,
}

/// Why a stage did not connect. Paired with its [`PathStage`], which says where.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StageFailure {
    /// Not tried: both NATs are unpredictable, so a hole punch cannot work.
    NatIncompatible,
    /// Not tried: the TURN policy is relay-only.
    SkippedByPolicy,
    /// Not tried: no TURN config was supplied for this connection.
    NotConfigured,
    /// The hole punch found no working pair of addresses.
    PunchFailed,
    /// No TURN server granted this node an allocation.
    AllocationFailed,
    /// The peer had no TURN allocation to offer.
    PeerUnavailable,
    /// A TURN permission or channel binding was refused.
    PermissionFailed,
    /// Probes through the relay went unanswered.
    ProbeFailed,
    /// Coordinating with the peer over the server relay failed (an endpoint, a message or a sync).
    Signalling,
    /// The QUIC handshake over the punched or relayed path failed.
    HandshakeFailed,
    /// A connection was made but could not become the connection's route.
    AttachFailed,
    /// A local socket could not be opened.
    LocalSocket,
    /// The stage ran out of time.
    Timeout,
    /// The session ended during the stage.
    SessionGone,
    /// This platform cannot run the stage.
    Unsupported,
}

/// How one stage of an attempt ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StageOutcome {
    pub stage: PathStage,
    pub result: Result<(), StageFailure>,
    /// Zero for a stage that was not tried.
    pub elapsed: Duration,
}

/// Which paths an attempt was planned to try.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathPlanKind {
    DirectOnly,
    DirectThenTurn,
    TurnOnly,
    ServerOnly,
}

/// One upgrade attempt of a P2P connection's background campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathAttemptOutcome {
    pub peer_cid: u64,
    /// 1 for the campaign's first attempt; every retry (after a lost route or a re-arm) adds one.
    pub attempt: u32,
    pub plan: PathPlanKind,
    /// The path the attempt attached, or [`P2pPath::ServerRelay`] when it attached none.
    pub path: P2pPath,
    /// On a [`P2pPath::Turn`] path, whether both peers relay through their own allocation.
    pub relayed_both: bool,
    /// Every stage, in [`PathStage`] order, including those not tried (with the reason).
    pub stages: Vec<StageOutcome>,
    pub local_nat: NatClass,
    pub peer_nat: NatClass,
}

impl PathAttemptOutcome {
    /// From the start of the attempt's coordination to its route attaching; `None` when it
    /// attached none.
    pub fn time_to_connect(&self) -> Option<Duration> {
        (self.path != P2pPath::ServerRelay).then(|| self.stages.iter().map(|s| s.elapsed).sum())
    }

    /// The failure of `stage`, if it failed or was not tried.
    pub fn failure(&self, stage: PathStage) -> Option<StageFailure> {
        self.stages
            .iter()
            .find(|s| s.stage == stage)
            .and_then(|s| s.result.err())
    }
}

/// The kernel's copy of an attempt's outcome, named by session and connection.
#[derive(Clone, Debug)]
pub struct PeerPathOutcome {
    pub session_cid: u64,
    /// The connection this attempt belongs to (`PeerChannel::connection_id`).
    pub connection_id: Option<Ticket>,
    pub outcome: PathAttemptOutcome,
}

/// What the platform's upgrade attempt ran, and the route it attached (`PlatformOps`'s answer;
/// applications read [`PathAttemptOutcome`]).
#[doc(hidden)]
#[derive(Debug)]
pub struct AttemptReport {
    pub(crate) stages: Vec<StageOutcome>,
    pub(crate) route: Option<P2pRoute>,
}

impl AttemptReport {
    pub(crate) fn nothing_attached(stages: Vec<StageOutcome>) -> Self {
        Self {
            stages,
            route: None,
        }
    }
}

/// A stage's failure, with the detail for the log.
pub(crate) struct StageError {
    pub(crate) failure: StageFailure,
    pub(crate) detail: String,
}

impl StageError {
    pub(crate) fn new(failure: StageFailure, detail: impl Into<String>) -> Self {
        Self {
            failure,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.failure, self.detail)
    }
}

/// Classifies an error as the failure of a stage.
pub(crate) trait AtStage<T> {
    fn at(self, failure: StageFailure) -> Result<T, StageError>;
}

impl<T, E: fmt::Display> AtStage<T> for Result<T, E> {
    fn at(self, failure: StageFailure) -> Result<T, StageError> {
        self.map_err(|err| StageError {
            failure,
            detail: err.to_string(),
        })
    }
}

pub(crate) use super::p2p_outcome_context::{tried, OutcomeContext};

#[cfg(test)]
#[path = "p2p_outcome_tests.rs"]
mod tests;
