//! Why a [`PathPolicy`](super::PathPolicy) was refused.
use super::path_policy::{PathClass, PathKind, MAX_ATTEMPT_TIMEOUT, MIN_ATTEMPT_TIMEOUT};
use std::time::Duration;

/// Why a [`PathPolicy`](super::PathPolicy) was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathPolicyError {
    /// No rule names this path.
    MissingKind(PathKind),
    /// More than one rule names this path.
    DuplicateKind(PathKind),
    /// The rule's attempt timeout is outside 1–60 s.
    TimeoutOutOfRange { kind: PathKind, timeout: Duration },
    /// The server relay must be enabled for [`PathClass::Control`]: key exchange rides it.
    ServerRelayMustCarryControl,
    /// No enabled rule carries this class, and the policy does not deny it.
    ClassUncovered(PathClass),
    /// The policy denies this class, yet an enabled rule lets it ride this path.
    DeniedClassAllowed { class: PathClass, kind: PathKind },
    /// This enabled rule comes after the server relay, which is always available, so it could
    /// never be reached.
    UnreachableAfterServerRelay(PathKind),
}

impl std::fmt::Display for PathPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKind(kind) => write!(f, "no rule for path {kind:?}"),
            Self::DuplicateKind(kind) => write!(f, "more than one rule for path {kind:?}"),
            Self::TimeoutOutOfRange { kind, timeout } => write!(
                f,
                "path {kind:?}: attempt timeout {timeout:?} is outside {MIN_ATTEMPT_TIMEOUT:?}..={MAX_ATTEMPT_TIMEOUT:?}"
            ),
            Self::ServerRelayMustCarryControl => write!(
                f,
                "the server relay must be enabled for control traffic: key exchange rides it"
            ),
            Self::ClassUncovered(class) => write!(
                f,
                "no enabled path carries {class:?} traffic, and the policy does not deny it"
            ),
            Self::DeniedClassAllowed { class, kind } => write!(
                f,
                "{class:?} traffic is denied, yet path {kind:?} allows it"
            ),
            Self::UnreachableAfterServerRelay(kind) => write!(
                f,
                "path {kind:?} is enabled after the server relay, so it can never be reached"
            ),
        }
    }
}

impl std::error::Error for PathPolicyError {}
