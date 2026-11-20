//! The protocol's stage failures as the link core names them.

use citadel_link::StageFailure;

use crate::proto::peer::p2p_outcome::StageError;

/// The protocol's stage failure as the link core names it (the same variants, §6.1).
pub(crate) fn link_failure(err: StageError) -> StageFailure {
    use crate::proto::peer::p2p_outcome::StageFailure as P;
    match err.failure {
        P::NatIncompatible => StageFailure::NatIncompatible,
        P::SkippedByPolicy => StageFailure::SkippedByPolicy,
        P::NotConfigured => StageFailure::NotConfigured,
        P::PunchFailed => StageFailure::PunchFailed,
        P::AllocationFailed => StageFailure::AllocationFailed,
        P::PeerUnavailable => StageFailure::PeerUnavailable,
        P::PermissionFailed => StageFailure::PermissionFailed,
        P::ProbeFailed => StageFailure::ProbeFailed,
        P::Signalling => StageFailure::Signalling,
        P::HandshakeFailed => StageFailure::HandshakeFailed,
        P::AttachFailed => StageFailure::AttachFailed,
        P::LocalSocket => StageFailure::LocalSocket,
        P::Timeout => StageFailure::Timeout,
        P::SessionGone => StageFailure::SessionGone,
        P::Unsupported => StageFailure::Unsupported,
    }
}
