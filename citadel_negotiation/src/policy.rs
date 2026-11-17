//! The negotiator's timing and retry bounds. Required at construction; there are no defaults
//! (PCND): the agent reads them from its config and hands them to the SDK adapter (D6).

use std::time::Duration;

/// Deadlines and bounds for one negotiator. Every field must be given explicitly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NegotiationPolicy {
    /// How long a proposal may wait for the peer's answer. The peer answers on receipt, so
    /// silence past this means the lane is broken; the negotiator then falls back.
    pub proposal_deadline: Duration,
    /// How long one apply attempt (a key round, or a local apply) and the confirmation that
    /// follows it may take before the negotiator falls back.
    pub apply_deadline: Duration,
    /// How many key rounds one agreed profile may take when plain rekeys keep superseding it.
    pub max_apply_attempts: u8,
    /// How long the media (UDP) floor is held back after `Retire`. `None` drops late old-epoch
    /// media at once (owner decision D5). The core only carries it; the SDK receive path uses it.
    pub udp_retire_grace: Option<Duration>,
}

/// A policy that cannot bound the negotiator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    ZeroProposalDeadline,
    ZeroApplyDeadline,
    ZeroApplyAttempts,
}

impl NegotiationPolicy {
    /// Fails fast on a policy that would let a state wait forever or never apply.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.proposal_deadline.is_zero() {
            return Err(PolicyError::ZeroProposalDeadline);
        }
        if self.apply_deadline.is_zero() {
            return Err(PolicyError::ZeroApplyDeadline);
        }
        if self.max_apply_attempts == 0 {
            return Err(PolicyError::ZeroApplyAttempts);
        }
        Ok(())
    }
}
