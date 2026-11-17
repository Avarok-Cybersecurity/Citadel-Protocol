//! Pieces of the key-epoch test shell: its policy, the gate's view of the negotiator, helpers.

use citadel_io::tokio;
use citadel_negotiation::frame::Frame;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{Envelope, Epoch, NegotiationPolicy, Negotiator, RoundAdmission};
use citadel_sdk::prelude::negotiation::key_epoch::RoundAdmitter;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Deadlines a live link meets with room to spare; the tests never wait them out.
pub fn policy() -> NegotiationPolicy {
    NegotiationPolicy {
        proposal_deadline: Duration::from_secs(60),
        apply_deadline: Duration::from_secs(60),
        max_apply_attempts: 3,
        udp_retire_grace: None,
    }
}

pub struct Admit(pub Arc<Mutex<Negotiator<KeyProfile>>>);

impl RoundAdmitter for Admit {
    fn admit_key_round(&self, epoch: Epoch, profile: &KeyProfile) -> RoundAdmission {
        self.0.lock().unwrap().admit_key_round(epoch, profile)
    }
}

pub fn spawn(task: impl std::future::Future<Output = ()> + core::marker::Send + 'static) {
    drop(tokio::spawn(task));
}

/// Whether an envelope is the answer that agrees to a proposal.
pub fn is_accept(envelope: &Envelope) -> bool {
    matches!(envelope.frame, Frame::Accept { .. })
}
