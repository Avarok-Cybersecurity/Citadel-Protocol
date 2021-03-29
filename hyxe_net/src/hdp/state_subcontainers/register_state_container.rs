use tokio::time::Instant;

use crate::constants::DO_REGISTER_EXPIRE_TIME_MS;
use crate::hdp::hdp_packet::packet_flags;
use hyxe_user::proposed_credentials::ProposedCredentials;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
use hyxe_crypt::hyper_ratchet::HyperRatchet;

/// These values should correlate directly to the packet_flags::cmd::aux::do_register::*
#[derive(Default)]
pub struct RegisterState {
    pub(crate) last_stage: u8,
    pub(crate) proposed_credentials: Option<ProposedCredentials>,
    pub(crate) constructor: Option<HyperRatchetConstructor>,
    pub(crate) created_hyper_ratchet: Option<HyperRatchet>,
    pub(crate) proposed_cid: Option<u64>,
    pub(crate) last_packet_time: Option<Instant>
}

impl RegisterState {
    /// When the registration stage fails along any step, call this closure
    pub fn on_fail(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_register::FAILURE;
        self.constructor = None;
        self.on_register_packet_received();
    }

    /// When the registration stage succeeds, call this closure
    pub fn on_success(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_register::SUCCESS;
        self.constructor = None;
        self.on_register_packet_received();
    }

    /// At the end of every stage, this should be called
    pub fn on_register_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }

    /// This should be periodically called by the session event loop
    pub fn has_expired(&self) -> bool {
        if let Some(prev_interaction) = self.last_packet_time.as_ref() {
            prev_interaction.elapsed() > DO_REGISTER_EXPIRE_TIME_MS
        } else {
            false
        }
    }
}

impl From<u8> for RegisterState {
    fn from(stage: u8) -> Self {
        Self { last_stage: stage, ..Default::default() }
    }
}