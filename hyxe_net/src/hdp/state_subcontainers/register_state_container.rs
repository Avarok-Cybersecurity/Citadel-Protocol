use tokio::time::Instant;

use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;

use crate::constants::DO_REGISTER_EXPIRE_TIME_MS;
use crate::hdp::hdp_packet::packet_flags;
use crate::proposed_credentials::ProposedCredentials;
use ez_pqcrypto::PostQuantumContainer;

/// These values should correlate directly to the packet_flags::cmd::aux::do_register::*
pub struct RegisterState {
    pub(crate) last_stage: u8,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) proposed_credentials: Option<ProposedCredentials>,
    pub(crate) pqc: Option<PostQuantumContainer>,
    pub(crate) proposed_cid: Option<u64>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) fail_time: Option<i64>,
    pub(crate) success_time: Option<i64>
}

impl RegisterState {
    /// When the registration stage fails along any step, call this closure
    pub fn on_fail(&mut self, fail_time: i64) {
        self.last_stage = packet_flags::cmd::aux::do_register::FAILURE;
        self.fail_time = Some(fail_time);
        self.success_time = None;
        self.pqc = None;
        self.on_register_packet_received();
    }

    /// When the registration stage succeeds, call this closure
    pub fn on_success(&mut self, success_time: i64) {
        self.last_stage = packet_flags::cmd::aux::do_register::SUCCESS;
        self.success_time = Some(success_time);
        self.pqc = None;
        self.fail_time = None;
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
        Self { pqc: None, proposed_cid: None, last_packet_time: None, last_stage: stage, nonce: None, proposed_credentials: None, fail_time: None, success_time: None }
    }
}