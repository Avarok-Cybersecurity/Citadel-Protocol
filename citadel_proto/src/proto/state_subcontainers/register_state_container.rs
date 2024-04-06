use citadel_io::tokio::time::Instant;

use crate::proto::packet::packet_flags;
use citadel_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use citadel_crypt::stacked_ratchet::StackedRatchet;

/// These values should correlate directly to the packet_flags::cmd::aux::do_register::*
#[derive(Default)]
pub struct RegisterState {
    pub(crate) last_stage: u8,
    pub(crate) constructor: Option<StackedRatchetConstructor>,
    pub(crate) created_hyper_ratchet: Option<StackedRatchet>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) passwordless: Option<bool>,
}

impl RegisterState {
    /// When the registration stage fails along any step, call this closure
    pub fn on_fail(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_register::FAILURE;
        self.constructor = None;
        self.on_register_packet_received();
    }

    /// At the end of every stage, this should be called
    pub fn on_register_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

impl From<u8> for RegisterState {
    fn from(stage: u8) -> Self {
        Self {
            last_stage: stage,
            ..Default::default()
        }
    }
}
