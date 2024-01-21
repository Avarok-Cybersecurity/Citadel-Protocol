use tokio::time::Instant;

use crate::proto::packet::packet_flags;
use citadel_types::proto::ConnectMode;
use citadel_user::auth::proposed_credentials::ProposedCredentials;

/// These values should correlate directly to the packet_flags::cmd::aux::do_connect::*
#[derive(Default)]
pub struct ConnectState {
    pub(crate) last_stage: u8,
    pub(crate) proposed_credentials: Option<ProposedCredentials>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) fail_time: Option<i64>,
    pub(crate) connect_mode: Option<ConnectMode>,
}

impl ConnectState {
    /// Whenever the connection stage fails, this should be called. Do not forget to set the session's global state too
    pub fn on_fail(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_connect::FAILURE;
        self.on_connect_packet_received();
    }

    /// Once the connection succeeds, call this closure. Do not forget to set the session's global state too
    pub fn on_success(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_connect::SUCCESS;
        self.fail_time = None;
        self.on_connect_packet_received();
    }

    /// At the end of every stage, this should be called
    pub fn on_connect_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

impl From<u8> for ConnectState {
    fn from(stage: u8) -> Self {
        Self {
            last_stage: stage,
            ..Default::default()
        }
    }
}
