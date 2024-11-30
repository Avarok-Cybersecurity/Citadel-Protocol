//! # Connect State Container
//!
//! Manages the state of active connections in the Citadel Protocol, tracking connection stages,
//! credentials, and timing information.
//!
//! ## Features
//! - Stage-based connection management with transition tracking
//! - Credential handling for authentication processes
//! - Connection timing and failure monitoring
//! - Support for different connection modes
//! - State recovery mechanisms for connection resilience
//!
//! ## Example Usage
//! ```rust
//! use citadel_proto::proto::state_subcontainers::ConnectState;
//!
//! // Create new connection state
//! let mut state = ConnectState::default();
//!
//! // Handle successful connection
//! state.on_success();
//! state.on_connect_packet_received();
//!
//! // Handle connection failure
//! state.on_fail();
//! state.on_connect_packet_received();
//! ```
//!
//! ## Important Notes
//! - State transitions must update both local and global session state
//! - Packet timing is tracked for timeout management
//! - Connection modes affect behavior and security settings
//! - Failure states include timing information for recovery
//!
//! ## Related Components
//! - `packet_processor`: Uses connection states for packet handling
//! - `session`: Manages overall session state
//! - `peer`: Uses connection states for peer management
//! - `remote`: Handles remote connection states

use citadel_io::tokio::time::Instant;

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
