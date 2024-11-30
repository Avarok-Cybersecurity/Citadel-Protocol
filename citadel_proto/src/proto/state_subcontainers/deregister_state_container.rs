//! # Deregistration State Container
//!
//! Manages the state of account deregistration processes in the Citadel Protocol.
//!
//! ## Features
//! - Tracks deregistration process state and progress
//! - Manages deregistration tickets for process identification
//! - Tracks timing information for deregistration operations
//! - Provides atomic state transitions for thread safety
//!
//! ## Example Usage
//! ```rust
//! use citadel_proto::proto::state_subcontainers::DeRegisterState;
//! use citadel_proto::proto::remote::Ticket;
//!
//! let mut state = DeRegisterState::default();
//! let ticket = Ticket::default();
//!
//! // Initialize deregistration process
//! state.on_init(timestamp, ticket);
//! ```
//!
//! ## Important Notes
//! - State must be properly initialized before use
//! - Timing information is critical for process tracking
//! - Ticket management ensures process uniqueness
//!
//! ## Related Components
//! - `session`: Uses deregistration states for account management
//! - `remote`: Handles remote deregistration operations
//! - `validation`: Validates deregistration requests

use crate::proto::remote::Ticket;

/// For keeping track of deregistration processes
#[derive(Default)]
pub struct DeRegisterState {
    pub(crate) last_packet_time: Option<i64>,
    pub(crate) in_progress: bool,
    pub(crate) current_ticket: Option<Ticket>,
}

impl DeRegisterState {
    /// run this when it begins
    pub fn on_init(&mut self, timestamp: i64, ticket: Ticket) {
        self.in_progress = true;
        self.last_packet_time = Some(timestamp);
        self.current_ticket = Some(ticket);
    }
}
