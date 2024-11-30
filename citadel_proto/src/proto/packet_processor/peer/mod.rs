//! Peer Packet Processing Module for Citadel Protocol
//!
//! This module provides the core functionality for handling peer-to-peer communication
//! in the Citadel Protocol network. It manages group broadcasts, peer commands,
//! server interactions, and signal handling between peers.
//!
//! # Features
//!
//! - Group broadcast management
//! - Peer command processing
//! - Server interaction handling
//! - Signal processing between peers
//! - Disconnect signal management
//!
//! # Important Notes
//!
//! - Requires established peer connections
//! - Handles peer session state
//! - Manages error propagation
//! - Supports ticket-based operations
//!
//! # Related Components
//!
//! - `CitadelSession`: Manages peer sessions
//! - `NodeResult`: Handles operation results
//! - `Ticket`: Tracks peer operations
//! - `NetworkError`: Manages error states

use crate::error::NetworkError;
use crate::prelude::{ConnectFail, NodeResult, Ticket};
use crate::proto::session::CitadelSession;

pub mod group_broadcast;
pub mod peer_cmd_packet;
pub mod server;
pub mod signal_handler_interface;

pub(crate) fn send_dc_signal_peer<T: Into<String>>(
    session: &CitadelSession,
    ticket: Ticket,
    err: T,
) -> Result<(), NetworkError> {
    let implicated_cid = session.implicated_cid.get().expect("Should exist");
    session
        .send_to_kernel(NodeResult::ConnectFail(ConnectFail {
            ticket,
            cid_opt: Some(implicated_cid),
            error_message: err.into(),
        }))
        .map_err(|err| NetworkError::Generic(err.to_string()))?;

    Ok(())
}
