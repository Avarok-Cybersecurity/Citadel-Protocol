//! Node Result Types and Processing
//!
//! This module defines the result types and structures used for handling responses
//! and events in the Citadel Protocol. It provides a comprehensive set of result
//! types for managing node operations, connection states, and event handling.
//!
//! # Features
//!
//! - **Operation Results**: Registration, connection, and deregistration outcomes
//! - **Event Handling**: Peer events, group events, and mailbox deliveries
//! - **Transfer Management**: Object transfer and ReVFS operations
//! - **Error Handling**: Comprehensive error reporting and status codes
//! - **Session Management**: Session state and channel tracking
//!
//! # Important Notes
//!
//! - All results include ticket tracking for asynchronous operation matching
//! - Connection results contain security settings and channel information
//! - Object transfer results include progress tracking capabilities
//! - Error results provide detailed failure information
//!
//! # Related Components
//!
//! - `NodeRequest`: Defines corresponding request types
//! - `SessionManager`: Processes and generates results
//! - `PeerChannel`: Handles peer communication channels
//! - `GroupChannel`: Manages group communication channels
//!
use crate::prelude::{GroupBroadcast, GroupChannel, PeerChannel, PeerSignal, UdpChannel};
use crate::proto::peer::peer_layer::MailboxTransfer;
use crate::proto::remote::Ticket;
use crate::proto::state_container::VirtualConnectionType;

use crate::kernel::kernel_communicator::CallbackKey;
use citadel_crypt::prelude::CryptError;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::SessionSecuritySettings;
use citadel_user::backend::utils::ObjectTransferHandler;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct RegisterOkay {
    pub ticket: Ticket,
    pub cid: u64,
    pub welcome_message: Vec<u8>,
}

#[derive(Debug)]
pub struct RegisterFailure {
    pub ticket: Ticket,
    pub error_message: String,
}

#[derive(Debug)]
pub struct DeRegistration {
    pub session_cid: u64,
    pub ticket_opt: Option<Ticket>,
    pub success: bool,
}

#[derive(Debug)]
pub struct ConnectSuccess<R: Ratchet> {
    pub ticket: Ticket,
    pub session_cid: u64,
    pub remote_addr: SocketAddr,
    pub is_personal: bool,
    pub v_conn_type: VirtualConnectionType,
    pub services: citadel_user::external_services::ServicesObject,
    pub welcome_message: String,
    pub channel: PeerChannel<R>,
    pub udp_rx_opt: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
    pub session_security_settings: SessionSecuritySettings,
}

#[derive(Debug)]
pub struct ConnectFail {
    pub ticket: Ticket,
    pub cid_opt: Option<u64>,
    pub error_message: String,
}

#[derive(Debug)]
pub struct ReKeyResult {
    pub ticket: Ticket,
    pub status: ReKeyReturnType,
    pub session_cid: u64,
}

#[derive(Debug)]
pub enum ReKeyReturnType {
    Success { version: u32 },
    AlreadyInProgress,
    Failure { err: CryptError },
}

#[derive(Debug)]
pub struct OutboundRequestRejected {
    pub ticket: Ticket,
    pub message_opt: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ObjectTransferHandle {
    pub ticket: Ticket,
    pub handle: ObjectTransferHandler,
    pub session_cid: u64,
}

#[derive(Debug)]
pub struct MailboxDelivery {
    pub session_cid: u64,
    pub ticket_opt: Option<Ticket>,
    pub items: MailboxTransfer,
}

#[derive(Debug)]
pub struct PeerEvent {
    pub event: PeerSignal,
    pub ticket: Ticket,
    pub session_cid: u64,
}

#[derive(Debug)]
pub struct GroupChannelCreated {
    pub ticket: Ticket,
    pub channel: GroupChannel,
    pub session_cid: u64,
}

#[derive(Debug)]
pub struct GroupEvent {
    pub session_cid: u64,
    pub ticket: Ticket,
    pub event: GroupBroadcast,
}

#[derive(Debug)]
pub struct Disconnect {
    pub ticket: Ticket,
    pub cid_opt: Option<u64>,
    pub success: bool,
    pub v_conn_type: Option<VirtualConnectionType>,
    pub message: String,
}

#[derive(Debug)]
pub struct InternalServerError {
    pub ticket_opt: Option<Ticket>,
    pub message: String,
    pub cid_opt: Option<u64>,
}

#[derive(Debug)]
pub struct PeerChannelCreated<R: Ratchet> {
    pub ticket: Ticket,
    pub channel: PeerChannel<R>,
    pub udp_rx_opt: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
}

#[derive(Debug)]
pub struct SessionList {
    pub ticket: Ticket,
    pub sessions: Vec<u64>,
}

#[derive(Debug)]
pub struct ReVFSResult {
    pub error_message: Option<String>,
    pub data: Option<PathBuf>,
    pub ticket: Ticket,
    pub session_cid: u64,
}

/// This type is for relaying results between the lower-level protocol and the higher-level kernel
#[derive(Debug)]
pub enum NodeResult<R: Ratchet> {
    /// Returns the CNAC which was created during the registration process
    RegisterOkay(RegisterOkay),
    /// The registration was a failure
    RegisterFailure(RegisterFailure),
    /// When de-registration occurs. Third is_personal, Fourth is true if success, false otherwise
    DeRegistration(DeRegistration),
    /// Connection succeeded for the cid self.0. bool is "is personal"
    ConnectSuccess(ConnectSuccess<R>),
    /// The connection was a failure
    ConnectFail(ConnectFail),
    ReKeyResult(ReKeyResult),
    ReVFS(ReVFSResult),
    /// The outbound request was rejected
    OutboundRequestRejected(OutboundRequestRejected),
    /// For file transfers. Implicated CID, Peer/Target CID, object ID
    ObjectTransferHandle(ObjectTransferHandle),
    /// Mailbox
    MailboxDelivery(MailboxDelivery),
    /// Peer result
    PeerEvent(PeerEvent),
    /// For denoting a channel was created
    GroupChannelCreated(GroupChannelCreated),
    /// for group-related events. Implicated cid, ticket, group info
    GroupEvent(GroupEvent),
    /// vt-cxn-type is optional, because it may have only been a provisional connection
    Disconnect(Disconnect),
    /// An internal error occurred
    InternalServerError(InternalServerError),
    /// A channel was created, with channel_id = ticket (same as post-connect ticket received)
    PeerChannelCreated(PeerChannelCreated<R>),
    /// A list of running sessions
    SessionList(SessionList),
    /// For shutdowns
    Shutdown,
}

impl<R: Ratchet> NodeResult<R> {
    pub fn is_connect_success_type(&self) -> bool {
        matches!(self, NodeResult::ConnectSuccess(ConnectSuccess { .. }))
    }

    pub fn callback_key(&self) -> Option<CallbackKey> {
        match self {
            NodeResult::RegisterOkay(RegisterOkay {
                ticket: t,
                cid,
                welcome_message: _,
            }) => Some(CallbackKey::new(*t, *cid)),
            NodeResult::RegisterFailure(RegisterFailure {
                ticket: t,
                error_message: _,
            }) => Some(CallbackKey::ticket_only(*t)),
            NodeResult::DeRegistration(DeRegistration {
                session_cid,
                ticket_opt: t,
                ..
            }) => Some(CallbackKey::new((*t)?, *session_cid)),
            NodeResult::ConnectSuccess(ConnectSuccess {
                ticket: t,
                session_cid,
                ..
            }) => Some(CallbackKey::new(*t, *session_cid)),
            NodeResult::ConnectFail(ConnectFail {
                ticket: t,
                cid_opt,
                error_message: _,
            }) => Some(CallbackKey {
                ticket: *t,
                session_cid: *cid_opt,
            }),
            NodeResult::OutboundRequestRejected(OutboundRequestRejected {
                ticket: t,
                message_opt: _,
            }) => Some(CallbackKey::ticket_only(*t)),
            NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                session_cid,
                ticket,
                ..
            }) => Some(CallbackKey::new(*ticket, *session_cid)),
            NodeResult::MailboxDelivery(MailboxDelivery {
                session_cid,
                ticket_opt: t,
                items: _,
            }) => Some(CallbackKey::new((*t)?, *session_cid)),
            NodeResult::PeerEvent(PeerEvent {
                event: _,
                ticket: t,
                session_cid,
            }) => Some(CallbackKey::new(*t, *session_cid)),
            NodeResult::GroupEvent(GroupEvent {
                session_cid,
                ticket: t,
                event: _,
            }) => Some(CallbackKey::new(*t, *session_cid)),
            NodeResult::PeerChannelCreated(PeerChannelCreated {
                ticket: t, channel, ..
            }) => Some(CallbackKey::new(*t, channel.get_session_cid())),
            NodeResult::GroupChannelCreated(GroupChannelCreated {
                ticket: t,
                channel: _,
                session_cid,
            }) => Some(CallbackKey::new(*t, *session_cid)),
            NodeResult::Disconnect(Disconnect {
                ticket: t,
                cid_opt,
                success: _,
                v_conn_type: _,
                message: _,
            }) => Some(CallbackKey {
                ticket: *t,
                session_cid: *cid_opt,
            }),
            NodeResult::InternalServerError(InternalServerError {
                ticket_opt: t,
                cid_opt,
                message: _,
            }) => Some(CallbackKey {
                ticket: (*t)?,
                session_cid: *cid_opt,
            }),
            NodeResult::SessionList(SessionList {
                ticket: t,
                sessions: _,
            }) => Some(CallbackKey::ticket_only(*t)),
            NodeResult::Shutdown => None,
            NodeResult::ReKeyResult(ReKeyResult {
                ticket,
                session_cid,
                ..
            }) => Some(CallbackKey::new(*ticket, *session_cid)),
            NodeResult::ReVFS(ReVFSResult {
                ticket,
                session_cid,
                ..
            }) => Some(CallbackKey::new(*ticket, *session_cid)),
        }
    }
}
