use crate::prelude::{
    GroupBroadcast, GroupChannel, PeerChannel, PeerSignal, SessionSecuritySettings, UdpChannel,
};
use crate::proto::peer::peer_layer::MailboxTransfer;
use crate::proto::remote::Ticket;
use crate::proto::state_container::VirtualConnectionType;

use citadel_user::backend::utils::ObjectTransferHandler;
use citadel_user::client_account::ClientNetworkAccount;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct RegisterOkay {
    pub ticket: Ticket,
    pub cnac: ClientNetworkAccount,
    pub welcome_message: Vec<u8>,
}

#[derive(Debug)]
pub struct RegisterFailure {
    pub ticket: Ticket,
    pub error_message: String,
}

#[derive(Debug)]
pub struct DeRegistration {
    pub implicated_cid: u64,
    pub ticket_opt: Option<Ticket>,
    pub success: bool,
}

#[derive(Debug)]
pub struct ConnectSuccess {
    pub ticket: Ticket,
    pub implicated_cid: u64,
    pub remote_addr: SocketAddr,
    pub is_personal: bool,
    pub v_conn_type: VirtualConnectionType,
    pub services: citadel_user::external_services::ServicesObject,
    pub welcome_message: String,
    pub channel: PeerChannel,
    pub udp_rx_opt: Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
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
}

#[derive(Debug)]
pub enum ReKeyReturnType {
    Success { version: u32 },
    AlreadyInProgress,
    Failure,
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
}

#[derive(Debug)]
pub struct MailboxDelivery {
    pub implicated_cid: u64,
    pub ticket_opt: Option<Ticket>,
    pub items: MailboxTransfer,
}

#[derive(Debug)]
pub struct PeerEvent {
    pub event: PeerSignal,
    pub ticket: Ticket,
}

#[derive(Debug)]
pub struct GroupChannelCreated {
    pub ticket: Ticket,
    pub channel: GroupChannel,
}

#[derive(Debug)]
pub struct GroupEvent {
    pub implicated_cid: u64,
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
}

#[derive(Debug)]
pub struct PeerChannelCreated {
    pub ticket: Ticket,
    pub channel: PeerChannel,
    pub udp_rx_opt: Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
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
}

/// This type is for relaying results between the lower-level protocol and the higher-level kernel
#[derive(Debug)]
pub enum NodeResult {
    /// Returns the CNAC which was created during the registration process
    RegisterOkay(RegisterOkay),
    /// The registration was a failure
    RegisterFailure(RegisterFailure),
    /// When de-registration occurs. Third is_personal, Fourth is true if success, false otherwise
    DeRegistration(DeRegistration),
    /// Connection succeeded for the cid self.0. bool is "is personal"
    ConnectSuccess(ConnectSuccess),
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
    PeerChannelCreated(PeerChannelCreated),
    /// A list of running sessions
    SessionList(SessionList),
    /// For shutdowns
    Shutdown,
}

impl NodeResult {
    pub fn is_connect_success_type(&self) -> bool {
        matches!(self, NodeResult::ConnectSuccess(ConnectSuccess { .. }))
    }

    pub fn ticket(&self) -> Option<Ticket> {
        match self {
            NodeResult::RegisterOkay(RegisterOkay {
                ticket: t,
                cnac: _,
                welcome_message: _,
            }) => Some(*t),
            NodeResult::RegisterFailure(RegisterFailure {
                ticket: t,
                error_message: _,
            }) => Some(*t),
            NodeResult::DeRegistration(DeRegistration {
                implicated_cid: _,
                ticket_opt: t,
                ..
            }) => *t,
            NodeResult::ConnectSuccess(ConnectSuccess { ticket: t, .. }) => Some(*t),
            NodeResult::ConnectFail(ConnectFail {
                ticket: t,
                cid_opt: _,
                error_message: _,
            }) => Some(*t),
            NodeResult::OutboundRequestRejected(OutboundRequestRejected {
                ticket: t,
                message_opt: _,
            }) => Some(*t),
            NodeResult::ObjectTransferHandle(ObjectTransferHandle { ticket: t, .. }) => Some(*t),
            NodeResult::MailboxDelivery(MailboxDelivery {
                implicated_cid: _,
                ticket_opt: t,
                items: _,
            }) => *t,
            NodeResult::PeerEvent(PeerEvent {
                event: _,
                ticket: t,
            }) => Some(*t),
            NodeResult::GroupEvent(GroupEvent {
                implicated_cid: _,
                ticket: t,
                event: _,
            }) => Some(*t),
            NodeResult::PeerChannelCreated(PeerChannelCreated { ticket: t, .. }) => Some(*t),
            NodeResult::GroupChannelCreated(GroupChannelCreated {
                ticket: t,
                channel: _,
            }) => Some(*t),
            NodeResult::Disconnect(Disconnect {
                ticket: t,
                cid_opt: _,
                success: _,
                v_conn_type: _,
                message: _,
            }) => Some(*t),
            NodeResult::InternalServerError(InternalServerError {
                ticket_opt: t,
                message: _,
            }) => *t,
            NodeResult::SessionList(SessionList {
                ticket: t,
                sessions: _,
            }) => Some(*t),
            NodeResult::Shutdown => None,
            NodeResult::ReKeyResult(ReKeyResult { ticket, .. }) => Some(*ticket),
            NodeResult::ReVFS(ReVFSResult { ticket, .. }) => Some(*ticket),
        }
    }
}
