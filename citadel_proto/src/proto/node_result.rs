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
use crate::error::NetworkError;
use crate::prelude::{GroupBroadcast, GroupChannel, PeerChannel, PeerSignal, UdpChannel};
use crate::proto::disconnect_tracker::DisconnectToken;
use crate::proto::peer::peer_layer::MailboxTransfer;
use crate::proto::remote::Ticket;
use crate::proto::state_container::VirtualConnectionType;

use crate::kernel::kernel_communicator::CallbackKey;
use citadel_crypt::prelude::CryptError;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{ClientConnectionType, SessionSecuritySettings};
use citadel_user::auth::pq::admission::AdmissionChallenge;
use citadel_user::backend::utils::ObjectTransferHandler;
use citadel_wire::nat_identification::NatType;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct RegisterOkay {
    pub ticket: Ticket,
    pub cid: u64,
    pub welcome_message: Vec<u8>,
    /// The new account's recovery phrase, 24 words, when the registration was given the server's
    /// domain (`RegisterToHypernode::recovery_domain`). Show it to the user now: the client
    /// generated it, the server holds only its key, and nothing keeps it.
    pub recovery_phrase: Option<Vec<String>>,
}

/// A recovery succeeded: this device now holds the account's only bundle. Sign in with the
/// phrase next, to a session that may manage the account's credentials.
#[derive(Debug)]
pub struct RecoverOkay {
    pub ticket: Ticket,
    pub cid: u64,
}

#[derive(Debug)]
pub struct RegisterFailure {
    pub ticket: Ticket,
    pub error_message: String,
    /// The check to complete before trying again, when the server's admission refusal sent one
    /// (public: see `citadel_user::auth::pq::admission::AdmissionChallenge`).
    pub admission_challenge: Option<AdmissionChallenge>,
    /// The failure's stable error code, when the side that failed sent one (every post-quantum
    /// registration's refusal does), or when it failed on this side.
    pub error_code: Option<u16>,
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
    pub channel: Box<PeerChannel<R>>,
    pub udp_rx_opt: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
    pub session_security_settings: SessionSecuritySettings,
    /// The server's path policy: on a client, as the server sent it (`None` when it sent none, or
    /// one that failed validation); on the server, its own.
    pub path_policy: Option<citadel_types::proto::PathPolicy>,
    /// On a client: the resume credential this sign-in was granted (see
    /// `citadel_user::auth::pq::resume`). `None` when it asked for none, the server issues none,
    /// or the sign-in was itself a resume, whose credential stays as it was.
    pub resume: Option<citadel_user::auth::pq::resume::ResumeCredential>,
    /// On a client: the longest a resume credential may live on this server, in seconds; `None`
    /// when the server issues none.
    pub resume_max_lifetime_s: Option<u64>,
}

#[derive(Debug)]
pub struct ConnectFail {
    pub ticket: Ticket,
    pub cid_opt: Option<u64>,
    pub error_message: String,
    /// As [`RegisterFailure::admission_challenge`].
    pub admission_challenge: Option<AdmissionChallenge>,
    /// The refusal's stable error code (`ErrorCode`), when the refusing side named one: what a
    /// caller matches on, in place of `error_message`.
    pub error_code: Option<u16>,
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

// ClientConnectionType is imported from citadel_types::proto

#[derive(Debug)]
pub struct Disconnect {
    pub ticket: Ticket,
    pub cid_opt: Option<u64>,
    pub success: bool,
    /// The type of client connection being disconnected.
    /// None only for provisional connections that never fully established.
    pub conn_type: Option<ClientConnectionType>,
    pub message: String,
    /// Token identifying the specific C2S session instance.
    /// Used to reject stale disconnect signals from previous sessions.
    pub disconnect_token: Option<DisconnectToken>,
    /// Why the link closed, when the protocol knows (`citadel_link::CloseReason`): this node
    /// disconnected or abandoned it on purpose. `None` is a link that was lost, or ended in a way
    /// this node cannot attribute; it never stands for a deliberate close.
    pub reason: Option<citadel_link::CloseReason>,
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
    pub channel: Box<PeerChannel<R>>,
    pub udp_rx_opt: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// If None, this is a c2s connection. Else, a p2p connection.
    pub peer_cid: Option<u64>,
    /// The NAT type of the adjacent peer, if known
    pub adjacent_nat_type: Option<NatType>,
    pub connection_type: VirtualConnectionType,
    pub connected: bool,
    /// Returns effectively the number of re-keys in the session minus 1 (version starts at 0)
    pub latest_ratchet_version: u32,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub cid: u64,
    pub connections: Vec<ConnectionInfo>,
}

#[derive(Debug)]
pub struct ActiveSessions {
    pub sessions: Vec<SessionInfo>,
    pub local_nat_type: NatType,
}

#[derive(Debug)]
pub struct SessionList {
    pub ticket: Ticket,
    pub sessions: ActiveSessions,
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
    /// The registration (or a recovery) was a failure
    RegisterFailure(RegisterFailure),
    /// A recovery installed this device's bundle
    RecoverOkay(RecoverOkay),
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
    /// How a server liveness probe ended
    ServerProbe(crate::proto::server_probe::ServerProbeResult),
    /// How one background P2P upgrade attempt ended (which path won, and why the others did
    /// not). Unsolicited, one per attempt; a kernel that does not measure paths can ignore it.
    PeerPathOutcome(crate::proto::peer::p2p_outcome::PeerPathOutcome),
    /// For shutdowns
    Shutdown,
}

impl<R: Ratchet> NodeResult<R> {
    /// Used to map error result types into hard errors
    pub fn into_result(self) -> Result<NodeResult<R>, NetworkError> {
        match self {
            NodeResult::ConnectFail(ConnectFail {
                ticket: _,
                cid_opt: _,
                error_message: err,
                admission_challenge,
                error_code,
            }) => Err(
                // As a registration's: the code the refusing side sent, unless it names nothing
                // more than the text does.
                match error_code
                    .map(|code| NetworkError::from_wire(code, err.clone()))
                    .filter(|wired| wired.code() != citadel_io::ErrorCode::Generic)
                {
                    Some(wired) if admission_challenge.is_none() => wired,
                    _ => refused(err, admission_challenge),
                },
            ),
            NodeResult::RegisterFailure(RegisterFailure {
                ticket: _,
                error_message: err,
                admission_challenge,
                error_code,
            }) => Err(
                // The code the failing side sent, unless it names nothing more than the text
                // does; then the text is read as `refused` reads it.
                match error_code
                    .map(|code| NetworkError::from_wire(code, err.clone()))
                    .filter(|wired| wired.code() != citadel_io::ErrorCode::Generic)
                {
                    Some(wired) if admission_challenge.is_none() => wired,
                    _ => refused(err, admission_challenge),
                },
            ),
            NodeResult::OutboundRequestRejected(reason) => Err(NetworkError::generic(format!(
                "Outbound request rejected: {:?}",
                String::from_utf8(reason.message_opt.unwrap_or_default())
                    .unwrap_or_else(|_| "Bad request".into())
            ))),
            NodeResult::InternalServerError(InternalServerError {
                ticket_opt: _,
                cid_opt: _,
                message: err,
            }) if crate::proto::link::is_login_deadline(&err) => {
                Err(crate::proto::link::login_deadline_error())
            }
            NodeResult::InternalServerError(InternalServerError {
                ticket_opt: _,
                cid_opt: _,
                message: err,
            }) => Err(NetworkError::generic(err)),
            NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::SignalError {
                        ticket: _,
                        error: err,
                        peer_connection_type: _,
                    },
                ..
            }) => Err(NetworkError::generic(err)),
            res => Ok(res),
        }
    }

    pub fn is_connect_success_type(&self) -> bool {
        matches!(self, NodeResult::ConnectSuccess(ConnectSuccess { .. }))
    }

    pub fn callback_key(&self) -> Option<CallbackKey> {
        match self {
            NodeResult::RegisterOkay(RegisterOkay { ticket: t, cid, .. }) => {
                Some(CallbackKey::new(*t, *cid))
            }
            NodeResult::RegisterFailure(RegisterFailure { ticket: t, .. }) => {
                Some(CallbackKey::ticket_only(*t))
            }
            NodeResult::RecoverOkay(RecoverOkay { ticket: t, cid }) => {
                Some(CallbackKey::new(*t, *cid))
            }
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
                ticket: t, cid_opt, ..
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
                ticket: t, cid_opt, ..
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
            NodeResult::ServerProbe(crate::proto::server_probe::ServerProbeResult {
                ticket,
                session_cid,
                ..
            }) => Some(CallbackKey::new(*ticket, *session_cid)),
            NodeResult::Shutdown | NodeResult::PeerPathOutcome(_) => None,
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

/// A connect or register FAILURE as an error: with its admission code (and, on a required check,
/// its challenge) when the server's admission check refused it
/// (`citadel_user::auth::pq::admission`), generic otherwise.
fn refused(message: String, challenge: Option<AdmissionChallenge>) -> NetworkError {
    // A server holding the account's session refuses with this reason, verbatim, at SYN and at
    // STAGE0, in every version; named here once, so a caller matches a code, not a string (S-C8).
    if message.starts_with(crate::proto::session_manager::SESSION_ALREADY_CONNECTED) {
        return citadel_io::error!(citadel_io::ErrorCode::RemoteServerHoldsSession, message);
    }
    citadel_user::auth::pq::admission::refusal_from_message(&message, challenge)
        .unwrap_or_else(|| NetworkError::generic(message))
}
