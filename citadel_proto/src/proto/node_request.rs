use crate::auth::AuthenticationRequest;
use crate::prelude::{GroupBroadcast, PeerSignal, VirtualTargetType};
use crate::proto::state_container::VirtualConnectionType;
use citadel_crypt::streaming_crypt_scrambler::ObjectSource;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::TransferType;
use citadel_types::proto::{ConnectMode, SessionSecuritySettings, UdpMode};
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::path::PathBuf;

pub struct RegisterToHypernode {
    pub remote_addr: SocketAddr,
    pub proposed_credentials: ProposedCredentials,
    pub static_security_settings: SessionSecuritySettings,
}

pub struct PeerCommand {
    pub implicated_cid: u64,
    pub command: PeerSignal,
}

pub struct DeregisterFromHypernode {
    pub implicated_cid: u64,
    pub v_conn_type: VirtualConnectionType,
}

pub struct ConnectToHypernode {
    pub auth_request: AuthenticationRequest,
    pub connect_mode: ConnectMode,
    pub udp_mode: UdpMode,
    pub keep_alive_timeout: Option<u64>,
    pub session_security_settings: SessionSecuritySettings,
}

pub struct ReKey {
    pub v_conn_type: VirtualTargetType,
}

// Also used for updating objects
pub struct SendObject {
    pub source: Box<dyn ObjectSource>,
    pub chunk_size: Option<usize>,
    pub implicated_cid: u64,
    pub v_conn_type: VirtualTargetType,
    pub transfer_type: TransferType,
}

pub struct PullObject {
    pub v_conn: VirtualConnectionType,
    pub virtual_dir: PathBuf,
    pub delete_on_pull: bool,
    pub transfer_security_level: SecurityLevel,
}

pub struct DeleteObject {
    pub v_conn: VirtualConnectionType,
    pub virtual_dir: PathBuf,
    pub security_level: SecurityLevel,
}

pub struct GroupBroadcastCommand {
    pub implicated_cid: u64,
    pub command: GroupBroadcast,
}

pub struct DisconnectFromHypernode {
    pub implicated_cid: u64,
}

/// These are sent down the stack into the server. Most of the requests expect a ticket ID
/// in order for processes sitting above the [Kernel] to know how the request went
#[allow(variant_size_differences)]
pub enum NodeRequest {
    /// Sends a request to the underlying HdpSessionManager to begin connecting to a new client
    RegisterToHypernode(RegisterToHypernode),
    /// A high-level peer command. Can be used to facilitate communications between nodes in the HyperLAN
    PeerCommand(PeerCommand),
    /// For submitting a de-register request
    DeregisterFromHypernode(DeregisterFromHypernode),
    /// Implicated CID, creds, connect mode, fcm keys, TCP/TLS only, keep alive timeout, security settings
    ConnectToHypernode(ConnectToHypernode),
    /// Updates the drill for the given CID
    ReKey(ReKey),
    /// Sends or updates a file
    SendObject(SendObject),
    /// Pulls a file from the remote virtual encrypted filesystem
    PullObject(PullObject),
    /// Deletes a file from the remote virtual encrypted filesystem
    DeleteObject(DeleteObject),
    /// A group-message related command
    GroupBroadcastCommand(GroupBroadcastCommand),
    /// Tells the server to disconnect a session (implicated cid, target_cid)
    DisconnectFromHypernode(DisconnectFromHypernode),
    /// Returns a list of connected sessions
    GetActiveSessions,
    /// shutdown signal
    Shutdown,
}

impl NodeRequest {
    pub fn implicated_cid(&self) -> Option<u64> {
        match self {
            NodeRequest::RegisterToHypernode(_) => None,
            NodeRequest::PeerCommand(PeerCommand { implicated_cid, .. }) => Some(*implicated_cid),
            NodeRequest::DeregisterFromHypernode(DeregisterFromHypernode {
                implicated_cid,
                ..
            }) => Some(*implicated_cid),
            NodeRequest::ConnectToHypernode(connect) => connect.auth_request.implicated_cid(),
            NodeRequest::ReKey(rk) => Some(rk.v_conn_type.get_implicated_cid()),
            NodeRequest::SendObject(SendObject { implicated_cid, .. }) => Some(*implicated_cid),
            NodeRequest::PullObject(pull) => Some(pull.v_conn.get_implicated_cid()),
            NodeRequest::DeleteObject(del) => Some(del.v_conn.get_implicated_cid()),
            NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
                implicated_cid, ..
            }) => Some(*implicated_cid),
            NodeRequest::DisconnectFromHypernode(DisconnectFromHypernode { implicated_cid }) => {
                Some(*implicated_cid)
            }
            NodeRequest::GetActiveSessions => None,
            NodeRequest::Shutdown => None,
        }
    }
}

impl Debug for NodeRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeRequest")
    }
}
