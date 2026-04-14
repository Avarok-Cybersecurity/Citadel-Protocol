use crate::crypto::{CryptoParameters, SecrecyMode, SecurityLevel};
use crate::prelude::HeaderObfuscatorSettings;
use crate::utils;
use packed_struct::derive::PrimitiveEnum_u8;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;
use strum::VariantNames;
#[cfg(feature = "typescript")]
use ts_rs::TS;
use uuid::Uuid;

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
/// If force_login is true, the protocol will disconnect any previously existent sessions in the session manager attributed to the account logging-in (so long as login succeeds)
/// The default is a Standard login that will with force_login set to false
pub enum ConnectMode {
    Standard { force_login: bool },
    Fetch { force_login: bool },
}

impl Default for ConnectMode {
    fn default() -> Self {
        Self::Standard { force_login: false }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct VirtualObjectMetadata {
    pub name: String,
    pub date_created: String,
    pub author: String,
    pub plaintext_length: usize,
    pub group_count: usize,
    pub object_id: ObjectId,
    pub cid: u64,
    pub transfer_type: TransferType,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[repr(transparent)]
pub struct ObjectId(pub u128);

impl Debug for ObjectId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ObjectId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl ObjectId {
    pub fn random() -> Self {
        Uuid::new_v4().as_u128().into()
    }

    pub const fn zero() -> Self {
        Self(0)
    }
}

impl From<u128> for ObjectId {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl VirtualObjectMetadata {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize_from<'a, T: AsRef<[u8]> + 'a>(input: T) -> Option<Self> {
        bincode::deserialize(input.as_ref()).ok()
    }

    pub fn get_security_level(&self) -> Option<SecurityLevel> {
        match &self.transfer_type {
            TransferType::FileTransfer => None,
            TransferType::RemoteEncryptedVirtualFilesystem { security_level, .. } => {
                Some(*security_level)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ObjectTransferOrientation {
    Receiver { is_revfs_pull: bool },
    Sender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[allow(variant_size_differences)]
pub enum ObjectTransferStatus {
    TransferBeginning,
    ReceptionBeginning(PathBuf, VirtualObjectMetadata),
    // relative group_id, total groups, Mb/s
    TransferTick(usize, usize, f32),
    ReceptionTick(usize, usize, f32),
    TransferComplete,
    ReceptionComplete,
    Fail(String),
}

impl ObjectTransferStatus {
    pub fn is_tick_type(&self) -> bool {
        matches!(
            self,
            ObjectTransferStatus::TransferTick(_, _, _)
                | ObjectTransferStatus::ReceptionTick(_, _, _)
        )
    }

    /// Even if an error, returns true if the file transfer is done
    pub fn is_finished_type(&self) -> bool {
        matches!(
            self,
            ObjectTransferStatus::TransferComplete
                | ObjectTransferStatus::ReceptionComplete
                | ObjectTransferStatus::Fail(_)
        )
    }
}

impl std::fmt::Display for ObjectTransferStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectTransferStatus::TransferBeginning => {
                write!(f, "Transfer beginning")
            }

            ObjectTransferStatus::ReceptionBeginning(_, vfm) => {
                write!(f, "Download for object {vfm:?} beginning")
            }

            ObjectTransferStatus::TransferTick(relative_group_id, total_groups, transfer_rate) => {
                utils::print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            ObjectTransferStatus::ReceptionTick(relative_group_id, total_groups, transfer_rate) => {
                utils::print_tick(f, *relative_group_id, *total_groups, *transfer_rate)
            }

            ObjectTransferStatus::TransferComplete => {
                write!(f, "Transfer complete")
            }

            ObjectTransferStatus::ReceptionComplete => {
                write!(f, "Download complete")
            }

            ObjectTransferStatus::Fail(reason) => {
                write!(f, "Failure. Reason: {reason}")
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SessionSecuritySettings {
    pub security_level: SecurityLevel,
    pub secrecy_mode: SecrecyMode,
    pub crypto_params: CryptoParameters,
    pub header_obfuscator_settings: HeaderObfuscatorSettings,
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Default,
    PrimitiveEnum_u8,
    strum::EnumString,
    strum::EnumIter,
    strum::EnumCount,
    strum_macros::VariantNames,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum UdpMode {
    #[default]
    Disabled,
    Enabled,
}

impl UdpMode {
    pub fn variants() -> Vec<String> {
        Self::VARIANTS.iter().map(|s| s.to_string()).collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum MemberState {
    EnteredGroup { cids: Vec<u64> },
    LeftGroup { cids: Vec<u64> },
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupMemberAlterMode {
    Leave,
    Kick,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
/// Options for creating message groups
pub struct MessageGroupOptions {
    pub group_type: GroupType,
    pub id: u128,
}

impl Default for MessageGroupOptions {
    fn default() -> Self {
        Self {
            group_type: GroupType::Private,
            id: Uuid::new_v4().as_u128(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupType {
    /// A public group is a group where any user registered to the owner can join
    Public,
    /// A private group is a group where the group can only be joined when the owner
    /// sends out Invitation requests to mutually-registered peers
    Private,
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct MessageGroupKey {
    pub cid: u64,
    pub mgid: u128,
}

impl MessageGroupKey {
    pub fn new(cid: u64, mgid: u128) -> Self {
        Self { cid, mgid }
    }
}

impl std::fmt::Debug for MessageGroupKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for MessageGroupKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.cid, self.mgid)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum TransferType {
    FileTransfer,
    RemoteEncryptedVirtualFilesystem {
        virtual_path: PathBuf,
        security_level: SecurityLevel,
    },
}

// =============================================================================
// Connection Types
// =============================================================================

/// Type of client-to-server connection.
///
/// Used for C2S disconnect events and peer discovery requests.
/// For P2P connections, use [`PeerConnectionType`] instead.
///
/// # Variants
///
/// - `Server`: Standard client-to-server connection (most common)
/// - `Extended`: Connection through federated server network (future feature)
///
/// # Network Topology
///
/// ```text
/// Standard Mode:          Extended Mode:
/// ┌────────┐              ┌────────┐      icid        ┌────────┐
/// │ Client │◄─────────────│ Server │◄────────────────►│ Server │
/// └────────┘  session_cid └────────┘                  └────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ClientConnectionType {
    /// Standard client-to-server connection.
    Server {
        /// The session CID for this connection
        session_cid: u64,
    },
    /// Extended mode: client connected through federated server network.
    ///
    /// In Extended mode, multiple central servers are interconnected.
    /// **NOTE**: Not yet implemented - reserved for future use.
    Extended {
        /// The session CID for the client's connection to their home server
        session_cid: u64,
        /// The interserver connection identifier (icid) for server-to-server link
        interserver_cid: u64,
    },
}

impl ClientConnectionType {
    /// Returns the session CID for this connection.
    #[inline]
    pub fn session_cid(&self) -> u64 {
        match self {
            ClientConnectionType::Server { session_cid } => *session_cid,
            ClientConnectionType::Extended { session_cid, .. } => *session_cid,
        }
    }

    /// Returns the interserver CID if this is an Extended connection.
    #[inline]
    pub fn interserver_cid(&self) -> Option<u64> {
        match self {
            ClientConnectionType::Server { .. } => None,
            ClientConnectionType::Extended {
                interserver_cid, ..
            } => Some(*interserver_cid),
        }
    }
}

impl Display for ClientConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientConnectionType::Server { session_cid } => {
                write!(f, "C2S Server (cid={session_cid})")
            }
            ClientConnectionType::Extended {
                session_cid,
                interserver_cid,
            } => {
                write!(
                    f,
                    "C2S Extended (cid={session_cid}, icid={interserver_cid})"
                )
            }
        }
    }
}

/// Type of peer-to-peer connection.
///
/// Used in peer signaling to identify P2P connections between clients.
///
/// # Variants
///
/// - `LocalGroupPeer`: Both peers connected to the same server
/// - `ExternalGroupPeer`: Peers connected to different servers (federated)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum PeerConnectionType {
    /// P2P connection where both peers are on the same server.
    LocalGroupPeer {
        /// This client's session CID
        session_cid: u64,
        /// The peer's CID
        peer_cid: u64,
    },
    /// P2P connection where peers are on different servers (federated).
    ExternalGroupPeer {
        /// This client's session CID
        session_cid: u64,
        /// The interserver connection identifier
        interserver_cid: u64,
        /// The peer's CID on their home server
        peer_cid: u64,
    },
}

impl PeerConnectionType {
    /// Returns the originating session CID.
    #[inline]
    pub fn get_original_session_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer { session_cid, .. } => *session_cid,
            PeerConnectionType::ExternalGroupPeer { session_cid, .. } => *session_cid,
        }
    }

    /// Returns the target peer CID.
    #[inline]
    pub fn get_original_target_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer { peer_cid, .. } => *peer_cid,
            PeerConnectionType::ExternalGroupPeer { peer_cid, .. } => *peer_cid,
        }
    }

    /// Returns a reversed connection (swapping session_cid and peer_cid).
    pub fn reverse(&self) -> PeerConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => PeerConnectionType::LocalGroupPeer {
                session_cid: *peer_cid,
                peer_cid: *session_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            } => PeerConnectionType::ExternalGroupPeer {
                session_cid: *peer_cid,
                interserver_cid: *interserver_cid,
                peer_cid: *session_cid,
            },
        }
    }

    /// Converts to a VirtualConnectionType.
    pub fn as_virtual_connection(self) -> VirtualConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            } => VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            },
        }
    }
}

impl Display for PeerConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => {
                write!(f, "hLAN {session_cid} <-> {peer_cid}")
            }
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            } => {
                write!(f, "hWAN {session_cid} <-> {interserver_cid} <-> {peer_cid}")
            }
        }
    }
}

/// Unified type representing all possible virtual connections.
///
/// This type is used throughout the protocol for packet routing and connection
/// management. It covers both C2S and P2P connection scenarios.
///
/// # Variants
///
/// ## C2S Connections
/// - `LocalGroupServer`: Client connected to their home server
/// - `ExternalGroupServer`: Client connected through federated network (future)
///
/// ## P2P Connections
/// - `LocalGroupPeer`: P2P where both peers share the same server
/// - `ExternalGroupPeer`: P2P across federated servers (future)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum VirtualConnectionType {
    /// P2P connection on the same server.
    LocalGroupPeer {
        /// This client's session CID
        session_cid: u64,
        /// The peer's CID
        peer_cid: u64,
    },
    /// P2P connection across federated servers.
    ExternalGroupPeer {
        /// This client's session CID
        session_cid: u64,
        /// The interserver connection identifier
        interserver_cid: u64,
        /// The peer's CID on their home server
        peer_cid: u64,
    },
    /// Standard client-to-server connection.
    LocalGroupServer {
        /// The session CID
        session_cid: u64,
    },
    /// Client-to-server through federated network.
    ExternalGroupServer {
        /// This client's session CID
        session_cid: u64,
        /// The interserver connection identifier
        interserver_cid: u64,
    },
}

/// Alias for VirtualConnectionType (for readability in target contexts).
pub type VirtualTargetType = VirtualConnectionType;

/// Constant for C2S identity (target_cid = 0 means server).
pub const C2S_IDENTITY_CID: u64 = 0;

impl VirtualConnectionType {
    /// Serializes to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Deserializes from bytes.
    pub fn deserialize_from<'a, T: AsRef<[u8]> + 'a>(this: T) -> Option<Self> {
        bincode::deserialize(this.as_ref()).ok()
    }

    /// Gets the target CID, agnostic to connection type.
    pub fn get_target_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::LocalGroupServer { .. } => C2S_IDENTITY_CID,
            VirtualConnectionType::LocalGroupPeer { peer_cid, .. } => *peer_cid,
            VirtualConnectionType::ExternalGroupPeer { peer_cid, .. } => *peer_cid,
            VirtualConnectionType::ExternalGroupServer {
                interserver_cid, ..
            } => *interserver_cid,
        }
    }

    /// Gets the session CID.
    pub fn get_session_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid } => *session_cid,
            VirtualConnectionType::LocalGroupPeer { session_cid, .. } => *session_cid,
            VirtualConnectionType::ExternalGroupPeer { session_cid, .. } => *session_cid,
            VirtualConnectionType::ExternalGroupServer { session_cid, .. } => *session_cid,
        }
    }

    /// Returns true if this is a C2S connection.
    pub fn is_server_connection(&self) -> bool {
        matches!(
            self,
            VirtualConnectionType::LocalGroupServer { .. }
                | VirtualConnectionType::ExternalGroupServer { .. }
        )
    }

    /// Returns true if this is a P2P connection.
    pub fn is_peer_connection(&self) -> bool {
        matches!(
            self,
            VirtualConnectionType::LocalGroupPeer { .. }
                | VirtualConnectionType::ExternalGroupPeer { .. }
        )
    }

    /// Attempts to convert to a PeerConnectionType.
    pub fn try_as_peer_connection(&self) -> Option<PeerConnectionType> {
        match self {
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => Some(PeerConnectionType::LocalGroupPeer {
                session_cid: *session_cid,
                peer_cid: *peer_cid,
            }),
            VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            } => Some(PeerConnectionType::ExternalGroupPeer {
                session_cid: *session_cid,
                interserver_cid: *interserver_cid,
                peer_cid: *peer_cid,
            }),
            _ => None,
        }
    }

    /// Attempts to convert to a ClientConnectionType.
    pub fn try_as_client_connection(&self) -> Option<ClientConnectionType> {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid } => {
                Some(ClientConnectionType::Server {
                    session_cid: *session_cid,
                })
            }
            VirtualConnectionType::ExternalGroupServer {
                session_cid,
                interserver_cid,
            } => Some(ClientConnectionType::Extended {
                session_cid: *session_cid,
                interserver_cid: *interserver_cid,
            }),
            _ => None,
        }
    }

    /// Returns true if this is a local group connection (same server).
    pub fn is_local_group(&self) -> bool {
        matches!(
            self,
            VirtualConnectionType::LocalGroupPeer { .. }
                | VirtualConnectionType::LocalGroupServer { .. }
        )
    }

    /// Returns true if this is an external group connection (federated).
    pub fn is_external_group(&self) -> bool {
        !self.is_local_group()
    }

    /// Sets the target CID (for P2P connections only).
    pub fn set_target_cid(&mut self, target_cid: u64) {
        match self {
            VirtualConnectionType::LocalGroupPeer { peer_cid, .. }
            | VirtualConnectionType::ExternalGroupPeer { peer_cid, .. } => *peer_cid = target_cid,
            _ => {}
        }
    }

    /// Sets the session CID.
    pub fn set_session_cid(&mut self, cid: u64) {
        match self {
            VirtualConnectionType::LocalGroupPeer { session_cid, .. }
            | VirtualConnectionType::ExternalGroupPeer { session_cid, .. }
            | VirtualConnectionType::LocalGroupServer { session_cid }
            | VirtualConnectionType::ExternalGroupServer { session_cid, .. } => *session_cid = cid,
        }
    }
}

impl Display for VirtualConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid } => {
                write!(f, "C2S Local (cid={session_cid})")
            }
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => {
                write!(f, "P2P Local ({session_cid} -> {peer_cid})")
            }
            VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid,
                peer_cid,
            } => {
                write!(
                    f,
                    "P2P External ({session_cid} -> {interserver_cid} -> {peer_cid})"
                )
            }
            VirtualConnectionType::ExternalGroupServer {
                session_cid,
                interserver_cid,
            } => {
                write!(f, "C2S External ({session_cid} -> {interserver_cid})")
            }
        }
    }
}

impl From<PeerConnectionType> for VirtualConnectionType {
    fn from(peer: PeerConnectionType) -> Self {
        peer.as_virtual_connection()
    }
}

impl From<ClientConnectionType> for VirtualConnectionType {
    fn from(client: ClientConnectionType) -> Self {
        match client {
            ClientConnectionType::Server { session_cid } => {
                VirtualConnectionType::LocalGroupServer { session_cid }
            }
            ClientConnectionType::Extended {
                session_cid,
                interserver_cid,
            } => VirtualConnectionType::ExternalGroupServer {
                session_cid,
                interserver_cid,
            },
        }
    }
}
