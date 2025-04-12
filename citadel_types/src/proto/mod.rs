use crate::crypto::{CryptoParameters, SecrecyMode, SecurityLevel};
use crate::prelude::HeaderObfuscatorSettings;
use crate::utils;
use packed_struct::derive::PrimitiveEnum_u8;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;
use strum::VariantNames;
use uuid::Uuid;

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
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
pub enum ObjectTransferOrientation {
    Receiver { is_revfs_pull: bool },
    Sender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub enum MemberState {
    EnteredGroup { cids: Vec<u64> },
    LeftGroup { cids: Vec<u64> },
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GroupMemberAlterMode {
    Leave,
    Kick,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
pub enum GroupType {
    /// A public group is a group where any user registered to the owner can join
    Public,
    /// A private group is a group where the group can only be joined when the owner
    /// sends out Invitation requests to mutually-registered peers
    Private,
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
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
pub enum TransferType {
    FileTransfer,
    RemoteEncryptedVirtualFilesystem {
        virtual_path: PathBuf,
        security_level: SecurityLevel,
    },
}
