use serde::{Serialize, Deserialize};
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::fcm::fcm_ratchet::FcmBobToAliceTransfer;

#[allow(variant_size_differences)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FcmPostRegister {
    Disable,
    Enable,
    AliceToBobTransfer(#[serde(with = "serde_bytes")] Vec<u8>, FcmKeys, u64),
    BobToAliceTransfer(FcmBobToAliceTransfer, FcmKeys, u64)
}

impl FcmPostRegister {
    pub fn get_peer_cid(&self) -> Option<u64> {
        match self {
            Self::AliceToBobTransfer(_, _, cid) => Some(*cid),
            Self::BobToAliceTransfer(_, _, cid) => Some(*cid),
            _ => None
        }
    }

    pub fn get_keys(&self) -> Option<&FcmKeys> {
        match self {
            Self::AliceToBobTransfer(_, keys, ..) | Self::BobToAliceTransfer(_, keys, ..) => Some(keys),
            _ => None
        }
    }
}