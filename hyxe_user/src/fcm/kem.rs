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

impl PartialEq for FcmPostRegister {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Disable => {
                match other {
                    Self::Disable => true,
                    _ => false
                }
            }

            Self::Enable => {
                match other {
                    Self::Enable => true,
                    _ => false
                }
            }

            Self::AliceToBobTransfer(a, b, c) => {
                match other {
                    Self::AliceToBobTransfer(a1, b1, c1) => a == a1 && b.api_key == b1.api_key && b.client_id == b1.client_id && *c == *c1,
                    _ => false
                }
            }

            Self::BobToAliceTransfer(_a, b, c) => {
                match other {
                    Self::BobToAliceTransfer(_a1, b1, c1) => b.api_key == b1.api_key && b.client_id == b1.client_id && *c == *c1,
                    _ => false
                }
            }
        }
    }
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