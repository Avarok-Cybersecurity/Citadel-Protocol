use serde::{Serialize, Deserialize};
use hyxe_crypt::fcm::keys::FcmKeys;

#[allow(variant_size_differences)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FcmPostRegister {
    Disable,
    Enable,
    AliceToBobTransfer(#[serde(with = "serde_bytes")] Vec<u8>, FcmKeys),
    BobToAliceTransfer(#[serde(with = "serde_bytes")] Vec<u8>, FcmKeys)
}