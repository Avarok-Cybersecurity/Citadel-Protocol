use serde::{Serialize, Deserialize};

#[allow(variant_size_differences)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FcmPostRegister {
    Disable,
    Enable,
    AliceToBobTransfer(Vec<u8>),
    BobToAliceTransfer(Vec<u8>)
}