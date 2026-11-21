//! The recovery lane's messages: a device with no bundle proves the account's recovery phrase
//! inside a fresh key exchange, and the server makes that exchange's ratchet
//! the account's device bundle.

use super::login::{LoginFinish, LoginStart};
use serde::{Deserialize, Serialize};

/// What the recovering device says about itself. The server records nothing yet; the label is
/// bound into the transcript so a proof names the device it was made on.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceOffer {
    pub label: String,
}

/// C→S, `RECOVER_START`: a login start with `recovery` set and no password.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoverStart {
    pub login: LoginStart,
    pub device: DeviceOffer,
}

/// C→S, `RECOVER_PROOF`: the tag over the recovery transcript.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoverProof {
    pub finish: LoginFinish,
}

/// S→C, `RECOVER_DONE`: the exchange's ratchet is now the account's bundle. Every other device's
/// bundle stopped working when it was installed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoverDone {
    pub cid: u64,
    /// The account's name as the server keeps it, for the device's new account entry.
    pub full_name: String,
}
