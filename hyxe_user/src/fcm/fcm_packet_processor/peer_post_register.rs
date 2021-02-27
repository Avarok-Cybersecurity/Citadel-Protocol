use crate::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult};
use crate::fcm::kem::FcmPostRegister;
use serde::{Serialize, Deserialize};
use super::super::data_structures::{string, base64_string};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub enum InvitationType {
    PostRegister(FcmPostRegister, String, u64)
}

impl InvitationType {
    #[allow(unreachable_patterns)]
    pub fn assert_register(self) -> Option<FcmPostRegister> {
        match self {
            Self::PostRegister(this, ..) => Some(this),
            _ => None
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostRegisterInvitation {
    #[serde(with = "string")]
    pub peer_cid: u64,
    #[serde(with = "string")]
    pub local_cid: u64,
    #[serde(with = "base64_string")]
    pub username: Vec<u8>,
    #[serde(with = "string")]
    pub ticket: u64,
}

pub fn process(post_register_store: &mut HashMap<u64, InvitationType>, local_cid: u64, ticket: u64, transfer: FcmPostRegister, username: String) -> FcmProcessorResult {
    // store inside cnac
    let peer_cid = transfer.get_peer_cid()?;
    if let Some(_) = post_register_store.insert(peer_cid, InvitationType::PostRegister(transfer, username.clone(), ticket)) {
        log::warn!("Overwrote pre-existing invite request. Previous is thus invalidated");
    }

    // finally, return signal to caller
    FcmProcessorResult::Value(FcmResult::PostRegisterInvitation { invite: PostRegisterInvitation { peer_cid, local_cid, username: username.into_bytes(), ticket } })
}