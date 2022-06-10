use crate::external_services::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult};
use crate::external_services::fcm::kem::FcmPostRegister;
use serde::{Serialize, Deserialize};
use super::super::data_structures::{string, base64_string};
use std::collections::HashMap;
use hyxe_crypt::hyper_ratchet::constructor::ConstructorType;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::toolset::Toolset;
use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use multimap::MultiMap;
use crate::client_account::{MutualPeer, HYPERLAN_IDX};
use crate::backend::PersistenceHandler;
use crate::misc::{AccountError, EmptyOptional};

#[derive(Serialize, Deserialize)]
pub enum InvitationType {
    PostRegister(FcmPostRegister, String, u128)
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
    pub ticket: u128,
}
/*

  pub struct PostRegisterResponse {
  #[serde(with = "string")]
  implicated_cid: u64,
  #[serde(with = "string")]
  peer_cid: u64,
  #[serde(with = "string")]
  ticket: u64,
  accept: bool,
  #[serde(with = "base64_string")]
  username: Vec<u8>,
  fcm: bool
}

 */

#[derive(Debug)]
pub struct FcmPostRegisterResponse {
    pub local_cid: u64,
    pub peer_cid: u64,
    pub ticket: u128,
    pub accept: bool,
    pub username: String
}

#[allow(unused_results)]
pub async fn process(persistence_handler: &PersistenceHandler, post_register_store: &mut HashMap<u64, InvitationType>, kem_state_containers: &mut HashMap<u64, ConstructorType>, fcm_crypt_container: &mut HashMap<u64, PeerSessionCrypto<FcmRatchet>>, mutuals: &mut MultiMap<u64, MutualPeer>, local_cid: u64, source_cid: u64, ticket: u128, transfer: FcmPostRegister, username: String) -> Result<FcmProcessorResult, AccountError> {
    log::trace!(target: "lusna", "FCM RECV PEER_POST_REGISTER");
    match &transfer {
        FcmPostRegister::AliceToBobTransfer(_transfer_bytes, _keys, source_cid) => {
            // store inside cnac
            let peer_cid = *source_cid;
            if post_register_store.insert(*source_cid, InvitationType::PostRegister(transfer, username.clone(), ticket)).is_some() {
                log::warn!(target: "lusna", "Overwrote pre-existing invite request. Previous is thus invalidated");
            }

            log::trace!(target: "lusna", "[FCM POST-REGISTER] Stored invitation from {} for {}", peer_cid, local_cid);

            // finally, return signal to caller
            Ok(FcmProcessorResult::Value(FcmResult::PostRegisterInvitation { invite: PostRegisterInvitation { peer_cid, local_cid, username: username.into_bytes(), ticket } }))
        }

        FcmPostRegister::BobToAliceTransfer(fcm_bob_to_alice_transfer, fcm_keys, source_cid) => {
            // here, we need to finalize the construction on Alice's side
            let mut fcm_constructor = kem_state_containers.remove(source_cid).map_empty_err()?.assume_fcm().map_empty_err()?;

            fcm_constructor.stage1_alice(fcm_bob_to_alice_transfer).map_empty_err()?;

            let fcm_ratchet = fcm_constructor.finish_with_custom_cid(local_cid).map_empty_err()?;

            let fcm_endpoint_container = PeerSessionCrypto::new_fcm(Toolset::new(local_cid, fcm_ratchet), true, fcm_keys.clone());

            fcm_crypt_container.insert(*source_cid, fcm_endpoint_container);

            mutuals.insert(HYPERLAN_IDX, MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid: *source_cid,
                username: Some(username.clone())
            });

            persistence_handler.register_p2p_as_client(local_cid, *source_cid, username.clone()).await?;

            // upon return, saving will occur
            Ok(FcmProcessorResult::Value(FcmResult::PostRegisterResponse {
                response: FcmPostRegisterResponse {
                    local_cid,
                    peer_cid: *source_cid,
                    ticket,
                    accept: true,
                    username,
                }
            }))
        }

        // Bob denied the request
        FcmPostRegister::Decline => {
            kem_state_containers.remove(&source_cid);
            Ok(FcmProcessorResult::Value(FcmResult::PostRegisterResponse {
                response: FcmPostRegisterResponse {
                    local_cid,
                    peer_cid: source_cid,
                    ticket,
                    accept: false,
                    username,
                }
            }))
        }
        s @ FcmPostRegister::Enable | s @ FcmPostRegister::Disable => {
            log::error!(target: "lusna", "Received unexpected signal: {:?}", s);
            // We should never reach here
            Ok(FcmProcessorResult::Void)
        }
    }
}