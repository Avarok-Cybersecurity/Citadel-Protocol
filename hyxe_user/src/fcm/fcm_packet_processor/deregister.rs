use crate::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, FcmPacketMaybeNeedsDuplication};
use std::collections::HashMap;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use multimap::MultiMap;
use crate::client_account::{MutualPeer, HYPERLAN_IDX};
use crate::misc::AccountError;

/// Here, we're receiving a notification that we've been deregistered from. We thus have no responsibility of making confirmation to the source. Just need to remove
/// the entries in the cnac
#[allow(unused_results)]
pub fn process(peer_cid: u64, local_cid: u64, ticket: u64, fcm_crypt_container: &mut HashMap<u64, PeerSessionCrypto<FcmRatchet>>, mutuals: &mut MultiMap<u64, MutualPeer>) -> FcmProcessorResult {
    log::info!("FCM RECV DEREGISTER");
    if let None = fcm_crypt_container.remove(&peer_cid) {
        log::warn!("[Deregister] Unable to remove fcm crypt container");
    }

    if let Err(err) = mutuals.get_vec_mut(&HYPERLAN_IDX).ok_or(AccountError::Generic("Zero mutuals".to_string())).and_then(|vec| {
        if let Some(idx) = vec.iter().position(|val| val.cid == peer_cid) {
            vec.remove(idx);
            Ok(())
        } else {
            Err(AccountError::Generic("Unable to find peer in map".to_string()))
        }
    }) {
        log::warn!("Unable to remove peer: {:?}", &err);
        FcmProcessorResult::Err(err.into_string())
    } else {
        // requestor is the peer, since we are receiving the notification here that the other endpoint deregistered
        FcmProcessorResult::Value(FcmResult::Deregistered { peer_cid: local_cid, requestor_cid: peer_cid, ticket }, FcmPacketMaybeNeedsDuplication::none())
    }
}