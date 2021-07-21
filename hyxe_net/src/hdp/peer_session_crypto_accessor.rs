#![allow(dead_code)]
use crate::hdp::state_container::{StateContainer, StateContainerInner};
use hyxe_user::prelude::ClientNetworkAccount;
use crate::error::NetworkError;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
use crate::inner_arg::ExpectedInnerTarget;

#[derive(Clone)]
pub enum PeerSessionCryptoAccessor {
    P2P(u64, StateContainer),
    C2S(ClientNetworkAccount, StateContainer)
}

impl PeerSessionCryptoAccessor {
    // In P2P Mode, will return a state container
    pub fn borrow_hr<F, T>(&self, vers: Option<u32>, access: F) -> Result<T, NetworkError>
        where F: for<'a> FnOnce(&'a HyperRatchet, &dyn ExpectedInnerTarget<StateContainerInner>) -> T {

        match self {
            Self::P2P(peer_cid, state_container) => {
                let state_container = inner!(state_container);
                let v_conn = state_container.active_virtual_connections.get(peer_cid).ok_or(NetworkError::InternalError("Virtual Connection not loaded"))?;
                let v_conn = v_conn.endpoint_container.as_ref().ok_or(NetworkError::InternalError("Endpoint channel container not loaded"))?;
                v_conn.endpoint_crypto.get_hyper_ratchet(vers).ok_or(NetworkError::InternalError("P2P HR does not exist")).map(|r| access(r, &state_container))
            }

            Self::C2S(cnac, state_container, ) => {
                let state_container = inner!(state_container);
                cnac.borrow_hyper_ratchet(vers, |hr| {
                    hr.ok_or(NetworkError::InternalError("C2S HR does not exist")).map(|r| access(r, &state_container))
                })
            }
        }
    }

    pub fn get_target_cid(&self) -> u64 {
        match self {
            Self::P2P(target_cid, ..) => *target_cid,
            Self::C2S(..) => ENDPOINT_ENCRYPTION_OFF
        }
    }
}