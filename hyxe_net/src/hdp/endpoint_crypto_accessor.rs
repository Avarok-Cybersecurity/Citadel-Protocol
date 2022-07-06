#![allow(dead_code)]
use crate::hdp::state_container::{StateContainer, StateContainerInner};
use hyxe_user::prelude::ClientNetworkAccount;
use crate::error::NetworkError;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::inner_arg::ExpectedInnerTarget;

#[derive(Clone)]
pub enum EndpointCryptoAccessor {
    P2P(u64, StateContainer),
    C2S(StateContainer)
}

impl EndpointCryptoAccessor {
    // In P2P Mode, will return a state container
    pub fn borrow_hr<F, T>(&self, vers: Option<u32>, access: F) -> Result<T, NetworkError>
        where F: for<'a> FnOnce(&'a HyperRatchet, &mut dyn ExpectedInnerTarget<StateContainerInner>) -> T {

        match self {
            Self::P2P(peer_cid, state_container) => {
                let mut state_container = inner_mut_state!(state_container);
                let v_conn = state_container.active_virtual_connections.get(peer_cid).ok_or(NetworkError::InternalError("Virtual Connection not loaded"))?;
                let v_conn = v_conn.endpoint_container.as_ref().ok_or(NetworkError::InternalError("Endpoint channel container not loaded"))?;
                v_conn.endpoint_crypto.get_hyper_ratchet(vers).ok_or(NetworkError::InternalError("P2P HR does not exist")).map(|r| access(r, &mut state_container))
            }

            Self::C2S(state_container, ) => {
                let mut state_container = inner_mut_state!(state_container);
                let hr = state_container.get_c2s_crypto()
                    .map(|r| r.get_hyper_ratchet(vers))
                    .ok_or(NetworkError::InternalError("C2S container does not exist"))?
                    .ok_or(NetworkError::InternalError("Ratchet does not exist"))?;
                Ok(access(hr, &mut state_container))
            }
        }
    }

    pub fn get_target_cid(&self) -> u64 {
        match self {
            Self::P2P(target_cid, ..) => *target_cid,
            Self::C2S(..) => C2S_ENCRYPTION_ONLY
        }
    }
}