//! Endpoint Cryptographic Access Management
//!
//! This module provides secure access to cryptographic state for both peer-to-peer (P2P)
//! and client-to-server (C2S) communication channels within the Citadel Protocol.
//!
//! # Features
//! - Safe access to cryptographic state through controlled borrowing
//! - Support for both P2P and C2S communication modes
//! - Version-aware cryptographic state management
//! - Thread-safe state container access
//! - Automatic error handling for missing or invalid states
//!
//! # Important Notes
//! - All cryptographic operations are performed using post-quantum secure algorithms
//! - State containers are protected against concurrent access
//! - Version control ensures forward compatibility
//!
//! # Related Components
//! - `StateContainer`: Manages the underlying cryptographic state
//! - `StackedRatchet`: Provides the core cryptographic operations
//! - `NetworkError`: Error handling for cryptographic operations

#![allow(dead_code)]
use crate::error::NetworkError;
use crate::inner_arg::ExpectedInnerTargetMut;
use crate::proto::packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::proto::state_container::{StateContainer, StateContainerInner};
use citadel_crypt::stacked_ratchet::StackedRatchet;

#[derive(Clone)]
pub enum EndpointCryptoAccessor {
    P2P(u64, StateContainer),
    C2S(StateContainer),
}

impl EndpointCryptoAccessor {
    // In P2P Mode, will return a state container
    pub fn borrow_hr<F, T>(&self, vers: Option<u32>, access: F) -> Result<T, NetworkError>
    where
        F: for<'a> FnOnce(
            &'a StackedRatchet,
            &mut dyn ExpectedInnerTargetMut<StateContainerInner>,
        ) -> T,
    {
        match self {
            Self::P2P(peer_cid, state_container) => {
                let mut state_container = inner_mut_state!(state_container);
                state_container
                    .get_peer_session_crypto(*peer_cid)
                    .ok_or(NetworkError::InternalError("Peer session crypto missing"))?
                    .get_hyper_ratchet(None)
                    .cloned()
                    .map(|hr| access(&hr, &mut state_container))
                    .ok_or(NetworkError::InternalError("Ratchet does not exist"))
            }

            Self::C2S(state_container) => {
                let mut state_container = inner_mut_state!(state_container);
                let hr = state_container
                    .get_c2s_crypto()
                    .map(|r| r.get_hyper_ratchet(vers).cloned())
                    .ok_or(NetworkError::InternalError("C2S container does not exist"))?
                    .ok_or(NetworkError::InternalError("Ratchet does not exist"))?;
                Ok(access(&hr, &mut state_container))
            }
        }
    }

    pub fn get_target_cid(&self) -> u64 {
        match self {
            Self::P2P(target_cid, ..) => *target_cid,
            Self::C2S(..) => C2S_ENCRYPTION_ONLY,
        }
    }
}
