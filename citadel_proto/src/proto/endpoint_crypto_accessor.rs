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
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::state_container::{StateContainer, StateContainerInner};
use citadel_crypt::ratchets::Ratchet;

#[derive(Clone)]
pub enum EndpointCryptoAccessor<R: Ratchet> {
    P2P(u64, StateContainer<R>),
    C2S(StateContainer<R>),
}

impl<R: Ratchet> EndpointCryptoAccessor<R> {
    // In P2P Mode, will return a state container
    pub fn borrow_hr<F, T>(&self, vers: Option<u32>, access: F) -> Result<T, NetworkError>
    where
        F: for<'a> FnOnce(&'a R, &mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> T,
    {
        let (peer_cid, state_container) = match self {
            Self::P2P(peer_cid, state_container) => (*peer_cid, state_container),

            Self::C2S(state_container) => (C2S_IDENTITY_CID, state_container),
        };

        let mut state_container = inner_mut_state!(state_container);
        state_container
            .get_virtual_connection_crypto(peer_cid)
            .ok_or(NetworkError::InternalError("Peer session crypto missing"))?
            .get_ratchet(vers)
            .map(|hr| access(&hr, &mut state_container))
            .ok_or(NetworkError::InternalError("Ratchet does not exist"))
    }

    pub fn get_target_cid(&self) -> u64 {
        match self {
            Self::P2P(target_cid, ..) => *target_cid,
            Self::C2S(..) => C2S_IDENTITY_CID,
        }
    }
}
