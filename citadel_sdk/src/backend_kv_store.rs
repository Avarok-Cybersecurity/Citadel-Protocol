//! Connection-Specific Key-Value Storage
//!
//! This module provides a trait for persistent key-value storage that is unique to each
//! connection in the Citadel Protocol. It allows applications to store and retrieve
//! arbitrary data associated with specific peer connections.
//!
//! # Features
//! - Connection-scoped storage (unique per session and peer)
//! - Basic key-value operations (get, set, remove)
//! - Bulk operations for managing multiple key-value pairs
//! - Automatic error handling and conversion
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//!
//! async fn store_data<T: BackendHandler<R>, R: Ratchet>(handler: &T) -> Result<(), NetworkError> {
//!     // Store a value
//!     handler.set("my_key", b"my_value".to_vec()).await?;
//!
//!     // Retrieve the value
//!     if let Some(value) = handler.get("my_key").await? {
//!         println!("Retrieved value: {:?}", value);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//! - Storage is tied to the connection's session and peer IDs
//! - All operations are asynchronous and may fail
//! - Values are stored as raw bytes (Vec<u8>)
//!
//! # Related Components
//! - [`TargetLockedRemote`]: Trait for accessing connection-specific information
//! - [`PersistenceHandler`]: Backend storage implementation
//!
//! [`TargetLockedRemote`]: crate::prelude::TargetLockedRemote
//! [`PersistenceHandler`]: crate::prelude::PersistenceHandler

use crate::prelude::*;
use std::collections::HashMap;

const DATA_MAP_KEY: &str = "_INTERNAL_DATA_MAP";

#[async_trait]
/// Contains a trait for persisting application-level data in a K,V store that is unique
/// for this particular connection
pub trait BackendHandler<R: Ratchet>: TargetLockedRemote<R> {
    /// Gets a value from the backend
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, NetworkError> {
        let (session_cid, peer_cid) = self.get_cids();
        self.remote()
            .account_manager()
            .get_persistence_handler()
            .get_byte_map_value(session_cid, peer_cid, DATA_MAP_KEY, key)
            .await
            .map_err(|err| NetworkError::msg(err.into_string()))
    }
    /// Removes a value from the backend, returning the previous value
    async fn remove(&self, key: &str) -> Result<Option<Vec<u8>>, NetworkError> {
        let (session_cid, peer_cid) = self.get_cids();
        self.remote()
            .account_manager()
            .get_persistence_handler()
            .remove_byte_map_value(session_cid, peer_cid, DATA_MAP_KEY, key)
            .await
            .map_err(|err| NetworkError::msg(err.into_string()))
    }
    /// Stores a value in the backend, either creating or overwriting any pre-existing value
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, NetworkError> {
        let (session_cid, peer_cid) = self.get_cids();
        self.remote()
            .account_manager()
            .get_persistence_handler()
            .store_byte_map_value(session_cid, peer_cid, DATA_MAP_KEY, key, value)
            .await
            .map_err(|err| NetworkError::msg(err.into_string()))
    }
    /// Obtains the K,V map for this application
    async fn get_all(&self) -> Result<HashMap<String, Vec<u8>>, NetworkError> {
        let (session_cid, peer_cid) = self.get_cids();
        self.remote()
            .account_manager()
            .get_persistence_handler()
            .get_byte_map_values_by_key(session_cid, peer_cid, DATA_MAP_KEY)
            .await
            .map_err(|err| NetworkError::msg(err.into_string()))
    }
    /// Obtains a list of K,V pairs such that `needle` is a subset of the K value
    async fn remove_all(&self) -> Result<HashMap<String, Vec<u8>>, NetworkError> {
        let (session_cid, peer_cid) = self.get_cids();
        self.remote()
            .account_manager()
            .get_persistence_handler()
            .remove_byte_map_values_by_key(session_cid, peer_cid, DATA_MAP_KEY)
            .await
            .map_err(|err| NetworkError::msg(err.into_string()))
    }

    #[doc(hidden)]
    fn get_cids(&self) -> (u64, u64) {
        (self.user().get_session_cid(), self.user().get_target_cid())
    }
}

impl<T: TargetLockedRemote<R>, R: Ratchet> BackendHandler<R> for T {}
