//! # Network Account Management
//!
//! This module provides core functionality for network account operations and user identification
//! in the Citadel Protocol. It defines the extension trait for user identifiers and handles
//! account searching and peer relationships.
//!
//! ## Features
//!
//! * **User Identification**
//!   - CID-based identification
//!   - Username-based lookup
//!   - Flexible identifier conversion
//!
//! * **Account Search**
//!   - Account lookup by CID
//!   - Account lookup by username
//!   - Peer relationship search
//!
//! * **Peer Management**
//!   - Mutual peer relationship tracking
//!   - Network peer lookup
//!   - Peer information retrieval
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_user::prelude::*;
//! use citadel_types::user::UserIdentifier;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create account manager
//!     let manager = AccountManager::new(
//!         BackendType::InMemory,
//!         None,
//!         None,
//!         None
//!     ).await?;
//!
//!     // Search by CID
//!     let user_by_id = UserIdentifier::ID(1234);
//!     if let Some(account) = user_by_id.search(&manager).await? {
//!         println!("Found account by CID");
//!     }
//!
//!     // Search by username
//!     let user_by_name = UserIdentifier::Username("alice".to_string());
//!     if let Some(account) = user_by_name.search(&manager).await? {
//!         println!("Found account by username");
//!     }
//!
//!     // Search for peer relationship
//!     if let Some(peer) = user_by_id.search_peer(5678, &manager).await? {
//!         println!("Found peer relationship");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * CIDs are unique identifiers for network accounts
//! * Username lookups are case-insensitive
//! * Peer relationships are bidirectional
//! * Search operations are async and fallible
//!
//! ## Related Components
//!
//! * `AccountManager`: Core account management
//! * `UserIdentifier`: User identification types
//! * `ClientNetworkAccount`: Client account type
//! * `MutualPeer`: Peer relationship type
//!

use crate::account_manager::AccountManager;
use crate::misc::AccountError;
use crate::prelude::ClientNetworkAccount;
use async_trait::async_trait;
use citadel_types::user::MutualPeer;
use citadel_types::user::UserIdentifier;

/// The file extension for CNACs only
pub const CNAC_SERIALIZED_EXTENSION: &str = "hca";

#[async_trait]
pub trait UserIdentifierExt {
    type AccountManager;
    type SearchOutput; // Usually the clientnetworkaccount
    type Error;
    async fn search(
        &self,
        account_manager: &Self::AccountManager,
    ) -> Result<Option<Self::SearchOutput>, Self::Error>;

    /// Performs a search for the current peer given the `implicated_cid`
    async fn search_peer(
        &self,
        implicated_cid: u64,
        account_manager: &Self::AccountManager,
    ) -> Result<Option<MutualPeer>, Self::Error>;

    fn get_cid(&self) -> u64;
}

#[async_trait]
impl UserIdentifierExt for UserIdentifier {
    type AccountManager = AccountManager;
    type SearchOutput = ClientNetworkAccount;
    type Error = AccountError;

    /// Searches for the account
    async fn search(
        &self,
        account_manager: &AccountManager,
    ) -> Result<Option<ClientNetworkAccount>, AccountError> {
        match self {
            Self::ID(cid) => account_manager.get_client_by_cid(*cid).await,
            Self::Username(uname) => account_manager.get_client_by_username(uname).await,
        }
    }

    /// Performs a search for the current peer given the `implicated_cid`
    async fn search_peer(
        &self,
        implicated_cid: u64,
        account_manager: &AccountManager,
    ) -> Result<Option<MutualPeer>, AccountError> {
        match self {
            UserIdentifier::ID(cid) => {
                account_manager
                    .get_persistence_handler()
                    .get_hyperlan_peer_by_cid(implicated_cid, *cid)
                    .await
            }
            UserIdentifier::Username(name) => {
                account_manager
                    .get_persistence_handler()
                    .get_hyperlan_peer_by_username(implicated_cid, name.as_str())
                    .await
            }
        }
    }

    /// Gets the CID of this target
    fn get_cid(&self) -> u64 {
        match self {
            UserIdentifier::ID(cid) => *cid,
            UserIdentifier::Username(uname) => citadel_types::user::username_to_cid(uname),
        }
    }
}
