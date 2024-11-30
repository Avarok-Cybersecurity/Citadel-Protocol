//! # Account Manager
//!
//! The Account Manager is responsible for managing user accounts in the Citadel Protocol.
//! It provides a unified interface for account creation, storage, retrieval, and management
//! across different backend storage systems.
//!
//! ## Features
//!
//! * **Account Management**
//!   - User registration and authentication
//!   - Personal and impersonal account modes
//!   - Account metadata management
//!   - Account deletion and purging
//!
//! * **Storage Backend Support**
//!   - In-memory storage
//!   - File system persistence
//!   - SQL database integration
//!   - Redis database support
//!
//! * **Peer Management**
//!   - HyperLAN peer registration
//!   - P2P connection handling
//!   - Peer list synchronization
//!   - User information lookup
//!
//! * **Security**
//!   - Argon2id password hashing
//!   - Secure credential management
//!   - Ratchet-based cryptography
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_user::prelude::*;
//! use citadel_crypt::stacked_ratchet::StackedRatchet;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize account manager with in-memory backend
//!     let manager = AccountManager::<StackedRatchet>::new(
//!         BackendType::InMemory,
//!         None,
//!         None,
//!         None
//!     ).await?;
//!
//!     // Register a new client account
//!     let conn_info = ConnectionInfo::new(
//!         SecurityLevel::Standard,
//!         None,
//!         None
//!     );
//!
//!     let creds = ProposedCredentials::new(
//!         "username".to_string(),
//!         "password".to_string(),
//!         None
//!     );
//!
//!     let ratchet = StackedRatchet::new(1234, 0);
//!
//!     let account = manager.register_impersonal_hyperlan_client_network_account(
//!         conn_info,
//!         creds,
//!         ratchet
//!     )?;
//!
//!     // Retrieve peer information
//!     if let Some(peers) = manager.get_hyperlan_peer_list(account.get_cid())? {
//!         for peer_cid in peers {
//!             println!("Connected to peer: {}", peer_cid);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Account manager must be initialized with appropriate backend configuration
//! * Username uniqueness is not guaranteed - use CIDs for unique identification
//! * Proper error handling is essential for backend operations
//! * Account operations are thread-safe and async-compatible
//! * Backend connections are verified during initialization
//!
//! ## Related Components
//!
//! * `ClientNetworkAccount` - Individual client account management
//! * `PersistenceHandler` - Backend storage interface
//! * `ServicesHandler` - External service integration
//! * `BackendType` - Storage backend configuration
//! * `ProposedCredentials` - Account creation parameters
//!

use crate::auth::proposed_credentials::ProposedCredentials;
use crate::backend::memory::MemoryBackend;
use crate::backend::{BackendType, PersistenceHandler};
use crate::client_account::ClientNetworkAccount;
use crate::external_services::{ServicesConfig, ServicesHandler};
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::ConnectionInfo;
use crate::server_misc_settings::ServerMiscSettings;
use citadel_crypt::argon::argon_container::{ArgonDefaultServerSettings, ArgonSettings};
use citadel_crypt::fcm::fcm_ratchet::ThinRatchet;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_crypt::stacked_ratchet::StackedRatchet;
use citadel_types::prelude::PeerInfo;
use citadel_types::user::MutualPeer;
use citadel_types::user::UserIdentifier;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// The default manager for handling the list of users stored locally. It also allows for user creation, and is used especially
/// for when creating a new user via the registration service.
#[derive(Clone)]
pub struct AccountManager<R: Ratchet = StackedRatchet, Fcm: Ratchet = ThinRatchet> {
    services_handler: ServicesHandler,
    persistence_handler: PersistenceHandler<R, Fcm>,
    node_argon_settings: ArgonSettings,
    server_misc_settings: ServerMiscSettings,
    backend_ty: BackendType,
}

impl<R: Ratchet, Fcm: Ratchet> AccountManager<R, Fcm> {
    /// `bind_addr`: Required for determining the local save directories for this instance
    /// `home_dir`: Optional. Overrides the default storage location for files
    /// `server_argon_settings`: Security settings used for saving the password to the backend. The AD will be replaced each time a new user is created, so it can be empty
    #[allow(unused_results)]
    pub async fn new(
        backend_type: BackendType,
        server_argon_settings: Option<ArgonDefaultServerSettings>,
        _services_cfg: Option<ServicesConfig>,
        server_misc_settings: Option<ServerMiscSettings>,
    ) -> Result<Self, AccountError> {
        // The below map should locally store: impersonal mode CNAC's, as well as personal remote server CNAC's
        #[cfg(feature = "google-services")]
        let services_handler = _services_cfg
            .unwrap_or_default()
            .into_services_handler()
            .await?;

        #[cfg(not(feature = "google-services"))]
        let services_handler = ServicesHandler;

        let persistence_handler = match &backend_type {
            BackendType::InMemory => {
                let backend = MemoryBackend::default();
                PersistenceHandler::create(backend).await?
            }

            #[cfg(feature = "filesystem")]
            BackendType::Filesystem(dir) => {
                use crate::backend::filesystem_backend::FilesystemBackend;
                let backend = FilesystemBackend::from(dir.clone());
                PersistenceHandler::create(backend).await?
            }

            #[cfg(all(feature = "sql", not(coverage)))]
            BackendType::SQLDatabase(..) => {
                use crate::backend::sql_backend::SqlBackend;
                let backend = SqlBackend::try_from(backend_type.clone()).map_err(|_| AccountError::Generic("Invalid database URL format. Please check documentation for preferred format".to_string()))?;
                PersistenceHandler::create(backend).await?
            }

            #[cfg(all(feature = "redis", not(coverage)))]
            BackendType::Redis(url, opts) => {
                use crate::backend::redis_backend::RedisBackend;
                let backend = RedisBackend::new(url.clone(), opts.clone());
                PersistenceHandler::create(backend).await?
            }
        };

        if !persistence_handler.is_connected().await? {
            return Err(AccountError::msg(
                "Unable to connect to remote database via account manager",
            ));
        }

        log::info!(target: "citadel", "Successfully established connection to backend {:?}...", backend_type);

        let this = Self {
            backend_ty: backend_type,
            persistence_handler,
            services_handler,
            node_argon_settings: server_argon_settings.unwrap_or_default().into(),
            server_misc_settings: server_misc_settings.unwrap_or_default(),
        };

        Ok(this)
    }

    /// Returns a reference to the services handler
    pub fn services_handler(&self) -> &ServicesHandler {
        &self.services_handler
    }

    /// Once a valid and decrypted stage 4 packet gets received by the server (Bob), this function should be called
    /// to create the new CNAC. The generated CNAC will be assumed to be an impersonal hyperlan client
    ///
    /// This also generates the argon-2id password hash
    pub async fn register_impersonal_hyperlan_client_network_account(
        &self,
        conn_info: ConnectionInfo,
        creds: ProposedCredentials,
        init_hyper_ratchet: R,
    ) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let reserved_cid = self
            .persistence_handler
            .get_cid_by_username(creds.username());
        let auth_store = creds
            .derive_server_container(&self.node_argon_settings, self.get_misc_settings())
            .await?;

        self.server_misc_settings
            .credential_requirements
            .check::<_, &str, _>(auth_store.username(), None, auth_store.full_name())?;

        let pers = &self.persistence_handler;

        // We must lock the config to ensure that the obtained CID gets added into the database before any competing threads may get called
        log::trace!(target: "citadel", "Checking username {} for correspondence ...", auth_store.username());

        let username = auth_store.username().to_string();

        if pers.username_exists(&username).await? {
            return Err(AccountError::Generic(format!(
                "Username {} already exists!",
                &username
            )));
        }

        // cnac gets saved below
        let new_cnac = ClientNetworkAccount::<R, Fcm>::new(
            reserved_cid,
            false,
            conn_info,
            auth_store,
            init_hyper_ratchet,
        )
        .await?;
        log::trace!(target: "citadel", "Created impersonal CNAC ...");
        self.persistence_handler.save_cnac(&new_cnac).await?;

        Ok(new_cnac)
    }

    /// whereas the HyperLAN server (Bob) runs `register_impersonal_hyperlan_client_network_account`, the registering
    /// HyperLAN Client (Alice) runs this function below
    pub async fn register_personal_hyperlan_server(
        &self,
        hyper_ratchet: R,
        creds: ProposedCredentials,
        conn_info: ConnectionInfo,
    ) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let valid_cid = self
            .persistence_handler
            .get_cid_by_username(creds.username());
        let client_auth_store = creds.into_auth_store();
        let cnac = ClientNetworkAccount::<R, Fcm>::new_from_network_personal(
            valid_cid,
            hyper_ratchet,
            client_auth_store,
            conn_info,
        )
        .await?;
        self.persistence_handler.save_cnac(&cnac).await?;

        Ok(cnac)
    }

    /// Determines if the HyperLAN client is registered
    /// Impersonal mode
    pub async fn hyperlan_cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.persistence_handler.cid_is_registered(cid).await
    }

    /// Returns a list of impersonal cids
    pub async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler
            .get_registered_impersonal_cids(limit)
            .await
    }

    /// Returns the CNAC with the supplied CID
    pub async fn get_client_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler.get_cnac_by_cid(cid).await
    }

    /// Gets username by CID
    pub async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.persistence_handler.get_username_by_cid(cid).await
    }

    /// Gets full name by CID
    pub async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.persistence_handler.get_full_name_by_cid(cid).await
    }

    /// Gets user info for all the given CIDs, omitting any invalid users from the returned values
    pub async fn get_peer_info_from_cids(&self, cids: &[u64]) -> HashMap<u64, Option<PeerInfo>> {
        let mut peer_info = HashMap::new();
        let mut queue = FuturesOrdered::<
            Pin<Box<dyn Future<Output = Result<Option<CNACMetadata>, AccountError>>>>,
        >::new();
        for cid in cids {
            queue.push_back(Box::pin(self.persistence_handler.get_client_metadata(*cid)))
        }
        let mut results = futures::executor::block_on(queue.collect::<Vec<_>>());
        let metadata: Vec<&Option<CNACMetadata>> = results
            .iter_mut()
            .map(|result| result.as_ref().unwrap_or(&None))
            .collect();
        let _: Vec<_> = cids
            .iter()
            .zip(metadata.into_iter())
            .map(|(&cid, user_data)| {
                peer_info.insert(
                    cid,
                    user_data.as_ref().map(|some| PeerInfo {
                        cid: some.cid,
                        username: some.username.clone(),
                        full_name: some.full_name.clone(),
                    }),
                )
            })
            .collect();
        peer_info
    }

    /// Returns the first username detected. This is not advised to use, because overlapping usernames are entirely possible.
    /// Instead, use get_client_by_cid, as the cid is unique unlike the username
    pub async fn get_client_by_username<T: AsRef<str>>(
        &self,
        username: T,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler
            .get_client_by_username(username.as_ref())
            .await
    }

    /// Returns the number of accounts purged
    pub async fn purge(&self) -> Result<usize, AccountError> {
        self.persistence_handler.purge().await
    }

    /// Does not execute the registration process between two peers; it only consolidates the changes to the local CNAC
    /// returns true if success, false otherwise
    pub async fn register_hyperlan_p2p_at_endpoints<T: Into<String>>(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        adjacent_username: T,
    ) -> Result<(), AccountError> {
        let adjacent_username = adjacent_username.into();
        log::trace!(target: "citadel", "Registering {} ({}) to {} (local/endpoints)", &adjacent_username, peer_cid, implicated_cid);
        self.persistence_handler
            .register_p2p_as_client(implicated_cid, peer_cid, adjacent_username)
            .await
    }

    /// Registers the two accounts together at the server
    pub async fn register_hyperlan_p2p_as_server(
        &self,
        cid0: u64,
        cid1: u64,
    ) -> Result<(), AccountError> {
        self.persistence_handler
            .register_p2p_as_server(cid0, cid1)
            .await
    }

    /// Deletes a client by cid. Returns true if a success
    #[allow(unused_results)]
    pub async fn delete_client_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        self.persistence_handler.delete_cnac_by_cid(cid).await
    }

    /// Gets a list of hyperlan peers for the given peer
    pub async fn get_hyperlan_peer_list(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler
            .get_hyperlan_peer_list(implicated_cid)
            .await
    }

    /// Finds a hyperlan peer for a given user. Returns the implicated CID and mutual peer info
    pub async fn find_target_information(
        &self,
        implicated_user: impl Into<UserIdentifier>,
        target_user: impl Into<UserIdentifier>,
    ) -> Result<Option<(u64, MutualPeer)>, AccountError> {
        let implicated_cid = match implicated_user.into() {
            UserIdentifier::ID(id) => id,

            UserIdentifier::Username(uname) => {
                self.get_persistence_handler().get_cid_by_username(&uname)
            }
        };

        match target_user.into() {
            UserIdentifier::ID(peer_cid) => Ok(self
                .persistence_handler
                .get_hyperlan_peer_by_cid(implicated_cid, peer_cid)
                .await?
                .map(|r| (implicated_cid, r))),

            UserIdentifier::Username(uname) => Ok(self
                .persistence_handler
                .get_hyperlan_peer_by_username(implicated_cid, &uname)
                .await?
                .map(|r| (implicated_cid, r))),
        }
    }

    /// Converts a user identifier into its cid
    pub async fn find_local_user_information(
        &self,
        implicated_user: impl Into<UserIdentifier>,
    ) -> Result<Option<u64>, AccountError> {
        match implicated_user.into() {
            UserIdentifier::ID(cid) => Ok(Some(cid)),
            UserIdentifier::Username(username) => {
                let cid = self.persistence_handler.get_cid_by_username(&username);
                Ok(self
                    .persistence_handler
                    .get_client_metadata(cid)
                    .await?
                    .map(|r| r.cid))
            }
        }
    }

    /// Converts a user identifier into its cid
    pub async fn find_cnac_by_identifier(
        &self,
        implicated_user: impl Into<UserIdentifier>,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        match implicated_user.into() {
            UserIdentifier::ID(cid) => self.get_client_by_cid(cid).await,
            UserIdentifier::Username(username) => self.get_client_by_username(username).await,
        }
    }

    /// Returns the persistence handler
    #[doc(hidden)]
    pub fn get_persistence_handler(&self) -> &PersistenceHandler<R, Fcm> {
        &self.persistence_handler
    }

    /// Returns the misc settings
    pub fn get_misc_settings(&self) -> &ServerMiscSettings {
        &self.server_misc_settings
    }

    /// Gets the backend type
    pub fn get_backend_type(&self) -> &BackendType {
        &self.backend_ty
    }
}
