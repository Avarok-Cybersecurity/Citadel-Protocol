use crate::network_account::NetworkAccount;
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use std::net::SocketAddr;
use crate::prelude::{HyperNodeAccountInformation, UserIdentifier};
use crate::misc::AccountError;
use hyxe_fs::hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hypernode_account::NAC_SERIALIZED_EXTENSION;
use hyxe_fs::env::DirectoryStore;
use crate::backend::{BackendType, PersistenceHandler};
use crate::backend::filesystem_backend::FilesystemBackend;
use crate::backend::BackendConnection;
use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::fcm::fcm_ratchet::ThinRatchet;
use hyxe_crypt::argon::argon_container::{ArgonSettings, ArgonDefaultServerSettings};
use crate::external_services::{ServicesHandler, ServicesConfig};
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::server_misc_settings::ServerMiscSettings;

/// The default manager for handling the list of users stored locally. It also allows for user creation, and is used especially
/// for when creating a new user via the registration service.
#[derive(Clone)]
pub struct AccountManager<R: Ratchet = HyperRatchet, Fcm: Ratchet = ThinRatchet> {
    services_handler: ServicesHandler,
    persistence_handler: PersistenceHandler<R, Fcm>,
    node_argon_settings: ArgonSettings,
    server_misc_settings: ServerMiscSettings
}

impl<R: Ratchet, Fcm: Ratchet> AccountManager<R, Fcm> {
    /// `bind_addr`: Required for determining the local save directories for this instance
    /// `home_dir`: Optional. Overrides the default storage location for files
    /// `server_argon_settings`: Security settings used for saving the password to the backend. The AD will be replaced each time a new user is created, so it can be empty
    #[allow(unused_results)]
    pub async fn new(bind_addr: SocketAddr, home_dir: Option<String>, backend_type: BackendType, server_argon_settings: Option<ArgonDefaultServerSettings>, services_cfg: Option<ServicesConfig>, server_misc_settings: Option<ServerMiscSettings>) -> Result<Self, AccountError> {
        // The below map should locally store: impersonal mode CNAC's, as well as personal remote server CNAC's
        let directory_store = hyxe_fs::env::setup_directories(bind_addr, NAC_SERIALIZED_EXTENSION, home_dir)?;
        let services_handler = services_cfg.unwrap_or_default().into_services_handler().await?;

        let persistence_handler = match &backend_type {
            BackendType::Filesystem => {
                let mut backend = FilesystemBackend::from(directory_store.clone());
                backend.connect(&directory_store).await?;
                PersistenceHandler::new(backend, directory_store)
            }

            #[cfg(feature = "sql")]
            BackendType::SQLDatabase(..) => {
                use crate::backend::mysql_backend::SqlBackend;
                use std::convert::TryFrom;
                let mut backend = SqlBackend::try_from(backend_type).map_err(|_| AccountError::Generic("Invalid database URL format. Please check documentation for preferred format".to_string()))?;
                backend.connect(&directory_store).await?;
                PersistenceHandler::new(backend, directory_store)
            }

            #[cfg(feature = "redis")]
            BackendType::Redis(url, opts) => {
                use crate::backend::redis_backend::RedisBackend;
                let mut backend = RedisBackend::new(url.clone(), opts.clone());
                backend.connect(&directory_store).await?;
                PersistenceHandler::new(backend, directory_store)
            }
        };

        persistence_handler.post_connect(&persistence_handler).await?;

        if !persistence_handler.is_connected().await? {
            return Err(AccountError::msg("Unable to connect to remote database via account manager"))
        }

        log::info!(target: "lusna", "Successfully established connection to backend ...");

        #[cfg(feature = "localhost-testing")] {
            let _ = persistence_handler.purge().await?;
        }

        let this = Self { persistence_handler, services_handler, node_argon_settings: server_argon_settings.unwrap_or_default().into(), server_misc_settings: server_misc_settings.unwrap_or_default() };

        Ok(this)
    }

    /// Returns the directory store for this local node session
    pub fn get_directory_store(&self) -> &DirectoryStore {
        self.persistence_handler.directory_store()
    }

    /// Returns a reference to the services handler
    pub fn services_handler(&self) -> &ServicesHandler {
        &self.services_handler
    }

    /// Once a valid and decrypted stage 4 packet gets received by the server (Bob), this function should be called
    /// to create the new CNAC. The generated CNAC will be assumed to be an impersonal hyperlan client
    ///
    /// This also generates the argon-2id password hash
    pub async fn register_impersonal_hyperlan_client_network_account(&self, reserved_cid: u64, nac_other: NetworkAccount<R, Fcm>, creds: ProposedCredentials, init_hyper_ratchet: R) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let server_auth_store = creds.derive_server_container(&self.node_argon_settings, reserved_cid, self.get_misc_settings()).await?;
        let new_cnac = self.get_local_nac().create_client_account(reserved_cid, Some(nac_other), server_auth_store, init_hyper_ratchet).await?;
        log::trace!(target: "lusna", "Created impersonal CNAC ...");
        self.persistence_handler.save_cnac(new_cnac.clone()).await?;

        Ok(new_cnac)
    }

    /// whereas the HyperLAN server (Bob) runs `register_impersonal_hyperlan_client_network_account`, the registering
    /// HyperLAN Client (Alice) runs this function below
    pub async fn register_personal_hyperlan_server(&self, valid_cid: u64, hyper_ratchet: R, creds: ProposedCredentials, adjacent_nac: NetworkAccount<R, Fcm>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let client_auth_store = creds.into_auth_store(valid_cid);

        let username = client_auth_store.username().to_string();
        let cnac = ClientNetworkAccount::<R, Fcm>::new_from_network_personal(valid_cid, hyper_ratchet, client_auth_store, adjacent_nac, self.persistence_handler.clone()).await?;

        self.persistence_handler.register_cid_in_nac(cnac.get_id(), username.as_str()).await?;
        self.persistence_handler.save_cnac(cnac.clone()).await?;

        self.get_local_nac().save_to_local_fs()?;

        Ok(cnac)
    }

    /// Determines if the HyperLAN client is registered
    /// Impersonal mode
    pub async fn hyperlan_cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.persistence_handler.cid_is_registered(cid).await
    }

    /// Returns a list of impersonal cids
    pub async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler.get_registered_impersonal_cids(limit).await
    }

    /// Returns the CNAC with the supplied CID
    pub async fn get_client_by_cid(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler.get_cnac_by_cid(cid).await
    }

    /// Gets username by CID
    pub async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.persistence_handler.get_username_by_cid(cid).await
    }

    /// Returns the first username detected. This is not advised to use, because overlapping usernames are entirely possible.
    /// Instead, use get_client_by_cid, as the cid is unique unlike the cid
    pub async fn get_client_by_username<T: AsRef<str>>(&self, username: T) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler.get_client_by_username(username.as_ref()).await
    }

    /// Gets the CID by username
    pub async fn get_cid_by_username<T: AsRef<str>>(&self, username: T) -> Result<Option<u64>, AccountError> {
        self.persistence_handler.get_cid_by_username(username.as_ref()).await
    }

    /// Returns the number of accounts purged
    pub async fn purge(&self) -> Result<usize, AccountError> {
        self.persistence_handler.purge().await
    }

    /// Does not execute the registration process between two peers; it only consolidates the changes to the local CNAC
    /// returns true if success, false otherwise
    pub async fn register_hyperlan_p2p_at_endpoints<T: Into<String>>(&self, implicated_cid: u64, peer_cid: u64, adjacent_username: T) -> Result<(), AccountError> {
        let adjacent_username = adjacent_username.into();
        log::trace!(target: "lusna", "Registering {} ({}) to {} (local/endpoints)", &adjacent_username, peer_cid, implicated_cid);
        self.persistence_handler.register_p2p_as_client(implicated_cid, peer_cid, adjacent_username).await
    }

    /// Registers the two accounts together at the server
    pub async fn register_hyperlan_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        if let Some(mut rtdb_instance) = self.services_handler.rtdb_root_instance.clone() {
            let cid0_str = cid0.to_string();
            let cid1_str = cid1.to_string();

            #[derive(serde::Serialize)]
            struct PeerMint {
                registered: bool
            }

            let mint = PeerMint { registered: true };

            // We have root access, so we can edit anything we want here. Our goal is to insert each other's nodes inside the tree to allow each
            // other to insert messages inside the tree
            rtdb_instance.refresh()?;
            let _ = rtdb_instance.root().await.map_err(|err| AccountError::Generic(err.inner))?.child("users").child(cid0_str.as_str()).child("peers").final_node(cid1_str.as_str()).put(&mint).await.map_err(|err| AccountError::Generic(err.inner))?;
            let _ = rtdb_instance.root().await.map_err(|err| AccountError::Generic(err.inner))?.child("users").child(cid1_str.as_str()).child("peers").final_node(cid0_str.as_str()).put(&mint).await.map_err(|err| AccountError::Generic(err.inner))?;
        }

        self.persistence_handler.register_p2p_as_server(cid0, cid1).await
    }

    /// Deregisters the two peers from each other
    pub async fn deregister_hyperlan_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.persistence_handler.deregister_p2p_as_server(cid0, cid1).await
    }

    /// Deletes a client by cid. Returns true if a success
    #[allow(unused_results)]
    pub async fn delete_client_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        self.persistence_handler.delete_cnac_by_cid(cid).await
    }

    /// Gets a list of hyperlan peers for the given peer
    pub async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler.get_hyperlan_peer_list(implicated_cid).await
    }

    /// Finds a hyperlan peer for a given user. Returns the implicated CID and mutual peer info
    pub async fn find_target_information(&self, implicated_user: impl Into<UserIdentifier>, target_user: impl Into<UserIdentifier>) -> Result<Option<(u64, MutualPeer)>, AccountError> {
        let implicated_cid = match implicated_user.into() {
            UserIdentifier::ID(id) => {
                id
            }

            UserIdentifier::Username(uname) => {
                // TODO: optimize this into a single step
                self.get_persistence_handler().get_cid_by_username(&uname).await?.ok_or_else(||AccountError::msg("Implicated user does not exist"))?
            }
        };

        match target_user.into() {
            UserIdentifier::ID(peer_cid) => {
                Ok(self.persistence_handler.get_hyperlan_peer_by_cid(implicated_cid, peer_cid).await?.map(|r| (implicated_cid, r)))
            }

            UserIdentifier::Username(uname) => {
                Ok(self.persistence_handler.get_hyperlan_peer_by_username(implicated_cid, &uname).await?.map(|r| (implicated_cid, r)))
            }
        }
    }

    /// Converts a user identifier into its cid
    pub async fn find_local_user_information(&self, implicated_user: impl Into<UserIdentifier>) -> Result<Option<u64>, AccountError> {
        match implicated_user.into() {
            UserIdentifier::ID(cid) => Ok(Some(cid)),
            UserIdentifier::Username(username) => self.persistence_handler.get_cid_by_username(username.as_str()).await
        }
    }

    /// Converts a user identifier into its cid
    pub async fn find_cnac_by_identifier(&self, implicated_user: impl Into<UserIdentifier>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        match implicated_user.into() {
            UserIdentifier::ID(cid) => self.get_client_by_cid(cid).await,
            UserIdentifier::Username(username) => self.get_client_by_username(username).await
        }
    }

    /// returns the local nac
    pub fn get_local_nac(&self) -> &NetworkAccount<R, Fcm> {
        self.persistence_handler.local_nac()
    }

    /// Returns the persistence handler
    pub fn get_persistence_handler(&self) -> &PersistenceHandler<R, Fcm> {
        &self.persistence_handler
    }

    /// Purges the entire home directory for this node
    pub async fn purge_home_directory(&self) -> Result<(), AccountError> {
        let _ = self.purge().await?;
        let home = self.get_directory_store().inner.read().hyxe_home.clone();
        log::trace!(target: "lusna", "Purging program home directory: {:?}", &home);
        tokio::fs::remove_dir_all(home).await.map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Returns the misc settings
    pub fn get_misc_settings(&self) -> &ServerMiscSettings {
        &self.server_misc_settings
    }

    /// Returns the NID of the local system
    pub fn get_local_nid(&self) -> u64 {
        self.get_local_nac().get_id()
    }
}