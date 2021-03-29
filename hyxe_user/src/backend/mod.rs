use std::sync::Arc;
use std::ops::Deref;
use async_trait::async_trait;
use crate::misc::AccountError;
use crate::client_account::ClientNetworkAccount;
use std::path::PathBuf;
use hyxe_fs::env::DirectoryStore;
use crate::prelude::NetworkAccount;
use crossbeam_utils::sync::ShardedLock;
use std::collections::HashMap;
use hyxe_crypt::hyper_ratchet::{Ratchet, HyperRatchet};
use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use hyxe_crypt::fcm::keys::FcmKeys;

#[cfg(feature = "enterprise")]
/// Implementation for the SQL backend
pub mod mysql_backend;
/// Implementation for the default filesystem backend
pub mod filesystem_backend;

/// Used when constructing the account manager
#[derive(Clone)]
pub enum BackendType {
    /// Synchronization will occur on the filesystem
    Filesystem,
    #[cfg(feature = "enterprise")]
    /// Synchronization will occur on a remote SQL database
    MySQLDatabase(String)
}

impl BackendType {
    /// For requesting the use of the FilesystemBackend driver
    pub const fn filesystem() -> BackendType {
        BackendType::Filesystem
    }

    /// For requesting the use of the SqlBackend driver. Url should be in the form:
    /// "mysql://username:password@ip/database"
    ///
    /// PostgreSQL, MSSQL, MySQL, SqLite supported
    #[cfg(feature = "enterprise")]
    pub fn my_sql<T: Into<String>>(url: T) -> BackendType {
        BackendType::MySQLDatabase(url.into())
    }
}

/// An interface for synchronizing information do differing target
#[async_trait]
pub trait BackendConnection<R: Ratchet, Fcm: Ratchet>: Send + Sync {
    /// This should be run for handling any types of underlying connect operations
    async fn connect(&mut self, directory_store: &DirectoryStore) -> Result<(), AccountError>;
    /// This is called once the PersistenceHandler is loaded
    fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError>;
    /// Determines if connected or not
    async fn is_connected(&self) -> Result<bool, AccountError>;
    /// Saves the entire cnac to the DB
    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError>;
    /// Find a CNAC by cid
    async fn get_cnac_by_cid(&self, cid: u64, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError>;
    /// Gets the client by username
    async fn get_client_by_username(&self, username: &str, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError>;
    /// Determines if a CID is registered
    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError>;
    /// deletes a CNAC
    async fn delete_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError>;
    /// Removes a CNAC by cid
    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError>;
    /// Saves all CNACs and local NACs
    async fn save_all(&self) -> Result<(), AccountError>;
    /// Removes all CNACs
    async fn purge(&self) -> Result<usize, AccountError>;
    /// Returns the number of clients
    async fn client_count(&self) -> Result<usize, AccountError>;
    /// Maybe generates a local save path, only if required by the implementation
    fn maybe_generate_cnac_local_save_path(&self, cid: u64, is_personal: bool) -> Option<PathBuf>;
    /// Searches the internal database/nac for the first cid that is unused
    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError>;
    /// Determines if a username exists
    async fn username_exists(&self, username: &str) -> Result<bool, AccountError>;
    /// Registers a CID to the db/fs, preventing future registrants from using the same values
    async fn register_cid(&self, cid: u64, username: &str) -> Result<(), AccountError>;
    /// Returns a list of impersonal cids
    async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError>;
    /// Gets the username by CID
    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError>;
    /// Gets the CID by username
    async fn get_cid_by_username(&self, username: &str) -> Result<Option<u64>, AccountError>;
    /// Deletes a client by username
    async fn delete_client_by_username(&self, username: &str) -> Result<(), AccountError>;
    /// Registers two peers together
    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError>;
    /// Deregisters two peers from each other
    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError>;
    /// Gets the FCM keys for a peer
    async fn get_fcm_keys_for(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<FcmKeys>, AccountError>;
    /// Determines if two peers are registered to each other
    async fn is_registered_to(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError>;
    /// Returns a list of hyperlan peers for the client
    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError>;
    /// Stores the CNAC inside the hashmap, if possible (may be no-op on database)
    fn store_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>);
    /// Determines if a remote db is used
    fn uses_remote_db(&self) -> bool;
    /// Returns the filesystem list
    fn get_local_map(&self) -> Option<Arc<ShardedLock<HashMap<u64, ClientNetworkAccount<R, Fcm>>>>>;
    /// Returns the local nac
    fn local_nac(&self) -> &NetworkAccount<R, Fcm>;
    #[allow(unused_results, unused_must_use)]
    /// spawns to thread pool
    fn spawn_save_task_to_threadpool(self: Arc<Self>, cnac: ClientNetworkAccount<R, Fcm>) where Self: 'static {
        tokio::task::spawn(async move { self.save_cnac(cnac); });
    }
}

/// This is what every C/NAC gets. This gets called before making I/O operations
pub struct PersistenceHandler<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    inner: Arc<dyn BackendConnection<R, Fcm>>,
    directory_store: DirectoryStore
}

impl<R: Ratchet, Fcm: Ratchet> PersistenceHandler<R, Fcm> {
    /// Creates a new persistence handler
    pub fn new<T: BackendConnection<R, Fcm> + 'static>(inner: T, directory_store: DirectoryStore) -> Self {
        Self { inner: Arc::new(inner), directory_store }
    }

    /// Returns the inner directory store
    pub fn directory_store(&self) -> &DirectoryStore {
        &self.directory_store
    }
}

impl<R: Ratchet, Fcm: Ratchet> Deref for PersistenceHandler<R, Fcm> {
    type Target = Arc<dyn BackendConnection<R, Fcm>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<R: Ratchet, Fcm: Ratchet> Clone for PersistenceHandler<R, Fcm> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), directory_store: self.directory_store.clone() }
    }
}