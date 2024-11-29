use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;

use citadel_crypt::fcm::fcm_ratchet::ThinRatchet;
use citadel_crypt::stacked_ratchet::{Ratchet, StackedRatchet};

#[cfg(all(feature = "redis", not(coverage)))]
use crate::backend::redis_backend::RedisConnectionOptions;
#[cfg(all(feature = "sql", not(coverage)))]
use crate::backend::sql_backend::SqlConnectionOptions;
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use citadel_crypt::streaming_crypt_scrambler::ObjectSource;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use citadel_types::proto::{ObjectTransferStatus, VirtualObjectMetadata};
use citadel_types::user;
use citadel_types::user::MutualPeer;

/// Implementation for the default filesystem backend
#[cfg(feature = "filesystem")]
pub mod filesystem_backend;
/// Implementation for an in-memory backend. No synchronization occurs.
/// This is useful for no-fs environments
pub mod memory;
#[cfg(all(feature = "redis", not(coverage)))]
/// Implementation for the redis backend
pub mod redis_backend;
#[cfg(all(feature = "sql", not(coverage)))]
/// Implementation for the SQL backend
pub mod sql_backend;
/// Utils for the backend trait
#[allow(missing_docs)]
pub mod utils;

/// Used when constructing the account manager
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(variant_size_differences)]
pub enum BackendType {
    /// No true synchronization will occur; data is lost between program
    /// executions. Ideal for WASM environments that don't have filesystem
    /// access
    InMemory,
    /// Synchronization will occur on the filesystem
    #[cfg(feature = "filesystem")]
    Filesystem(String),
    #[cfg(all(feature = "sql", not(coverage)))]
    /// Synchronization will occur on a remote SQL database
    SQLDatabase(String, SqlConnectionOptions),
    #[cfg(all(feature = "redis", not(coverage)))]
    /// Synchronization will occur on a remote redis database
    Redis(String, RedisConnectionOptions),
}

impl BackendType {
    /// Creates a new [`BackendType`] given the provided `url`. Returns an error
    /// if the URL could not be parsed
    pub fn new<T: Into<String>>(url: T) -> Result<Self, AccountError> {
        let addr = url.into();
        #[cfg(all(feature = "redis", not(coverage)))]
        {
            if addr.starts_with("redis") {
                return Ok(BackendType::redis(addr));
            }
        }

        #[cfg(all(feature = "sql", not(coverage)))]
        {
            if addr.starts_with("mysql")
                || addr.starts_with("postgres")
                || addr.starts_with("sqlite")
            {
                return Ok(BackendType::sql(addr));
            }
        }

        #[cfg(all(feature = "filesystem", not(target_family = "wasm")))]
        {
            if addr.starts_with("file:") {
                return Ok(Self::filesystem(addr));
            }
        }

        Err(AccountError::msg(format!("The addr '{addr}' is not a valid target (hint: ensure either 'redis', 'sql' or 'filesystem' features are enabled when compiling")))
    }

    #[cfg(all(feature = "filesystem", not(target_family = "wasm")))]
    /// For requesting the use of the local filesystem as a backend
    /// URL format: file:/path/to/directory (unix) or file:C\windows\dir (windows)
    pub fn filesystem<T: Into<String>>(path: T) -> Self {
        Self::Filesystem(path.into().replace("file:", ""))
    }

    #[cfg(all(feature = "redis", not(coverage)))]
    /// For requesting the use of the redis backend driver.
    /// URL format: redis://[<username>][:<password>@]<hostname>[:port][/<db>]
    /// If unix socket support is available:
    /// URL format: redis+unix:///<path>[?db=<db>[&pass=<password>][&user=<username>]]
    pub fn redis<T: Into<String>>(url: T) -> BackendType {
        Self::redis_with(url, Default::default())
    }

    #[cfg(all(feature = "redis", not(coverage)))]
    /// Like [`Self::redis`], but with custom options
    pub fn redis_with<T: Into<String>>(url: T, opts: RedisConnectionOptions) -> BackendType {
        BackendType::Redis(url.into(), opts)
    }

    /// For requesting the use of the SqlBackend driver. Url should be in the form:
    /// "mysql://username:password@ip/database"
    /// "postgres:// [...]"
    /// "sqlite:/path/to/file.db"
    ///
    /// PostgreSQL, MySQL, SqLite supported
    #[cfg(all(feature = "sql", not(coverage)))]
    pub fn sql<T: Into<String>>(url: T) -> BackendType {
        BackendType::SQLDatabase(url.into(), Default::default())
    }

    /// Like [`Self::sql`], but with custom options
    #[cfg(all(feature = "sql", not(coverage)))]
    pub fn sql_with<T: Into<String>>(url: T, opts: SqlConnectionOptions) -> BackendType {
        BackendType::SQLDatabase(url.into(), opts)
    }
}

/// An interface for synchronizing information do differing target
#[async_trait]
pub trait BackendConnection<R: Ratchet, Fcm: Ratchet>: Send + Sync {
    /// This should be run for handling any types of underlying connect operations
    async fn connect(&mut self) -> Result<(), AccountError>;
    /// Determines if connected or not
    async fn is_connected(&self) -> Result<bool, AccountError>;
    /// Saves the entire cnac to the DB
    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError>;
    /// Find a CNAC by cid
    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError>;
    /// Gets the client by username
    async fn get_client_by_username(
        &self,
        username: &str,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.get_cnac_by_cid(user::username_to_cid(username)).await
    }
    /// Determines if a CID is registered
    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError>;
    /// Removes a CNAC by cid
    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError>;
    /// Removes all CNACs
    async fn purge(&self) -> Result<usize, AccountError>;
    /// Determines if a username exists
    async fn username_exists(&self, username: &str) -> Result<bool, AccountError> {
        self.cid_is_registered(user::username_to_cid(username))
            .await
    }
    /// Returns a list of impersonal cids
    async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError>;
    /// Gets the username by CID
    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError>;
    /// Gets the full name by CID
    async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError>;
    /// Gets the CID by username
    fn get_cid_by_username(&self, username: &str) -> u64 {
        user::username_to_cid(username)
    }
    /// Registers two peers together
    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError>;
    /// registers p2p as client
    async fn register_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError>;
    /// Deregisters two peers from each other
    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError>;
    /// Deregisters two peers from each other
    async fn deregister_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError>;
    /// Returns a list of hyperlan peers for the client
    async fn get_hyperlan_peer_list(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError>;
    /// Returns the metadata for a client
    async fn get_client_metadata(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError>;
    /// Gets all the metadata for many clients
    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError>;
    /// Gets hyperlan peer
    async fn get_hyperlan_peer_by_cid(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError>;
    /// Determines if the peer exists or not
    async fn hyperlan_peer_exists(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError>;
    /// Determines if the input cids are mutual to the implicated cid in order
    async fn hyperlan_peers_are_mutuals(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError>;
    /// Returns a set of PeerMutual containers
    async fn get_hyperlan_peers(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError>;
    /// Gets hyperland peer by username
    async fn get_hyperlan_peer_by_username(
        &self,
        implicated_cid: u64,
        username: &str,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.get_hyperlan_peer_by_cid(implicated_cid, user::username_to_cid(username))
            .await
    }
    /// Gets all peers for client
    async fn get_hyperlan_peer_list_as_server(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError>;
    /// Synchronizes the list locally. Returns true if needs to be saved
    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError>;
    /// Returns a vector of bytes from the byte map
    async fn get_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError>;
    /// Removes a value from the byte map, returning the previous value
    async fn remove_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError>;
    /// Stores a value in the byte map, either creating or overwriting any pre-existing value
    async fn store_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError>;
    /// Obtains a list of K,V pairs such that they reside inside `key`
    async fn get_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError>;
    /// Obtains a list of K,V pairs such that `needle` is a subset of the K value
    async fn remove_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError>;
    /// Streams an object to the backend
    async fn stream_object_to_backend(
        &self,
        source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: &VirtualObjectMetadata,
        status_tx: UnboundedSender<ObjectTransferStatus>,
    ) -> Result<(), AccountError>;
    /// Returns the encrypted file from the virtual filesystem into the provided buffer.
    /// The security level used to encrypt the data is also returned
    #[allow(unused_variables)]
    async fn revfs_get_file_info(
        &self,
        cid: u64,
        virtual_path: std::path::PathBuf,
    ) -> Result<(Box<dyn ObjectSource>, VirtualObjectMetadata), AccountError> {
        Err(AccountError::Generic(
            "The target does not support the RE-VFS protocol".into(),
        ))
    }
    /// Deletes the encrypted file from the virtual filesystem
    #[allow(unused_variables)]
    async fn revfs_delete(
        &self,
        cid: u64,
        virtual_path: std::path::PathBuf,
    ) -> Result<(), AccountError> {
        Err(AccountError::Generic(
            "The target does not support the RE-VFS protocol".into(),
        ))
    }
}

/// This is what every C/NAC gets. This gets called before making I/O operations
pub struct PersistenceHandler<R: Ratchet = StackedRatchet, Fcm: Ratchet = ThinRatchet> {
    inner: Arc<dyn BackendConnection<R, Fcm>>,
}

impl<R: Ratchet, Fcm: Ratchet> PersistenceHandler<R, Fcm> {
    /// Creates a new persistence handler, connecting to the backend then
    /// returning self
    pub async fn create<T: BackendConnection<R, Fcm> + 'static>(
        mut inner: T,
    ) -> Result<Self, AccountError> {
        inner.connect().await?;
        Ok(Self {
            inner: Arc::new(inner),
        })
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
        Self {
            inner: self.inner.clone(),
        }
    }
}
