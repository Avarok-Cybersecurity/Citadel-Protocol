use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::{RwLock, RwLockWriteGuard, RwLockReadGuard};
//use future_parking_lot::rwlock::{FutureReadable, FutureWriteable, RwLock};
use log::info;
use rand::{random, RngCore, thread_rng};
use serde::{Deserialize, Serialize};

use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet};
use hyxe_fs::env::DirectoryStore;
use hyxe_fs::misc::get_pathbuf;
use hyxe_fs::prelude::SyncIO;

use crate::backend::PersistenceHandler;
use crate::client_account::ClientNetworkAccount;
use crate::hypernode_account::HyperNodeAccountInformation;
use crate::misc::AccountError;
use crate::auth::DeclaredAuthenticationMode;

#[derive(Serialize, Deserialize, Default)]
/// Inner device
pub struct NetworkAccountInner<R: Ratchet, Fcm: Ratchet> {
    /// The global connection info for this conn
    pub(crate) connection_info: Option<ConnectionInfo>,
    /// Contains a list of registered HyperLAN CIDS. We only store values herein if using the local filesystem
    pub cids_registered: HashMap<u64, String>,
    /// for serialization
    #[serde(with = "crate::external_services::fcm::data_structures::none")]
    pub persistence_handler: Option<PersistenceHandler<R, Fcm>>,
    /// The NID
    nid: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// For saving the state of client-side connections
pub struct ConnectionInfo {
    /// The address of the adjacent node
    pub addr: SocketAddr
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// For saving the state of client-side connections
pub enum ConnectProtocol {
    /// Uses the transmission control protocol
    Tcp,
    /// The domain
    Tls(Option<String>),
    /// Quic
    Quic(Option<String>)
}

impl ConnectProtocol {
    /// Gets domain
    pub fn get_domain(&self) -> Option<String> {
        match self {
            Self::Tcp => None,
            Self::Tls(t) => t.clone(),
            Self::Quic(t) => t.clone()
        }
    }
}

/// Thread-safe handle
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkAccount<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    /// the inner device
    #[serde(bound = "")]
    inner: Arc<(u64, RwLock<NetworkAccountInner<R, Fcm>>)>
}

impl<R: Ratchet, Fcm: Ratchet> NetworkAccount<R, Fcm> {
    /// This should be called at runtime if the current node does not have a detected NAC. This is NOT for
    /// creating a NAC for new server connections; instead, use `new_from_recent_connection`.
    pub fn new(directory_store: &DirectoryStore) -> Result<NetworkAccount<R, Fcm>, AccountError> {
        let nid = random::<u64>() ^ random::<u64>();
        let local_path = get_pathbuf(directory_store.inner.read().nac_node_default_store_location.as_str());
        let cids_registered = HashMap::new();
        info!("Attempting to create a NAC at {:?}", &local_path);

        Ok(Self { inner: Arc::new((nid, RwLock::new(NetworkAccountInner::<R, Fcm> { cids_registered, nid, connection_info: None, persistence_handler: None}))) })
    }

    /// When a new connection is created, this may be called
    /// 'proto' should be None if calling from a server, and Some if from a client
    /// Server keeps addr in case PINNED_ADDR_MODE is enabled
    #[allow(unused_results)]
    pub fn new_from_recent_connection(nid: u64, addr: SocketAddr, persistence_handler: PersistenceHandler<R, Fcm>) -> NetworkAccount<R, Fcm> {
        Self {
            inner: Arc::new((nid, RwLock::new(NetworkAccountInner::<R, Fcm> {
                cids_registered: HashMap::new(),
                nid,
                connection_info: Some(ConnectionInfo { addr }),
                persistence_handler: Some(persistence_handler)
            }))),
        }
    }

    /// Gets the persistence handler
    pub fn persistence_handler(&self) -> Option<PersistenceHandler<R, Fcm>> {
        self.read().persistence_handler.clone()
    }

    /// This should be called during the registration phase client-side. It generates a list of CIDs that are available
    ///
    /// NOTE: This can only be run client-side on a node. Otherwise, this will return None
    pub fn client_only_generate_possible_cids(&self) -> Vec<u64> {
        let read = self.read();
        let mut rng = thread_rng();
        let cids_registered = &read.cids_registered;
        let mut ret = Vec::with_capacity(10);
        loop {
            let possible = rng.next_u64();
            if !cids_registered.contains_key(&possible) {
                ret.push(possible);
                if ret.len() == 10 {
                    return ret;
                }
            }
        }
    }

    /// Returns true if the given CID exists
    pub fn cid_exists_filesystem(&self, cid: u64) -> bool {
        self.read().cids_registered.contains_key(&cid)
    }

    /// Scans a list for a valid CID
    pub fn find_first_valid_cid_filesystem<T: AsRef<[u64]>>(&self, possible_cids: T) -> Option<u64> {
        let read = self.read();
        let possible_cids = possible_cids.as_ref();
        let cids_registered = &read.cids_registered;
        possible_cids.iter().find(|res| !cids_registered.contains_key(*res))
            .cloned()
    }

    /// This should be called after registration occurs
    #[allow(unused_results)]
    pub fn register_cid_filesystem<T: Into<String>>(&self, cid: u64, username: T) -> Result<(), AccountError>{
        let mut write = self.write();
        let cids_registered = &mut write.cids_registered;
        if let std::collections::hash_map::Entry::Vacant(e) = cids_registered.entry(cid) {
            e.insert(username.into());
            Ok(())
        } else {
            log::error!("Overwrote pre-existing account that lingered in the NID list. Report to developers");
            Err(AccountError::ClientExists(cid))
        }
    }

    /// Determines if a username exists
    pub fn username_exists_filesystem<T: AsRef<str>>(&self, username: T) -> bool {
        let read = self.read();
        let username = username.as_ref();
        let cids_registered = &read.cids_registered;
        cids_registered.values().any(|stored_username| stored_username.as_str() == username)
    }

    /// Returns true if the removal was a success
    pub fn remove_registered_cid_filesystem(&self, cid: u64) -> bool {
        let mut write = self.write();
        write.cids_registered.remove(&cid).is_some()
    }

    /// Creates a new CNAC given the input of a NAC and other information (e.g., username, password). The NAC can be constructed via an inbound packet's payload, or,
    /// constructed locally (if on a server) using known data. If the CNAC is constructed successfully, then the CID is added into the database.
    ///
    /// This will panic if self does not have a config file.
    ///
    /// Note: If the local node is the server node, then nac_other should be the client's NAC. This should always be made at a server anyways
    #[allow(unused_results)]
    pub async fn create_client_account(&self, reserved_cid: u64, nac_other: Option<NetworkAccount<R, Fcm>>, auth_store: DeclaredAuthenticationMode, base_hyper_ratchet: R, fcm_keys: Option<FcmKeys>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        if nac_other.is_none() {
            info!("WARNING: You are using debug mode. The supplied NAC is none, and will receive THIS nac in its place (unit tests only)");
        }

        // We must lock the config to ensure that the obtained CID gets added into the database before any competing threads may get called
        log::info!("Checking username {} for correspondence ...", auth_store.username());

        let persistence_handler = self.inner.1.read().persistence_handler.clone().ok_or_else(|| AccountError::Generic("Persistence handler not loaded".to_string()))?;

        let username = auth_store.username().to_string();

        if persistence_handler.username_exists(&username).await? {
            return Err(AccountError::Generic(format!("Username {} already exists!", &username)))
        }

        // cnac gets saved below
        let cnac = ClientNetworkAccount::<R, Fcm>::new(reserved_cid, false, nac_other.unwrap_or_else(|| self.clone()), auth_store, base_hyper_ratchet, persistence_handler.clone(), fcm_keys).await?;

        // So long as the CNAC creation succeeded, we can confidently add the CID into the config
        persistence_handler.register_cid_in_nac(reserved_cid, &username).await.map(|_| cnac)
    }

    /// Returns the IP address which belongs to the NID enclosed herein.
    /// if peer_cid is None, will get the HyperLAN conn info
    #[allow(deprecated)]
    pub fn get_conn_info(&self) -> Option<ConnectionInfo> {
        self.read().connection_info.clone()
    }

    /// This sets the IP address. This automatically determines if the address is IPv6 or IPv4, and then it places
    /// it inside the correct field of self
    #[allow(unused_results)]
    pub fn update_conn_info(&self, new_info: ConnectionInfo) {
        self.write().connection_info = Some(new_info)
    }

    /// Reads futures-style
    pub fn read(&self) -> RwLockReadGuard<NetworkAccountInner<R, Fcm>> {
        self.inner.1.read()
    }

    /// Reads futures-style
    pub fn write(&self) -> RwLockWriteGuard<NetworkAccountInner<R, Fcm>> {
        self.inner.1.write()
    }

    /// blocking version of async_save_to_local_fs
    pub fn save_to_local_fs(&self) -> Result<(), AccountError> {
        let inner_nac = self.write();
        let path = get_pathbuf(inner_nac.persistence_handler.as_ref().unwrap().directory_store().inner.read().nac_node_default_store_location.as_str());

        let path_no_filename = path.parent().unwrap().clone();
        let path_name = path_no_filename.display().to_string();
        info!("Storing NAC to directory: {}", &path_name);
        hyxe_fs::system_file_manager::make_dir_all_blocking(path_no_filename).map_err(|err| AccountError::Generic(err.to_string()))?;
        info!("Dirs created for {}", path_name);
        inner_nac.serialize_to_local_fs(path).map_err(|err| AccountError::IoError(err.to_string()))?;
        info!("Serialized to local fs for {}", path_name);
        Ok(())
    }

    /// Stores the PersistenceHandler internally
    pub fn store_persistence_handler(&self, persistence_handler: &PersistenceHandler<R, Fcm>) {
        self.write().persistence_handler = Some(persistence_handler.clone());
    }
}

impl<R: Ratchet, Fcm: Ratchet> Debug for NetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NID: {} | CIDs registered: {:?}", self.get_id(), &self.read().cids_registered)
    }
}

impl<R: Ratchet, Fcm: Ratchet> HyperNodeAccountInformation for NetworkAccount<R, Fcm> {
    fn get_id(&self) -> u64 {
        self.inner.0
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<NetworkAccountInner<R, Fcm>> for NetworkAccount<R, Fcm> {
    fn from(inner: NetworkAccountInner<R, Fcm>) -> Self {
        Self { inner: Arc::new((inner.nid, RwLock::new(inner))) }
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "addr: {}", self.addr)
    }
}