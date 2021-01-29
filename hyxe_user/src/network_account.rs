use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;
use async_trait::async_trait;
//use future_parking_lot::rwlock::{FutureReadable, FutureWriteable, RwLock};
use log::info;
use rand::random;
use secstr::SecVec;
use serde::{Deserialize, Serialize};

use hyxe_fs::misc::get_pathbuf;
use hyxe_fs::prelude::SyncIO;

use crate::client_account::ClientNetworkAccount;
use crate::hypernode_account::HyperNodeAccountInformation;
use crate::misc::AccountError;
use crate::server_config_handler::username_has_invalid_symbols;
use crossbeam_utils::sync::{ShardedLock, ShardedLockWriteGuard, ShardedLockReadGuard};
use std::fmt::Debug;
use serde::export::Formatter;
use hyxe_fs::hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_fs::env::DirectoryStore;

#[derive(Serialize, Deserialize, Default)]
/// Inner device
pub struct NetworkAccountInner {
    /// The global IPv4 address for this node
    pub(crate) global_ipv4: Option<SocketAddrV4>,
    /// The global IPv6 address for this node
    pub(crate) global_ipv6: Option<SocketAddrV6>,
    /// Contains a list of registered HyperLAN CIDS
    pub cids_registered: HashMap<u64, String>,
    /// for serialization
    #[serde(skip)]
    pub dirs: Option<DirectoryStore>,
    /// The NID
    nid: u64,
}

/// Thread-safe handle
#[derive(Default, Clone)]
pub struct NetworkAccount {
    /// the inner device
    inner: Arc<(u64, ShardedLock<NetworkAccountInner>)>
}

impl NetworkAccount {
    /// This should be called at runtime if the current node does not have a detected NAC. This is NOT for
    /// creating a NAC for new server connections; instead, use `new_from_recent_connection`.
    pub fn new_local(dirs: &DirectoryStore) -> Result<NetworkAccount, AccountError<String>> {
        let nid = random::<u64>() ^ random::<u64>();
        let (global_ipv4, global_ipv6) = (None, None);
        let local_save_path = get_pathbuf(dirs.inner.read().nac_node_default_store_location.as_str());
        let dirs = Some(dirs.clone());
        info!("Attempting to create a NAC at {}", local_save_path.to_str().unwrap());
        Ok(Self { inner: Arc::new((nid, ShardedLock::new(NetworkAccountInner { cids_registered: HashMap::new(), nid, global_ipv4, global_ipv6, dirs}))) })
    }

    /// Saves the file to the local FS
    #[allow(unused_results)]
    pub fn spawn_save_task_on_threadpool(&self) {
        let this = self.clone();
        tokio::task::spawn(this.async_save_to_local_fs());
    }

    /// When a new connection is created, this may be called
    pub fn new_from_recent_connection(nid: u64, addr: SocketAddr, dir_store: DirectoryStore) -> NetworkAccount {
        let (global_ipv4, global_ipv6) = {
            if addr.is_ipv4() {
                (Some(SocketAddrV4::from_str(addr.to_string().as_str()).unwrap()), None)
            } else {
                (None, Some(SocketAddrV6::from_str(addr.to_string().as_str()).unwrap()))
            }
        };

        Self {
            inner: Arc::new((nid, ShardedLock::new(NetworkAccountInner {
                cids_registered: HashMap::new(),
                nid,
                global_ipv4,
                global_ipv6,
                dirs: Some(dir_store)
            }))),
        }
    }

    /// Once the [NetworkAccountInner] is loaded, this should be called. It internally updates the save path
    pub fn new_from_local_fs(inner: NetworkAccountInner) -> Self {
        Self { inner: Arc::new((inner.nid, ShardedLock::new(inner))) }
    }

    /// When a CNAC loads its internally encrypted [NetworkAccount]
    pub fn new_from_cnac(inner: NetworkAccountInner) -> Self {
        Self { inner: Arc::new((inner.nid, ShardedLock::new(inner))) }
    }

    /// This should be called during the registration phase. It generates a list of CIDs that are available
    pub fn generate_possible_cids(&self) -> Vec<u64> {
        let read = self.read();
        let mut ret = Vec::with_capacity(10);
        loop {
            let possible = rand::random::<u64>();
            if !read.cids_registered.contains_key(&possible) {
                ret.push(possible);
                if ret.len() == 10 {
                    return ret;
                }
            }
        }
    }

    /// Scans a list for a valid CID
    pub fn find_first_valid_cid<T: AsRef<[u64]>>(&self, possible_cids: T) -> Option<u64> {
        let read = self.read();
        let possible_cids = possible_cids.as_ref();
        possible_cids.iter().find(|res| !read.cids_registered.contains_key(*res))
            .cloned()
    }

    /// This should be called after registration occurs
    #[allow(unused_results)]
    pub fn register_cid<T: ToString>(&self, cid: u64, username: T) -> Result<(), AccountError<String>>{
        let mut write = self.write();
        if write.cids_registered.contains_key(&cid) {
            log::error!("Overwrote pre-existing account that lingered in the NID list. Report to developers");
            Err(AccountError::ClientExists(cid))
        } else {
            write.cids_registered.insert(cid, username.to_string());
            Ok(())
        }
    }

    /// Determines if a username exists
    pub fn username_exists<T: AsRef<str>>(&self, username: T) -> bool {
        let read = self.read();
        let username = username.as_ref();
        read.cids_registered.values().any(|stored_username| stored_username.as_str() == username)
    }

    /// Returns true if the removal was a success
    pub fn remove_registered_cid(&self, cid: u64) -> bool {
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
    pub fn create_client_account<T: ToString, V: ToString>(&self, reserved_cid: u64, nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, password_hash: Vec<u8>, base_hyper_ratchet: HyperRatchet) -> Result<ClientNetworkAccount, AccountError<String>> {
        if nac_other.is_none() {
            info!("WARNING: You are using debug mode. The supplied NAC is none, and will receive THIS nac in its place (unit tests only)");
        }

        // We must lock the config to ensure that the obtained CID gets added into the database before any competing threads may get called

        let username = username.to_string();

        username_has_invalid_symbols(&username)?;
        log::info!("Checking username {} for correspondence ...", &username);

        if self.username_exists(&username) {
            return Err(AccountError::Generic(format!("Username {} already exists!", &username)))
        }

        //log::info!("Received password: {:?}", password.unsecure());
        let dirs = self.inner.1.read().unwrap().dirs.clone().ok_or_else(|| AccountError::Generic("Directory store not loaded".to_string()))?;

        let cnac = ClientNetworkAccount::new(reserved_cid, false, nac_other.unwrap_or_else(|| self.clone()), &username, password, full_name, password_hash, base_hyper_ratchet, dirs)?;

        // So long as the CNAC creation succeeded, we can confidently add the CID into the config
        self.register_cid(reserved_cid, username)
            .and_then(|_| Ok(cnac))
    }

    /// Returns the IPv4 address which belongs to the NID enclosed herein
    #[deprecated]
    pub fn get_ipv4_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::V4(self.read().global_ipv4?))
    }

    /// Returns the IPv6 address which belongs to the NID enclosed herein
    pub fn get_ipv6_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::V6(self.read().global_ipv6?))
    }

    /// Returns the IP address which belongs to the NID enclosed herein.
    #[allow(deprecated)]
    pub fn get_addr(&self, prefer_ipv6: bool) -> Option<SocketAddr> {
        if prefer_ipv6 {
            if let Some(addr) = self.get_ipv6_addr() {
                Some(addr)
            } else {
                self.get_ipv4_addr()
            }
        } else {
            if let Some(addr) = self.get_ipv4_addr() {
                Some(addr)
            } else {
                self.get_ipv6_addr()
            }
        }
    }

    /// This sets the IP address. This automatically determines if the address is IPv6 or IPv4, and then it places
    /// it inside the correct field of self
    #[allow(unused_results)]
    pub fn update_ip(&self, new_addr: SocketAddr) {
        if new_addr.is_ipv4() {
            self.write().global_ipv4.replace(SocketAddrV4::from_str(new_addr.to_string().as_str()).unwrap());
        } else {
            self.write().global_ipv6.replace(SocketAddrV6::from_str(new_addr.to_string().as_str()).unwrap());
        }
    }

    /// Reads futures-style
    pub fn read(&self) -> ShardedLockReadGuard<NetworkAccountInner> {
        self.inner.1.read().unwrap()
    }

    /// Reads futures-style
    pub fn write(&self) -> ShardedLockWriteGuard<NetworkAccountInner> {
        self.inner.1.write().unwrap()
    }

    /// blocking version of async_save_to_local_fs
    pub fn save_to_local_fs(&self) -> Result<(), AccountError<String>> {
        let inner_nac = self.write();
        let path = get_pathbuf(inner_nac.dirs.as_ref().unwrap().inner.read().nac_node_default_store_location.as_str());

        let path_no_filename = path.parent().unwrap().clone();
        info!("Storing NAC to directory: {}", &path_no_filename.display());
        hyxe_fs::system_file_manager::make_dir_all_blocking(path_no_filename).map_err(|err| AccountError::Generic(err.to_string()))?;
        // First, save the NAC
        inner_nac.serialize_to_local_fs(path).map_err(|err| AccountError::IoError(err.to_string()))
    }
}

impl Debug for NetworkAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NID: {} | CIDs registered: {:?}", self.get_id(), &self.read().cids_registered)
    }
}

#[async_trait]
impl HyperNodeAccountInformation for NetworkAccount {
    fn get_id(&self) -> u64 {
        self.inner.0
    }

    async fn async_save_to_local_fs(self) -> Result<(), AccountError<String>> where NetworkAccountInner: SyncIO {
        self.save_to_local_fs()
    }
}