use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::sync::Arc;
use async_trait::async_trait;
//use future_parking_lot::rwlock::{FutureReadable, FutureWriteable, RwLock};
use log::info;
use rand::{random, RngCore};
use secstr::SecVec;
use serde::{Deserialize, Serialize};

use hyxe_fs::hyxe_crypt::prelude::PostQuantumContainer;
use hyxe_fs::misc::get_pathbuf;
use hyxe_fs::prelude::SyncIO;

use crate::client_account::ClientNetworkAccount;
use crate::hypernode_account::HyperNodeAccountInformation;
use crate::misc::AccountError;
use crate::server_config_handler::username_has_invalid_symbols;
use rand::prelude::ThreadRng;
use crossbeam_utils::sync::{ShardedLock, ShardedLockWriteGuard, ShardedLockReadGuard};
use std::ops::Deref;

lazy_static! {
    /// Each node has a unique NetworkAccount; this information is stored at the address below if the instance is a server node
    pub static ref NAC_NODE_DEFAULT_STORE_LOCATION: Mutex<Option<String>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize, Default)]
/// Inner device
pub struct NetworkAccountInner {
    /// The global IPv4 address for this node
    pub(crate) global_ipv4: Option<SocketAddrV4>,
    /// The global IPv6 address for this node
    pub(crate) global_ipv6: Option<SocketAddrV6>,
    /// Contains a list of registered HyperLAN CIDS
    pub cids_registered: HashMap<u64, String>,
    /// Used to determining an unused cid
    pub max_cid_id: AtomicU64,
    /// The NID
    nid: u64,
}

/// Thread-safe handle
#[derive(Default)]
pub struct NetworkAccount {
    /// the inner device
    pub inner: Arc<ShardedLock<NetworkAccountInner>>,
    nid: u64,
}

unsafe impl Send for NetworkAccount {}
unsafe impl Sync for NetworkAccount {}

impl NetworkAccount {
    /// This should be called at runtime if the current node does not have a detected NAC. This is NOT for
    /// creating a NAC for new server connections; instead, use `new_from_recent_connection`.
    pub fn new_local() -> Result<NetworkAccount, AccountError<String>> {
        let nid = random::<u64>() ^ random::<u64>();
        let (global_ipv4, global_ipv6) = (None, None);
        let local_save_path = get_pathbuf(NAC_NODE_DEFAULT_STORE_LOCATION.lock().unwrap().as_ref().unwrap());
        info!("Attempting to create a NAC at {}", local_save_path.to_str().unwrap());
        Ok(Self { nid, inner: Arc::new(ShardedLock::new(NetworkAccountInner { max_cid_id: AtomicU64::new(ThreadRng::default().next_u32() as u64), cids_registered: HashMap::new(), nid, global_ipv4, global_ipv6})) })
    }

    /// When a new connection is created, this may be called
    pub fn new_from_recent_connection(nid: u64, addr: SocketAddr) -> NetworkAccount {
        let (global_ipv4, global_ipv6) = {
            if addr.is_ipv4() {
                (Some(SocketAddrV4::from_str(addr.to_string().as_str()).unwrap()), None)
            } else {
                (None, Some(SocketAddrV6::from_str(addr.to_string().as_str()).unwrap()))
            }
        };
        Self {
            nid,
            inner: Arc::new(ShardedLock::new(NetworkAccountInner {
                cids_registered: HashMap::new(),
                max_cid_id: AtomicU64::new(0),
                nid,
                global_ipv4,
                global_ipv6
            })),
        }
    }

    /// Once the [NetworkAccountInner] is loaded, this should be called. It internally updates the save path
    pub fn new_from_local_fs(inner: NetworkAccountInner) -> Self {
        Self { nid: inner.nid, inner: Arc::new(ShardedLock::new(inner)) }
    }

    /// When a CNAC loads its internally encrypted [NetworkAccount]
    pub fn new_from_cnac(inner: NetworkAccountInner) -> Self {
        Self { nid: inner.nid, inner: Arc::new(ShardedLock::new(inner)) }
    }

    /// Sets the highest cid internally. Must be consistent with the data loaded with the set of CNACS.
    ///
    /// Will only set the value if the highest cid provided is greater than the stored internal value
    pub fn set_highest_cid(&self, highest_cid: u64) {
        let write = self.write();
        if highest_cid > write.max_cid_id.load(Ordering::Relaxed) {
            // only update the value if the highest obtained CID is greater than what's stored in max_cid_id
            // If this is the case, it tells us that the NAC wasn't synced to the storage device (i.e, no safe shutdown).
            // No biggie; just ensure that all future calls to reserve_cid guarantee that the number isn't taken
            write.max_cid_id.store(highest_cid, Ordering::Relaxed)
        }
    }

    /// This should be called during the registration phase. The incrementing mechanism ensures the CID is unique
    ///
    /// this is a get and increment mechanism that is atomic-safe
    pub fn reserve_cid(&self) -> u64 {
        let read = self.read();
        // We add 1 to ensure there is no zero CID (reserved)
        1 + read.max_cid_id.fetch_add(1, Ordering::SeqCst)
    }

    /// This should be called after registration occurs
    pub fn register_cid<T: ToString>(&self, cid: u64, username: T) {
        let mut write = self.write();
        assert!(write.cids_registered.insert(cid, username.to_string()).is_none())
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
    pub fn create_client_account<T: ToString, V: ToString, K: AsRef<[u8]>>(&self, reserved_cid: u64, nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, password_hash: Vec<u8>, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>) -> Result<ClientNetworkAccount, AccountError<String>> {
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

        let cnac = ClientNetworkAccount::new(Some(reserved_cid), false, nac_other.unwrap_or_else(|| self.clone()), &username, password, full_name, password_hash, post_quantum_container, toolset_bytes)?;
        // So long as the CNAC creation succeeded, we can confidently add the CID into the config
        self.register_cid(reserved_cid, username);
        Ok(cnac)
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

    /// Returns the IP address which belongs to the NID enclosed herein.
    #[allow(deprecated)]
    pub fn get_addr_blocking(&self, prefer_ipv6: bool) -> Option<SocketAddr> {
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
        self.inner.read().unwrap()
    }

    /// Reads futures-style
    pub fn write(&self) -> ShardedLockWriteGuard<NetworkAccountInner> {
        self.inner.write().unwrap()
    }

    /// blocking version of async_save_to_local_fs
    pub fn save_to_local_fs(&self) -> Result<(), AccountError<String>> {
        let inner_nac = self.write();
        let path = get_pathbuf(NAC_NODE_DEFAULT_STORE_LOCATION.lock().unwrap().as_ref().unwrap());

        let path_no_filename = path.parent().unwrap().clone();
        info!("Storing NAC to directory: {}", &path_no_filename.display());
        hyxe_fs::system_file_manager::make_dir_all_blocking(path_no_filename).map_err(|err| AccountError::Generic(err.to_string()))?;
        // First, save the NAC
        inner_nac.serialize_to_local_fs(path).map_err(|err| AccountError::IoError(err.to_string()))
    }
}

/// This is called by the [ServerBridgeHandler] when needing to create a new Network account
impl From<(u64, SocketAddr)> for NetworkAccount {
    fn from(obj: (u64, SocketAddr)) -> Self {
        Self::new_from_recent_connection(obj.0, obj.1)
    }
}

#[async_trait]
impl HyperNodeAccountInformation for NetworkAccount {
    fn get_id(&self) -> u64 {
        self.nid
    }

    async fn get_filesystem_location(&self) -> PathBuf {
        get_pathbuf(NAC_NODE_DEFAULT_STORE_LOCATION.lock().unwrap().as_ref().unwrap())
    }

    async fn async_save_to_local_fs(self) -> Result<(), AccountError<String>> where NetworkAccountInner: SyncIO {
        let path = get_pathbuf(NAC_NODE_DEFAULT_STORE_LOCATION.lock().unwrap().as_ref().unwrap());
        let path_no_filename = path.parent().unwrap().clone();
        info!("Storing NAC to directory: {}", &path_no_filename.display());
        hyxe_fs::system_file_manager::make_dir_all(path_no_filename).await.map_err(|err| AccountError::Generic(err.to_string()))?;
        let inner_nac = self.write();
        // Save the NAC
        inner_nac.deref().serialize_to_local_fs(path).map_err(|err| AccountError::IoError(err.to_string()))
    }
}

impl Clone for NetworkAccount {
    fn clone(&self) -> Self {
        Self { nid: self.nid, inner: self.inner.clone() }
    }
}