use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use hyxe_fs::hyxe_crypt::drill_update::DrillUpdateObject;
use hyxe_fs::hyxe_crypt::prelude::*;
use hyxe_fs::env::{HYXE_NAC_DIR_PERSONAL, HYXE_NAC_DIR_IMPERSONAL};
use hyxe_fs::hyxe_file::HyxeFile;
use hyxe_fs::prelude::SyncIO;
use async_trait::async_trait;

use crate::hypernode_account::{CNAC_SERIALIZED_EXTENSION, HyperNodeAccountInformation};
use crate::misc::{AccountError, check_credential_formatting};
use secstr::SecVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use multimap::MultiMap;
use hyxe_fs::async_io::AsyncIO;
use crate::prelude::NetworkAccount;
use hyxe_fs::system_file_manager::bytes_to_type;
use crate::network_account::NetworkAccountInner;
use hyxe_fs::hyxe_crypt::prelude::PostQuantumContainer;
use std::str::FromStr;
use log::info;

//use future_parking_lot::rwlock::{RwLock, FutureReadable, FutureWriteable, FutureRawRwLock};
use std::ops::RangeInclusive;
use serde::export::Formatter;
use hyxe_fs::misc::{get_present_formatted_timestamp, get_pathbuf};
//use future_parking_lot::parking_lot::RawRwLock;
//use future_parking_lot::parking_lot::lock_api::RwLockReadGuard;
use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};

/// The password file needs to have a hard-to-guess password enclosing in the case it is accidentally exposed over the network
pub const HYXEFILE_PASSWORD_LENGTH: usize = 222;
/// The maximum size a password can be. This upper limit was made inconsideration of the idea that passwords can bloat to the size of MAX_PACKET_SIZE, and force a split of data
/// which we want to prevent
pub const MAX_PASSWORD_SIZE: usize = 33;
/// The minimum size was selected quasi-randomly
pub const MIN_PASSWORD_SIZE: usize = 7;
/// The default index for denoting a HyperLAN connection (relative to THIS cnac)
pub const HYPERLAN_IDX: u64 = 0;

/// This is to replace a tuple for greater organization
#[derive(Serialize, Deserialize, Clone)]
pub struct MutualPeer {
    /// The interserver cid to which `cid` belongs to
    pub parent_icid: u64,
    /// the client to which belongs within `parent_icid`
    pub cid: u64,
    /// The username of this peer
    pub username: Option<String>
}

impl PartialEq for MutualPeer {
    fn eq(&self, other: &Self) -> bool {
        self.parent_icid == other.parent_icid && self.cid == other.cid
    }
}

///use futures::{TryFutureExt, TryStreamExt};
#[derive(Serialize, Deserialize)]
/// Inner device
pub struct ClientNetworkAccountInner {
    /// The client identification number
    pub cid: u64,
    /// The alias for locally mapping a client's username to a CID, which is then able to be mapped to the central server NID
    pub username: String,
    /// While this NAC should be session-oriented, it may be replaced if [PINNED_IP_MODE] is disabled, meaning, a new IP
    /// address can enact as the CNAC, otherwise the IP address must stay constant
    #[serde(skip)]
    pub adjacent_nac: Option<NetworkAccount>,
    /// If this CNAC is for a personal connection, this is true
    pub is_local_personal: bool,
    /// User's registered full name
    pub full_name: String,
    /// The creation date
    pub creation_date: String,
    /// For impersonal mode:
    /// input: iCID (the central server of the CID), output: MutualPeer(iCID, CID) where iCID == iCID.
    /// It maps the iCID to the CID. The iCID is zero if the peer client is within the HyperLAN (impersonal mode ONLY). Each CNAC
    /// is implied to be tethered to a HyperLAN Server, and as such, we use ZERO to imply the connection is within the
    /// HyperLAN
    ///
    /// For personal mode:
    /// input: iCID, output: (equal iCID or HyperWAN iCID, CID).
    /// if iCID == 0, then that implies a personal HyperLAN Client
    /// Suppose we input key k to retrieve tuple (i, j). If k == i, then the peer j is in k. If k != i, then j is in i (i.e., a HyperWAN client).
    pub mutuals: MultiMap<u64, MutualPeer>,
    /// The PathBuf stored the local save location
    #[serde(skip)]
    local_save_path: PathBuf,
    /// The HyxeFile for the NAC. Serde skips serializing the `client_nac`, and instead it gets encrypted into here during
    /// the serializing process. During the load_safe process, this must have some value. During execution, this should be none
    inner_encrypted_nac: Option<HyxeFile>,
    /// This remains NONE throughout the program execution. It does not take a value until right before disk serialization.
    /// Since the program shutdown time is not necessarily deterministic, this is an additional layer of security, since the
    /// saved location isn't known until right before program termination. Leaving the save location floating in memory for
    /// an increasing period of time increases the probability of a vulnerability being penetrated (albeit, the probability is
    /// very low)
    hyxefile_save_path: Option<PathBuf>,
    /// During the registration phase, these credentials are stored in the register container.
    /// This allows the CNAC to be serialized and sent over without sending the password
    #[serde(skip)]
    password_hyxefile: Option<HyxeFile>,
    post_quantum_code: Vec<u8>,
    /// Toolset which contains all the drills
    pub toolset: Toolset,
    #[serde(skip)]
    /// We keep the password in RAM encrypted
    password_in_ram: Option<SecVec<u8>>,
}

/// A thread-safe handle for sharing data across threads and applications
/// 
/// SAFETY: The `cid`, `adjacent_nid`, and `is_personal` is private. These values
/// should NEVER be edited within this source file
pub struct ClientNetworkAccount {
    /// The inner thread-safe device
    inner: Arc<ShardedLock<ClientNetworkAccountInner>>,
    cid: u64,
    adjacent_nid: u64,
    /// Relative to THIS node only
    is_personal: bool,
}

unsafe impl Send for ClientNetworkAccount {}
unsafe impl Sync for ClientNetworkAccount {}

impl ClientNetworkAccount {
    /// Note: This should ONLY be called from a server node.
    ///
    /// `client_nac`: This is required because it allows the server to keep track of the IP in the case [PINNED_IP_MODE] is engaged
    #[allow(unused_results)]
    pub(crate) fn new<T: ToString, V: ToString, K: AsRef<[u8]>>(valid_cid: Option<u64>, is_personal: bool, adjacent_nac: NetworkAccount, username: &T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>) -> Result<Self, AccountError<String>> {

        info!("Creating valid cid: {:?}", valid_cid);
        let password = password.unsecure().to_vec();
        let password = String::from_utf8(password).map_err(|err| AccountError::Generic(err.to_string()))?;
        let username = username.to_string();
        let full_name = full_name.to_string();
        check_credential_formatting(&username, &password, &full_name)?;
        let creation_date = get_present_formatted_timestamp();

        // if is_client is true, then the password isn't stored. It only exists on the server
        let (toolset, cid, is_client): (Toolset, u64, bool) = if let Some(toolset_bytes) = toolset_bytes {
            let toolset = Toolset::deserialize_from_bytes(toolset_bytes.as_ref()).map_err(|err| AccountError::Generic(err.to_string()))?;
            let cid = toolset.cid;
            (toolset, cid, true)
        } else {
            let cid = valid_cid.unwrap();
            let toolset = Toolset::new(cid).map_err(|err| AccountError::Generic(err.to_string()))?;
            (toolset, cid, false)
        };

        assert_eq!(is_personal, is_client);

        let local_save_path = Self::generate_local_save_path(cid, is_personal);

        let (password_hyxefile, password_in_ram) = if is_client {
            (None, None)
        } else {
            let password = SecVec::new(password.into_bytes());
            (Some(HyxeFile::new(full_name.to_string(), cid, "password_file", None)), Some(password))
        };

        let post_quantum_code = post_quantum_container.serialize_to_vector()
            .map_err(|err| AccountError::Generic(err.to_string()))?;

        let mutuals = MultiMap::new();

        let inner = ClientNetworkAccountInner { creation_date, post_quantum_code, cid, username, adjacent_nac: Some(adjacent_nac), is_local_personal: is_personal, full_name, mutuals, local_save_path, inner_encrypted_nac: None, hyxefile_save_path: None, password_hyxefile, toolset, password_in_ram };
        let this = Self::from(inner);

        this.blocking_save_to_local_fs()?;

        Ok(this)
    }

    /// saves to the HD non-blocking
    /// TODO: In the future, include database (redis/sql) syncing
    #[allow(unused_results)]
    pub fn spawn_save_task_on_threadpool(&self) {
        let this = self.clone();
        tokio::task::spawn(this.async_save_to_local_fs());
    }

    /// Returns true if the NAC is a personal type
    pub fn is_personal(&self) -> bool {
        self.is_personal
    }
    
    pub(crate) fn generate_local_save_path(valid_cid: u64, is_personal: bool) -> PathBuf {
        if is_personal {
            get_pathbuf(format!("{}{}.{}", HYXE_NAC_DIR_PERSONAL.lock().unwrap().as_ref().unwrap(), valid_cid, CNAC_SERIALIZED_EXTENSION))
        } else {
            get_pathbuf(format!("{}{}.{}", HYXE_NAC_DIR_IMPERSONAL.lock().unwrap().as_ref().unwrap(), valid_cid, CNAC_SERIALIZED_EXTENSION))
        }
    }

    /// Loads from an inner device. Performs all the necessary actions to keep the data as safe as possible
    pub(crate) async fn load_safe_from_fs(mut inner: ClientNetworkAccountInner, local_save_path: PathBuf) -> Result<Self, AccountError<String>> {
        if inner.is_local_personal {
            debug_assert!(inner.hyxefile_save_path.is_none()); // onload, this should have a value
            debug_assert!(inner.password_hyxefile.is_none());
        } else {
            debug_assert!(inner.hyxefile_save_path.is_some()); // onload, this should have a value
            debug_assert!(inner.password_hyxefile.is_none());
        }

        debug_assert!(inner.inner_encrypted_nac.is_some()); // onload, this should have a value for both server and client types

        inner.local_save_path = local_save_path;

        let drill = unsafe { inner.toolset.get_static_auxiliary_drill() };

        if !inner.is_local_personal {
            let hyxefile_path = inner.hyxefile_save_path.as_ref().unwrap();
            let hyxefile = HyxeFile::deserialize_from_local_fs(hyxefile_path).map_err(|err| AccountError::IoError(err.to_string()))?;

            // For safety purposes, the old password file gets purged upon load
            hyxe_fs::system_file_manager::delete_file(hyxefile_path).await.map_err(|err| AccountError::IoError(err.to_string()))?;

            // Now, remove the hyxefile_save_path for additional security measure
            inner.hyxefile_save_path = None;
            let password_unencrypted = hyxefile.read_contents(&drill).map_err(|err| AccountError::IoError(err.to_string()))?;
            inner.password_in_ram = Some(SecVec::new(password_unencrypted));
            inner.password_hyxefile = Some(hyxefile);
        }

        // We must now clear the encrypted contents by taking it
        let internal_nac_hyxefile = inner.inner_encrypted_nac.take().unwrap();
        let decrypted_nac_bytes = internal_nac_hyxefile.read_contents(&drill).map_err(|err| AccountError::IoError(err.to_string()))?;
        let inner_nac = bytes_to_type::<NetworkAccountInner, _>(&decrypted_nac_bytes).map_err(|err| AccountError::IoError(err.to_string()))?;
        let nac = NetworkAccount::new_from_cnac(inner_nac);
        inner.adjacent_nac = Some(nac);

        let this = Self::from(inner);

        // save to the fs to scramble the data to the HD anew
        this.blocking_save_to_local_fs()?;

        Ok(this)
    }

    /// Towards the end of the registration phase, the [ClientNetworkAccountInner] gets transmitted to Alice.
    pub fn new_from_network_personal<T: AsRef<[u8]>, R: ToString, K: ToString>(toolset_bytes: T, username: R, password: SecVec<u8>, full_name: K, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer) -> Result<Self, AccountError<String>> {
        const IS_PERSONAL: bool = true;

        // We supply none to the valid cid
        Self::new(None, IS_PERSONAL, adjacent_nac, &username, password, full_name, post_quantum_container, Some(toolset_bytes.as_ref()))
    }

    /// Serializes the inner toolset to a vector. Requires exclusive access
    pub fn serialize_toolset_to_vec(&self) -> Result<Vec<u8>, AccountError<String>> {
        let mut this = self.write();
        this.toolset.serialize_to_vec().map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// When the client received its inner CNAC, it will not have the NAC of the server. Therefore, the client-version of the CNAC must be updated
    pub fn update_inner_nac(&self, server_nac_for_this_cnac: NetworkAccount) {
        let mut write = self.write();
        write.adjacent_nac = Some(server_nac_for_this_cnac);
    }

    /// Returns the username of this client
    pub fn get_username(&self) -> String {
        self.read().username.clone()
    }

    /// Validates an IP address for a new-created client with [PINNED_IP_MODE] in consideration. If
    /// PIM is enabled, then the new ip address must match the previously held address. If the addresses
    /// do not match, then this does not update the internal entry and returns FALSE. If PIM is disabled,
    /// then this inserts the new IP address unconditionally and returns TRUE
    #[allow(deprecated)]
    pub async fn validate_ip(&mut self, new_addr: &IpAddr, pinned_ip_mode: bool) -> bool {
        let nac = self.get_nac();
        let mut nac = nac.write();

        if pinned_ip_mode {
            if new_addr.is_ipv4() {
                // In pinned-ip mode, a client cannot switch from IPv6 to IPv4
                if let Some(old_addr) = nac.global_ipv4 {
                    *new_addr == old_addr
                } else {
                    false
                }
            } else {
                if let Some(old_addr) = nac.global_ipv6 {
                    *new_addr == old_addr
                } else {
                    false
                }
            }
        } else {
            if new_addr.is_ipv4() {
                nac.global_ipv4 = Some(Ipv4Addr::from_str(new_addr.to_string().as_str()).unwrap());
            } else {
                nac.global_ipv6 = Some(Ipv6Addr::from_str(new_addr.to_string().as_str()).unwrap());
            }
            true
        }
    }

    /// Returns the [NetworkAccount] associated with the [ClientNetworkAccount]. Before being called,
    /// validate_ip should be ran in order to update the internal IP address for this session
    pub fn get_nac(&self) -> NetworkAccount {
        self.read().adjacent_nac.clone().unwrap()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub unsafe fn validate_credentials<T: AsRef<[u8]>>(&self, username: T, password: SecVec<u8>) -> Result<(), AccountError<String>> {
        let read = self.read();
        if read.password_in_ram.is_none() {
            //debug_assert!(self.is_personal);
            return Err(AccountError::Generic("Account does not have password loaded; account is personal".to_string()))
        }

        if username.as_ref() != read.username.as_bytes() {
            return Err(AccountError::InvalidUsername);
        }

        let pass = password.unsecure();
        let pass_real = read.password_in_ram.as_ref().unwrap().unsecure();

        if pass != pass_real {
            log::warn!("Invalid password ...");
            Err(AccountError::InvalidPassword)
        } else {
            Ok(())
        }
    }

    /// Checks the credentials for validity. Used for the login process.
    pub unsafe fn validate_credentials_blocking<T: AsRef<[u8]>>(&self, username: T, password: SecVec<u8>) -> Result<(), AccountError<String>> {
        let read = self.read();

        if read.password_in_ram.is_none() {
            debug_assert!(self.is_personal);
            return Err(AccountError::Generic("Account does not have password loaded; account is personal".to_string()))
        }

        if username.as_ref() != read.username.as_bytes() {
            return Err(AccountError::InvalidUsername);
        }

        let pass = password.unsecure();
        let pass_real = read.password_in_ram.as_ref().unwrap().unsecure();
        //log::info!("Will compare ...");
        //log::info!("Password recv: {:?}\nPass internal: {:?}\n", pass, pass_real);

        if pass != pass_real {
            log::info!("Invalid password ...");
            Err(AccountError::InvalidPassword)
        } else {
            Ok(())
        }
    }

    //pub unsafe fn update_tool

    /// Returns the last registered IP address for this client
    pub fn get_ip(&self) -> Option<IpAddr> {
        self.read().adjacent_nac.as_ref()?.get_addr(true)
    }
    

    /// If no version is supplied, the latest drill will be retrieved. The drill will not be dropped from
    /// the toolset if the strong reference still exists
    pub fn get_drill(&self, version: Option<u32>) -> Option<Drill> {
        let read = self.read();
        if let Some(version) = version {
            read.toolset.get_drill(version).cloned()
        } else {
            read.toolset.get_most_recent_drill().cloned()
        }
    }

    /// Whereas get_drill allows the caller to store the drill, thus controlling how long it stays in memory,
    /// this function only gets a borrow to a drill, thus saving a clone. If the drill is not found, then
    /// None will be passed into the supplied function.
    ///
    /// F should be a nonblocking function!
    pub fn borrow_drill<F, Y>(&self, version: Option<u32>, f: F) -> Y where F: FnOnce(Option<&Drill>) -> Y {
        let read = self.read();
        if let Some(version) = version {
            f(read.toolset.get_drill(version))
        } else {
            f(read.toolset.get_most_recent_drill())
        }
    }

    /// Captures by reference instead of just by value
    pub fn borrow_drill_fn<F, Y>(&self, version: Option<u32>, f: F) -> Y where F: Fn(Option<&Drill>) -> Y {
        let read = self.read();
        if let Some(version) = version {
            f(read.toolset.get_drill(version))
        } else {
            f(read.toolset.get_most_recent_drill())
        }
    }

    /// Returns a range of available drill versions
    pub fn get_drill_versions(&self) -> RangeInclusive<u32> {
        let read = self.read();
        read.toolset.get_available_drill_versions()
    }

    /// Advances the toolset version by 1, and returns the latest drill
    pub fn get_next_drill(&self) -> Result<Drill, CryptError<String>> {
        self.update_toolset(None)?;
        self.get_drill(None).ok_or(CryptError::DrillUpdateError("Drill not available".to_string()))
    }

    /// Updates the internal toolset a desired number of times. Inserting None will imply that
    /// the toolset will update once
    pub fn update_toolset(&self, count: Option<usize>) -> Result<(), CryptError<String>> {
        let mut write = self.write();
        write.toolset.update_n(count.unwrap_or(1))
    }

    /// Generate a new DrillUpdate object coupled with its corresponding new drill.
    ///
    /// The latest_drill must be the CURRENT latest drill. The returned Drill will be one version newer, but is not added
    /// to the toolset
    pub fn generate_new_dou(&self, latest_drill: &Drill) -> Result<(DrillUpdateObject, Drill), CryptError<String>> {
        let cid = self.cid;
        let next_drill_version = latest_drill.get_version().wrapping_add(1);
        DrillUpdateObject::generate(cid, next_drill_version, latest_drill).and_then(|update| {
            update.compute_next_recursion(latest_drill, true).ok_or_else(|| CryptError::DrillUpdateError("Unable to compute next recursion".to_string()))
        })
    }

    /// Updates from a new inbound DOU. This will return None if the improper latest drill is sent. The returned Drill
    /// will be 1 version higher than the latest_drill, advancing the toolset in the process.
    pub fn update_toolset_from_dou(&self, latest_drill: &Drill, dou: DrillUpdateObject) -> Option<Drill> {
        let mut this = self.write();
        this.toolset.update_from(latest_drill, dou)
    }

    /// Replaces the internal toolset. This should ONLY be called (if absolutely necessary) during the PRE_CONNECT stage
    /// if synchronization is required
    pub fn replace_toolset(&self, toolset: Toolset) {
        self.write().toolset = toolset;
    }

    /// Adds the new drill to the toolset. The last step of the DO_DRILL_UPDATE process
    /// Note: This will return false if the toolsets are out of sync. Ever since the inclusion
    /// of using the static auxiliary drill for RECOVERY (out of sync) mode, this closure should
    /// always return true
    pub fn register_new_drill_to_toolset(&self, new_drill: Drill) -> bool {
        let mut this = self.write();
        this.toolset.register_new_drill(new_drill)
    }

    /// Retrieves the post quantum container. Performance note: Run only once! Then, update it later
    pub fn get_post_quantum_container(&self) -> Result<PostQuantumContainer, AccountError<String>> {
        PostQuantumContainer::deserialize_from_bytes(self.read().post_quantum_code.as_slice())
            .map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Once the key exchange occurs, this should be updated to save for the next time this node connects to the other node
    ///
    /// Note: by encryption standards, the public key should be refreshed upon each session. This helps ensure forward secrecy
    pub async fn update_post_quantum_container(&self, container: &PostQuantumContainer) -> Result<(), AccountError<String>> {
        match container.serialize_to_vector() {
            Ok(post_quantum_code) => {
                self.write().post_quantum_code = post_quantum_code;
                Ok(())
            }

            Err(err) => {
                Err(AccountError::Generic(err.to_string()))
            }
        }
    }

    /// Gets the username and password
    pub unsafe fn get_account_info(&self) -> (String, Vec<u8>) {
        let write = self.write();
        let username = write.username.clone();
        let password = write.password_in_ram.as_ref().unwrap().unsecure().to_vec();
        (username, password)
    }

    /// This should ONLY be used for recovery mode
    pub unsafe fn get_static_auxiliary_drill(&self) -> Drill {
        let this = self.read();
        this.toolset.get_static_auxiliary_drill()
    }

    /// Removes the CNAC from the hard drive
    pub async fn purge_from_fs(&mut self) -> Result<(), AccountError<String>> {
        let read = self.read();
        let path = &read.local_save_path;

        hyxe_fs::system_file_manager::delete_file(path).await.map_err(|err| AccountError::IoError(err.to_string()))
    }


    /// Purges this from the hard drive
    pub fn purge_from_fs_blocking(&mut self) -> Result<(), AccountError<String>> {
        let read = self.read();
        let path = &read.local_save_path;

        std::fs::remove_file(path).map_err(|err| err.into())
    }

    /// Reads futures-style
    pub fn read(&self) -> ShardedLockReadGuard<ClientNetworkAccountInner> {
        self.inner.read().unwrap()
    }

    /// Reads futures-style
    pub fn write(&self) -> ShardedLockWriteGuard<ClientNetworkAccountInner> {
        self.inner.write().unwrap()
    }

    /*
            Start of the mutual peer-related functions
     */

    /// Returns a set of hyperlan peers
    pub fn get_hyperlan_peer_list(&self) -> Option<Vec<u64>> {
        let this = self.read();
        let hyperlan_peers = this.mutuals.get_vec(&HYPERLAN_IDX)?;
        Some(hyperlan_peers.into_iter().map(|peer| peer.cid).collect::<Vec<u64>>())
    }

    /// Returns a set of hyperlan peers
    pub fn get_hyperwan_peer_list(&self, icid: u64) -> Option<Vec<u64>> {
        let this = self.read();
        let hyperwan_peers = this.mutuals.get_vec(&icid)?;
        Some(hyperwan_peers.into_iter().map(|peer| peer.cid).collect::<Vec<u64>>())
    }

    /// Gets the desired HyperLAN peer by CID (clones)
    pub fn get_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        for peer in hyperlan_peers {
            if peer.cid == cid {
                return Some(peer.clone())
            }
        }

        None
    }

    /// Gets the desired HyperLAN peer by username (clones)
    pub fn get_hyperlan_peer_by_username<T: AsRef<str>>(&self, username: T) -> Option<MutualPeer> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        let username = username.as_ref();

        for peer in hyperlan_peers {
            if let Some(username_peer) = peer.username.as_ref() {
                if username_peer == username {
                    return Some(peer.clone())
                }
            }
        }

        None
    }

    /// This function handles the registration for BOTH CNACs. Then, it synchronizes both to
    /// the local filesystem on the Threadpool
    #[allow(unused_results)]
    pub fn register_hyperlan_p2p_as_server(&self, other_orig: &ClientNetworkAccount) {
        let this_cid = self.cid;
        let other_cid = other_orig.cid;

        let mut this = self.write();
        let mut other = other_orig.write();

        let this_username = this.username.clone();
        let other_username = other.username.clone();

        this.mutuals.insert(HYPERLAN_IDX, MutualPeer {
            parent_icid: HYPERLAN_IDX,
            cid: other_cid,
            username: Some(other_username)
        });

        other.mutuals.insert(HYPERLAN_IDX, MutualPeer {
            parent_icid: HYPERLAN_IDX,
            cid: this_cid,
            username: Some(this_username)
        });

        std::mem::drop(this);
        std::mem::drop(other);

        let other = other_orig.clone();
        let this= self.clone();
        // spawn save task on threadpool
        tokio::task::spawn(async move {
            if let Err(err) = this.async_save_to_local_fs().await {
                log::error!("Unable to save CNAC {} to the local filesystem: {}", this_cid, err.to_string());
            }

            if let Err(err) = other.async_save_to_local_fs().await {
                log::error!("Unable to save CNAC {} to the local filesystem: {}", other_cid, err.to_string());
            }
        });
    }

    /// Returns the number of peers found
    pub fn view_hyperlan_peers(&self, mut fx: impl FnMut(&Vec<MutualPeer>)) -> usize {
        let read = self.read();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            fx(hyperlan_peers);
            hyperlan_peers.len()
        } else {
            0
        }
    }

    /// Determines if the specified hyperlan peer exists
    pub fn hyperlan_peer_exists(&self, cid: u64) -> bool {
        let read = self.read();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            //log::info!("Checking through {} peers", hyperlan_peers.len());
            for peer in hyperlan_peers {
                //log::info!("Checking if {} == {} ({})", peer.cid, cid, &peer.username.as_ref().unwrap());
                if peer.cid == cid {
                    return true
                }
            }
        } else {
            log::info!("mutuals vec is missing the hyperlan idx");
        }

        false
    }

    /// Returns true if and only if all the peers in `peers` exist
    pub fn hyperlan_peers_exist(&self, peers: &Vec<u64>) -> bool {
        let read = self.read();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            'search: for peer in peers {
                for hyperlan_peer in hyperlan_peers {
                    if hyperlan_peer.cid == *peer {
                        continue 'search;
                    }
                }
                // if we get here, it means we couldnt find a peer
                return false;
            }
            true
        } else {
            false
        }
    }

    /// Removes any inputs from the internal map that are not present in `peers`. The set `peers` should be
    /// obtained from the HyperLAN Server
    pub fn synchronize_hyperlan_peer_list(&self, peers: &Vec<u64>) {
        let mut this = self.write();
        if let Some(hyperlan_peers) = this.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            hyperlan_peers.retain(|hyperlan_peer| {
                for peer in peers {
                    if *peer == hyperlan_peer.cid {
                        // found a match; retain the entry
                        return true;
                    }
                }
                // no match found; do no retain the entry
                log::warn!("[CNAC Synchronize]: peer {} does not exist in the HyperLAN Server; removing", hyperlan_peer.cid);
                false
            });
        }
    }

    /// Determines if the username is a known hyperlan client to self
    pub fn hyperlan_peer_exists_by_username<T: AsRef<str>>(&self, username: T) -> bool {
        let read = self.read();
        let username = username.as_ref();

        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            //log::info!("Checking through {} peers", hyperlan_peers.len());
            for peer in hyperlan_peers {
                //log::info!("Checking if {} == {} ({})", peer.username.as_ref().unwrap(), username, peer.cid);
                if let Some(uname) = peer.username.as_ref() {
                    if uname == username {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// ONLY run this after you're sure the peer doesn't already exist
    pub fn insert_hyperlan_peer<T: ToString>(&self, cid: u64, username: T) {
        let mut write = self.write();
        let username = Some(username.to_string());

        write.mutuals.insert(HYPERLAN_IDX, MutualPeer { username, parent_icid: HYPERLAN_IDX, cid });
    }

    /// Returns Some if success, None otherwise. Also syncs to the disk in via the threadpool
    pub fn remove_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        let mut write = self.write();
        if let Some(hyperlan_peers) = write.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            if hyperlan_peers.len() != 0 {
                let mut idx_to_remove = -1;
                'search: for (idx, peer) in hyperlan_peers.iter().enumerate() {
                    if peer.cid == cid {
                        idx_to_remove = idx as isize;
                        break 'search;
                    }
                }

                if idx_to_remove != -1 {
                    let removed_peer = hyperlan_peers.remove(idx_to_remove as usize);
                    self.spawn_save_task_on_threadpool();
                    return Some(removed_peer);
                }
            } else {
                log::info!("Attempted to remove a HyperLAN Peer, but it doesn't exist!");
            }
        }

        None
    }

    /// Returns true if success, false otherwise
    pub fn remove_hyperlan_peer_by_username<T: AsRef<str>>(&self, username: T) -> Option<MutualPeer> {
        let username = username.as_ref();
        let mut write = self.write();
        if let Some(hyperlan_peers) = write.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            let mut idx: isize = -1;
            if hyperlan_peers.len() != 0 {
                'search: for (vec_idx, peer) in hyperlan_peers.iter().enumerate() {
                    if let Some(user) = peer.username.as_ref() {
                        if user == username {
                            idx = vec_idx as isize;
                            break 'search;
                        }
                    }
                }
            } else {
                log::info!("Attempted to remove a HyperLAN Peer, but it doesn't exist!");
            }

            if idx != -1 {
                return Some(hyperlan_peers.remove(idx as usize));
            }
        }

        None
    }

    /*

            End of the mutual peer-related functions

     */


    /// Generates the bytes of the underlying [ClientNetworkAccountInner]
    pub async fn generate_bytes_async(&self) -> Result<Vec<u8>, AccountError<String>> where ClientNetworkAccountInner: AsyncIO {
        self.write().async_serialize_to_vector().await.map_err(|err| AccountError::IoError(err.to_string()))
    }

    /// Useful for transmission
    pub fn generate_bytes_sync(&self) -> Result<Vec<u8>, AccountError<String>> where ClientNetworkAccountInner: SyncIO {
        self.write().serialize_to_vector().map_err(|err| err.into())
    }

    /// Visit the inner device
    pub fn visit<J>(&self, fx: impl FnOnce(ShardedLockReadGuard<'_, ClientNetworkAccountInner>) -> J) -> J {
        fx(self.read())
    }

    /// Visit the inner device mutably
    pub fn visit_mut<J>(&self, fx: impl FnOnce(ShardedLockWriteGuard<'_, ClientNetworkAccountInner>) -> J) -> J {
        fx(self.write())
    }

    /// Blocking version of `async_save_to_local_fs`
    pub fn blocking_save_to_local_fs(&self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner: SyncIO, NetworkAccountInner: SyncIO {
        let mut ptr = self.write();
        //debug_assert!(ptr.hyxefile_save_path.is_none());
        //debug_assert!(ptr.inner_encrypted_nac.is_none());

        let static_aux_drill = unsafe { ptr.toolset.get_static_auxiliary_drill() };
        //let path = ptr.local_save_path.clone();

        // impersonals store the password, NOT personals!
        if !ptr.is_local_personal {
            // We save the password locally if self is server
            let password_bytes = ptr.password_in_ram.as_ref().unwrap().unsecure().to_vec();
            let _ = ptr.password_hyxefile.as_mut().unwrap().replace_contents(&static_aux_drill, password_bytes.as_slice(), false, SecurityLevel::DIVINE).map_err(|err| AccountError::IoError(err.to_string()))?;
            let path = ptr.password_hyxefile.as_mut().unwrap().save_locally_blocking().map_err(|err| AccountError::IoError(err.to_string()))?;
            ptr.hyxefile_save_path = Some(path.clone());
        } else {
            debug_assert!(ptr.password_in_ram.is_none());
        }

        // We don't save the password locally if self is client

        // next, we must encrypt the inner [NetworkAccount] into the HyxeFile, whether self is client or not
        let mut new_hyxefile = HyxeFile::new(&ptr.full_name, ptr.cid, "encrypted_nac", None);
        let nac_unencrypted_bytes = ptr.adjacent_nac.as_ref().unwrap().read().serialize_to_vector().map_err(|err| AccountError::IoError(err.to_string()))?;
        // We save the bytes inside the HyxeFile.
        new_hyxefile.drill_contents(&static_aux_drill, nac_unencrypted_bytes.as_slice(), SecurityLevel::DIVINE).map_err(|err| AccountError::IoError(err.to_string()))?;
        // Place the HyxeFile inside
        assert!(ptr.inner_encrypted_nac.replace(new_hyxefile).is_none());

        // finally, save the CNAC to the local hard drive, but using the save path for the CNAC instead of the password HyxeFile
        let save_path = ptr.local_save_path.as_path().clone();
        log::info!("Saving CNAC {} to {}", ptr.cid, save_path.display());
        ptr.serialize_to_local_fs(save_path).map_err(|err| AccountError::IoError(err.to_string()))?;
        ptr.inner_encrypted_nac = None; // to free memory from the heap
        Ok(())
    }

    /// This will panic if the adjacent NAC is not loaded
    pub fn get_adjacent_nid(&self) -> u64 {
        self.adjacent_nid
    }
}

impl Clone for ClientNetworkAccount {
    fn clone(&self) -> Self {
        let adjacent_nid = self.adjacent_nid;
        Self { adjacent_nid, cid: self.cid, is_personal: self.is_personal, inner: self.inner.clone() }
    }
}

#[async_trait]
impl HyperNodeAccountInformation for ClientNetworkAccount {
    fn get_id(&self) -> u64 {
        self.cid
    }

    async fn get_filesystem_location(&self) -> PathBuf {
        self.read().local_save_path.clone()
    }

    // TODO: Make the syncing process cleaner. This is "blocking", but not really because a small amount of data is written to the disk
    async fn async_save_to_local_fs(self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner: SyncIO, NetworkAccountInner: SyncIO {
        self.blocking_save_to_local_fs()
    }
}

impl std::fmt::Debug for ClientNetworkAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CNAC | CID: {}, Adjacent NID: {}", self.cid, self.adjacent_nid)
    }
}

impl std::fmt::Display for ClientNetworkAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let inner = self.read();
        writeln!(f, "{}\t\t{}\t\t{}\t\t{}", self.cid, &inner.username, &inner.full_name, self.is_personal)
    }
}

impl From<ClientNetworkAccountInner> for ClientNetworkAccount {
    fn from(inner: ClientNetworkAccountInner) -> Self {
        let adjacent_nid = inner.adjacent_nac.as_ref().unwrap().get_id();
        Self { adjacent_nid, cid: inner.cid, is_personal: inner.is_local_personal, inner: Arc::new(ShardedLock::new(inner)) }
    }
}