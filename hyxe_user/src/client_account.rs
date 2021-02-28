use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use hyxe_fs::hyxe_crypt::prelude::*;
use hyxe_fs::env::DirectoryStore;
use hyxe_fs::hyxe_file::HyxeFile;
use hyxe_fs::prelude::SyncIO;
use async_trait::async_trait;

use crate::hypernode_account::{CNAC_SERIALIZED_EXTENSION, HyperNodeAccountInformation};
use crate::misc::{AccountError, check_credential_formatting};
use secstr::SecVec;
use std::net::SocketAddr;
use multimap::MultiMap;
use hyxe_fs::async_io::AsyncIO;
use crate::prelude::NetworkAccount;
use hyxe_fs::system_file_manager::bytes_to_type;
use crate::network_account::NetworkAccountInner;
use log::info;

use std::fmt::Formatter;
use hyxe_fs::misc::{get_present_formatted_timestamp, get_pathbuf};
use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};
use hyxe_fs::hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet};
use hyxe_fs::hyxe_crypt::toolset::UpdateStatus;
use hyxe_fs::hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use std::ops::RangeInclusive;

use std::collections::HashMap;
use hyxe_crypt::fcm::fcm_ratchet::{FcmRatchet, FcmAliceToBobTransfer};
use hyxe_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use hyxe_crypt::hyper_ratchet::constructor::{ConstructorType, AliceToBobTransferType};
use fcm::{Client, FcmResponse};
use crate::fcm::fcm_instance::FCMInstance;
use crate::fcm::data_structures::{FcmTicket, RawFcmPacket};
use crate::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, block_on_async};
use crate::fcm::fcm_packet_processor::peer_post_register::InvitationType;
use crate::fcm::kem::FcmPostRegister;


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
#[derive(Serialize, Deserialize, Clone, Debug)]
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
pub struct ClientNetworkAccountInner<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
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
    /// When the client needs to hash its proposed password for the future, this is required
    /// When the server needs to serve the role of recovering an account (e.g., if the client loses its local CNAC info),
    /// this constant password hash will store
    pub password_hash: Vec<u8>,
    /// Toolset which contains all the drills
    #[serde(bound = "")]
    pub crypt_container: PeerSessionCrypto<R>,
    /// A session-invariant container that stores the crypto container for a specific peer cid
    #[serde(bound = "")]
    pub fcm_crypt_container: HashMap<u64, PeerSessionCrypto<Fcm>>,
    /// For keeping track of KEX'es
    #[serde(bound = "")]
    pub kem_state_containers: HashMap<u64, ConstructorType<R, Fcm>>,
    /// For storing FCM invites
    pub fcm_invitations: HashMap<u64, InvitationType>,
    #[serde(skip)]
    /// We keep the password in RAM encrypted
    password_in_ram: Option<SecVec<u8>>,
    #[serde(skip)]
    dirs: Option<DirectoryStore>
}

/// A thread-safe handle for sharing data across threads and applications
/// 
/// SAFETY: The `cid`, `adjacent_nid`, and `is_personal` is private. These values
/// should NEVER be edited within this source file
pub struct ClientNetworkAccount<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    /// The inner thread-safe device
    inner: Arc<MetaInner<R, Fcm>>
}

struct MetaInner<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    cid: u64,
    adjacent_nid: u64,
    is_personal: bool,
    inner: ShardedLock<ClientNetworkAccountInner<R, Fcm>>
}

impl<R: Ratchet, Fcm: Ratchet> ClientNetworkAccount<R, Fcm> {
    /// Note: This should ONLY be called from a server node.
    ///
    /// `client_nac`: This is required because it allows the server to keep track of the IP in the case [PINNED_IP_MODE] is engaged
    #[allow(unused_results)]
    pub fn new<T: ToString, V: ToString>(valid_cid: u64, is_personal: bool, adjacent_nac: NetworkAccount, username: T, password: SecVec<u8>, full_name: V, password_hash: Vec<u8>, base_hyper_ratchet: R, dirs: DirectoryStore) -> Result<Self, AccountError<String>> {
        info!("Creating CNAC w/valid cid: {:?}", valid_cid);
        let username = username.to_string();
        let full_name = full_name.to_string();

        check_credential_formatting::<_, &str, _>(&username, None, &full_name)?;

        let creation_date = get_present_formatted_timestamp();
        // the static & f(0) hyper ratchets will be the provided hyper ratchet
        let crypt_container = PeerSessionCrypto::<R>::new(Toolset::<R>::new(valid_cid, base_hyper_ratchet), is_personal);
        //debug_assert_eq!(is_personal, is_client);


        let local_save_path = Self::generate_local_save_path(valid_cid, is_personal, &dirs);

        let (password_hyxefile, password_in_ram) = if is_personal {
            (None, None)
        } else {
            (Some(HyxeFile::new(full_name.to_string(), valid_cid, "password_file", None)), Some(password))
        };


        let mutuals = MultiMap::new();
        let dirs = Some(dirs);

        let fcm_crypt_container = HashMap::with_capacity(0);
        let kem_state_containers = HashMap::with_capacity(0);
        let fcm_invitations = HashMap::with_capacity(0);

        let inner = ClientNetworkAccountInner::<R, Fcm> { fcm_invitations, kem_state_containers, fcm_crypt_container, dirs, password_hash, creation_date, cid: valid_cid, username, adjacent_nac: Some(adjacent_nac), is_local_personal: is_personal, full_name, mutuals, local_save_path, inner_encrypted_nac: None, hyxefile_save_path: None, password_hyxefile, crypt_container, password_in_ram };
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

    /// Resets the toolset, if necessary. If the CNAC was freshly serialized, the hyper ratchet
    /// is not updated. In either case, returns the static aux hyper ratchet
    #[allow(unused_results)]
    pub fn refresh_static_hyper_ratchet(&self) -> R {
        let mut write = self.write();
        write.crypt_container.toolset.verify_init_state();
        write.crypt_container.toolset.get_static_auxiliary_ratchet().clone()
    }

    /// Returns true if the NAC is a personal type
    pub fn is_personal(&self) -> bool {
        self.inner.is_personal
    }


    pub(crate) fn generate_local_save_path(valid_cid: u64, is_personal: bool, dirs: &DirectoryStore) -> PathBuf {
        if is_personal {
            get_pathbuf(format!("{}{}.{}", dirs.inner.read().hyxe_nac_dir_personal.as_str(), valid_cid, CNAC_SERIALIZED_EXTENSION))
        } else {
            get_pathbuf(format!("{}{}.{}", dirs.inner.read().hyxe_nac_dir_impersonal.as_str(), valid_cid, CNAC_SERIALIZED_EXTENSION))
        }
    }

    /// Loads from an inner device. Performs all the necessary actions to keep the data as safe as possible
    pub(crate) fn load_safe_from_fs(mut inner: ClientNetworkAccountInner<R, Fcm>, local_save_path: PathBuf, dirs: &DirectoryStore) -> Result<Self, AccountError<String>> {
        if inner.is_local_personal {
            debug_assert!(inner.hyxefile_save_path.is_none()); // onload, this should have a value
            debug_assert!(inner.password_hyxefile.is_none());
        } else {
            debug_assert!(inner.hyxefile_save_path.is_some()); // onload, this should have a value
            debug_assert!(inner.password_hyxefile.is_none());
        }

        debug_assert!(inner.inner_encrypted_nac.is_some()); // onload, this should have a value for both server and client types

        inner.dirs = Some(dirs.clone());
        inner.local_save_path = local_save_path;

        let static_hyper_ratchet = inner.crypt_container.toolset.get_static_auxiliary_ratchet();

        if !inner.is_local_personal {
            let hyxefile_path = inner.hyxefile_save_path.as_ref().unwrap();
            let hyxefile = HyxeFile::deserialize_from_local_fs(hyxefile_path).map_err(|err| AccountError::IoError(err.to_string()))?;

            // For safety purposes, the old password file gets purged upon load
            hyxe_fs::system_file_manager::delete_file_blocking(hyxefile_path).map_err(|err| AccountError::IoError(err.to_string()))?;

            // Now, remove the hyxefile_save_path for additional security measure
            inner.hyxefile_save_path = None;
            let password_unencrypted = hyxefile.read_contents(static_hyper_ratchet).map_err(|err| AccountError::IoError(err.to_string()))?;
            inner.password_in_ram = Some(SecVec::new(password_unencrypted));
            inner.password_hyxefile = Some(hyxefile);
        }

        // We must now clear the encrypted contents by taking it
        let internal_nac_hyxefile = inner.inner_encrypted_nac.take().unwrap();
        let decrypted_nac_bytes = internal_nac_hyxefile.read_contents(static_hyper_ratchet).map_err(|err| AccountError::IoError(err.to_string()))?;
        let inner_nac = bytes_to_type::<NetworkAccountInner>(&decrypted_nac_bytes).map_err(|err| AccountError::IoError(err.to_string()))?;
        let nac = NetworkAccount::new_from_cnac(inner_nac);
        inner.adjacent_nac = Some(nac);
        inner.kem_state_containers.retain(|_, con| con.is_fcm());

        let this = Self::from(inner);

        // save to the fs to scramble the data to the HD anew
        this.blocking_save_to_local_fs()?;

        Ok(this)
    }

    /// Towards the end of the registration phase, the [ClientNetworkAccountInner] gets transmitted to Alice.
    pub fn new_from_network_personal<X: ToString, K: ToString>(valid_cid: u64, hyper_ratchet: R, username: X, password: SecVec<u8>, full_name: K, password_hash: Vec<u8>, adjacent_nac: NetworkAccount, dirs: DirectoryStore) -> Result<Self, AccountError<String>> {
        const IS_PERSONAL: bool = true;

        // We supply none to the valid cid
        Self::new(valid_cid, IS_PERSONAL, adjacent_nac, username, password, full_name, password_hash, hyper_ratchet, dirs)
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

    /// Returns the [NetworkAccount] associated with the [ClientNetworkAccount]. Before being called,
    /// validate_ip should be ran in order to update the internal IP address for this session
    pub fn get_nac(&self) -> NetworkAccount {
        self.read().adjacent_nac.clone().unwrap()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub fn validate_credentials<T: AsRef<[u8]>>(&self, username: T, password_hashed: SecVec<u8>) -> Result<(), AccountError<String>> {
        let read = self.read();
        if read.password_in_ram.is_none() {
            //debug_assert!(self.is_personal);
            return Err(AccountError::Generic("Account does not have password loaded; account is personal".to_string()))
        }

        if username.as_ref() != read.username.as_bytes() {
            return Err(AccountError::InvalidUsername);
        }

        // the password_in_ram is the raw original hashed password computed by the client sent to here (server-side)
        let pass_hashed_internal = read.password_in_ram.as_ref().unwrap().unsecure();
        //log::info!("\n\rINTERNAL({}): {:?}", pass_hashed_internal.len(), pass_hashed_internal);
        //log::info!("\n\rExternal({}): {:?}", password_hashed.unsecure().len(), password_hashed.unsecure());
        // the client computes the hash of its proposed password and sends it
        if pass_hashed_internal != password_hashed.unsecure() {
            log::warn!("Invalid password ...");
            Err(AccountError::InvalidPassword)
        } else {
            Ok(())
        }
    }

    //pub unsafe fn update_tool

    /// Returns the last registered IP address for this client
    pub fn get_ip(&self) -> Option<SocketAddr> {
        self.read().adjacent_nac.as_ref()?.get_addr(true)
    }

    /// If no version is supplied, the latest drill will be retrieved. The drill will not be dropped from
    /// the toolset if the strong reference still exists
    pub fn get_hyper_ratchet(&self, version: Option<u32>) -> Option<R> {
        let read = self.read();
        read.crypt_container.get_hyper_ratchet(version).cloned()
    }

    /// Whereas get_drill allows the caller to store the drill, thus controlling how long it stays in memory,
    /// this function only gets a borrow to a drill, thus saving a clone. If the drill is not found, then
    /// None will be passed into the supplied function.
    ///
    /// F should be a nonblocking function!
    pub fn borrow_hyper_ratchet<F, Y>(&self, version: Option<u32>, f: F) -> Y where F: FnOnce(Option<&R>) -> Y {
        let read = self.read();
        f(read.crypt_container.get_hyper_ratchet(version))
    }

    /// Captures by reference instead of just by value
    pub fn borrow_hyper_ratchet_fn<F, Y>(&self, version: Option<u32>, f: F) -> Y where F: Fn(Option<&R>) -> Y {
        let read = self.read();
        f(read.crypt_container.get_hyper_ratchet(version))
    }

    /// Returns the versions available in the hyper ratchet
    pub fn get_hyper_ratchet_versions(&self) -> RangeInclusive<u32> {
        let read = self.read();
        read.crypt_container.toolset.get_oldest_hyper_ratchet_version()..=read.crypt_container.toolset.get_most_recent_hyper_ratchet_version()
    }

    /// Updates the internal toolset
    pub fn register_new_hyper_ratchet(&self, new_hyper_ratchet: R) -> Result<UpdateStatus, CryptError<String>> {
        let mut write = self.write();
        write.crypt_container.toolset.update_from(new_hyper_ratchet).ok_or(CryptError::Decrypt("Unable to update toolset".to_string()))
    }

    /// Removes the oldest hyper ratchet version. Explicit specification required to monitor consistency in the network
    pub fn deregister_oldest_hyper_ratchet(&self, version: u32) -> Result<(), CryptError<String>> {
        let mut write = self.write();
        write.crypt_container.deregister_oldest_hyper_ratchet(version)
    }

    /// Replaces the internal toolset. This should ONLY be called (if absolutely necessary) during the PRE_CONNECT stage
    /// if synchronization is required
    pub fn replace_toolset(&self, toolset: Toolset<R>) {
        self.write().crypt_container.toolset = toolset;
    }

    /// This should ONLY be used for recovery mode
    pub fn get_static_auxiliary_hyper_ratchet(&self) -> R {
        let this = self.read();
        this.crypt_container.toolset.get_static_auxiliary_ratchet().clone()
    }

    /// Removes the CNAC from the hard drive
    pub async fn purge_from_fs(&mut self) -> Result<(), AccountError<String>> {
        let read = self.read();
        let path = &read.local_save_path;
        let ref pass_path_opt = read.hyxefile_save_path;

        hyxe_fs::system_file_manager::delete_file(path).await.map_err(|err| AccountError::IoError(err.to_string()))
            .and_then(|_| if let Some(pass) = pass_path_opt {
                std::fs::remove_file(pass).map_err(|err| err.into())
            } else {
                Ok(())
            })
    }


    /// Purges this from the hard drive
    pub fn purge_from_fs_blocking(&mut self) -> Result<(), AccountError<String>> {
        let read = self.read();
        let ref path = read.local_save_path;
        let ref pass_path_opt = read.hyxefile_save_path;

        std::fs::remove_file(path).map_err(|err| err.into())
            .and_then(|_| if let Some(pass) = pass_path_opt {
                std::fs::remove_file(pass).map_err(|err| err.into())
            } else {
                Ok(())
            })
    }

    /// Reads futures-style
    pub fn read(&self) -> ShardedLockReadGuard<ClientNetworkAccountInner<R, Fcm>> {
        self.inner.inner.read().unwrap()
    }

    /// Reads futures-style
    pub fn write(&self) -> ShardedLockWriteGuard<ClientNetworkAccountInner<R, Fcm>> {
        self.inner.inner.write().unwrap()
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
        hyperlan_peers.iter().find(|peer| peer.cid == cid).cloned()
    }

    /// Gets the desired HyperLAN peer by username (clones)
    pub fn get_hyperlan_peer_by_username<T: AsRef<str>>(&self, username: T) -> Option<MutualPeer> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        let username = username.as_ref();

        hyperlan_peers.iter().find(|peer| peer.username.as_ref().map(|name| name == username).unwrap_or(false)).cloned()
    }

    /// This function handles the registration for BOTH CNACs. Then, it synchronizes both to
    /// the local filesystem on the Threadpool
    #[allow(unused_results)]
    pub fn register_hyperlan_p2p_as_server(&self, other_orig: &ClientNetworkAccount) {
        let this_cid = self.inner.cid;
        let other_cid = other_orig.inner.cid;

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
                log::error!("Unable to save CNAC {} to the local filesystem: {:?}", this_cid, err);
            }

            if let Err(err) = other.async_save_to_local_fs().await {
                log::error!("Unable to save CNAC {} to the local filesystem: {:?}", other_cid, err);
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
            hyperlan_peers.iter().any(|peer| peer.cid == cid)
        } else {
            log::info!("mutuals vec is missing the hyperlan idx");
            false
        }
    }

    /// Returns true if and only if all the peers in `peers` exist
    pub fn hyperlan_peers_exist(&self, peers: &Vec<u64>) -> bool {
        let read = self.read();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            peers.iter().all(|peer| hyperlan_peers.iter().any(|hyperlan_peer| hyperlan_peer.cid == *peer))
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
            hyperlan_peers.iter().any(|peer| peer.username.as_ref().map(|uname| uname == username).unwrap_or(false))
        } else {
            false
        }
    }

    /// ONLY run this after you're sure the peer doesn't already exist
    pub fn insert_hyperlan_peer<T: ToString>(&self, cid: u64, username: T) {
        let mut write = self.write();
        let username = Some(username.to_string());

        write.mutuals.insert(HYPERLAN_IDX, MutualPeer { username, parent_icid: HYPERLAN_IDX, cid });
    }

    /// Returns Some if success, None otherwise. Also syncs to the disk in via the threadpool
    #[allow(unused_results)]
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
                    // now, remove the fcm just incase
                    write.fcm_crypt_container.remove(&cid);
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
    #[allow(unused_results)]
    pub fn remove_hyperlan_peer_by_username<T: AsRef<str>>(&self, username: T) -> Option<MutualPeer> {
        let username = username.as_ref();
        let mut write = self.write();
        if let Some(hyperlan_peers) = write.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            let mut idx: isize = -1;
            let mut cid = 0;
            if hyperlan_peers.len() != 0 {
                'search: for (vec_idx, peer) in hyperlan_peers.iter().enumerate() {
                    if let Some(user) = peer.username.as_ref() {
                        if user == username {
                            cid = peer.cid;
                            idx = vec_idx as isize;
                            break 'search;
                        }
                    }
                }
            } else {
                log::info!("Attempted to remove a HyperLAN Peer, but it doesn't exist!");
            }

            if idx != -1 {
                let removed = hyperlan_peers.remove(idx as usize);
                write.fcm_crypt_container.remove(&cid);
                return Some(removed);
            }
        }

        None
    }

    /*
         End of the mutual peer-related functions
     */

    #[allow(unused_results)]
    /// Replaces the internal FCM device
    pub fn replace_fcm_crypt_container(&self, peer_cid: u64, container: PeerSessionCrypto<Fcm>) {
        let mut write = self.write();
        write.fcm_crypt_container.insert(peer_cid, container);
    }

    #[allow(unused_results)]
    /// Returns the FcmPostRegister instance meant to be sent through the ordinary network. Additionally, returns the ticket associated with the transaction
    pub fn fcm_prepare_accept_register(&self, peer_cid: u64, accept: bool) -> Result<(FcmPostRegister, u64), AccountError> {
        let mut write = self.write();
        let local_cid = write.cid;

        // remove regardless
        let invite = write.fcm_invitations.remove(&peer_cid).ok_or(AccountError::Generic("Invitation for client does not exist, or, expired".to_string()))?;

        /*if write.fcm_crypt_container.contains_key(&peer_cid) {
            return Err(AccountError::ClientExists(peer_cid))
        }*/

        match invite {
            InvitationType::PostRegister(FcmPostRegister::AliceToBobTransfer(transfer, fcm_keys, ..), username, ticket) => {
                //let fcm_instance = FCMInstance::new(fcm_keys.clone(), client.clone());

                if accept {
                    // now, construct the endpoint container
                    let bob_constructor = Fcm::Constructor::new_bob(0, local_cid, 0,AliceToBobTransferType::Fcm(FcmAliceToBobTransfer::deserialize_from_vector(&transfer[..]).map_err(|err| AccountError::Generic(err.to_string()))?)).ok_or(AccountError::IoError("Bad ratchet container".to_string()))?;
                    let fcm_post_register = FcmPostRegister::BobToAliceTransfer(bob_constructor.stage0_bob().ok_or(AccountError::IoError("Stage0/Bob failed".to_string()))?.assume_fcm().unwrap(), fcm_keys.clone(), local_cid);
                    let fcm_ratchet = bob_constructor.finish_with_custom_cid(local_cid).ok_or(AccountError::IoError("Unable to construct Bob's ratchet".to_string()))?;

                    write.fcm_crypt_container.insert(peer_cid, PeerSessionCrypto::new_fcm(Toolset::new(local_cid, fcm_ratchet), false, fcm_keys));
                    write.mutuals.insert(HYPERLAN_IDX, MutualPeer { parent_icid: HYPERLAN_IDX, cid: peer_cid, username: Some(username) });
                    std::mem::drop(write);
                    self.clone().spawn_save_task_on_threadpool();
                    Ok((fcm_post_register, ticket))
                } else {
                    Ok((FcmPostRegister::Disable, ticket))
                }
            }

            _ => {
                Err(AccountError::Generic("package is not a valid post-register type".to_string()))
            }
        }
    }

    /// For sending a pre-prepared packet. Specifying a nonzero target cid will send to target's FCM. If target cid is zero, then will send to self
    pub async fn fcm_raw_send(&self, target_cid: u64, raw_fcm_packet: RawFcmPacket, fcm_client: &Arc<Client>) -> Result<FcmResponse, AccountError> {
        let mut write = self.write();
        let fcm_keys = if target_cid == 0 {
            write.crypt_container.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?
        } else {
            write.fcm_crypt_container.get_mut(&target_cid).ok_or(AccountError::ClientNonExists(target_cid))?.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?
        };

        let instance = FCMInstance::new(fcm_keys, fcm_client.clone());
        instance.send_to_fcm_user(raw_fcm_packet).await
    }

    /// sends, blocking on an independent single-threaded executor
    pub fn blocking_fcm_send_to(&self, target_peer_cid: u64, message: SecBuffer, client: &Arc<Client>) -> Result<FcmProcessorResult, AccountError> {
        let this = self.clone();
        let client = client.clone();
        block_on_async(move || async move {
            this.fcm_send_message_to(target_peer_cid, message, &client).await
        })?
    }

    /// Sends the request to the FCM server, returns the ticket for the request
    pub async fn fcm_send_message_to(&self, target_peer_cid: u64, message: SecBuffer, client: &Arc<Client>) -> Result<FcmProcessorResult, AccountError> {
        let (ticket, fcm_instance, packet) = self.prepare_fcm_send_message(target_peer_cid, message, client)?;
        fcm_instance.send_to_fcm_user(packet).await.map(|_| FcmProcessorResult::Value(FcmResult::MessageSent { ticket }))
    }

    /// Prepares the requires abstractions needed to send data
    fn prepare_fcm_send_message(&self, target_peer_cid: u64, message: SecBuffer, client: &Arc<Client>) -> Result<(FcmTicket, FCMInstance, RawFcmPacket), AccountError> {
        let mut write = self.write();
        let ClientNetworkAccountInner::<R, Fcm> {
            fcm_crypt_container,
            kem_state_containers,
            cid,
            ..
        } = &mut *write;

        let crypt_container = fcm_crypt_container.get_mut(&target_peer_cid).ok_or(AccountError::ClientNonExists(target_peer_cid))?;

        // construct the instance
        let fcm_instance = FCMInstance::new(crypt_container.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?, client.clone());

        let ref ratchet = crypt_container.get_hyper_ratchet(None).unwrap().clone();
        let object_id = crypt_container.get_and_increment_object_id();
        let group_id = crypt_container.get_and_increment_group_id();

        let ticket = FcmTicket::new(*cid, target_peer_cid, object_id);

        let constructor = crypt_container.get_next_constructor(None);
        let transfer = constructor.as_ref().map(|con| con.stage0_alice());
        let packet = crate::fcm::fcm_packet_crafter::craft_group_header(ratchet, object_id, group_id, target_peer_cid, message, transfer).ok_or(AccountError::Generic("Report to developers (x-77)".to_string()))?;

        // store constructor if required (may not be required if an update is already in progress)
        if let Some(constructor) = constructor {
            if kem_state_containers.insert(target_peer_cid, ConstructorType::Fcm(constructor)).is_some() {
                log::error!("[FCM] overwrote pre-existing KEM constructor. Please report to developers")
            }
        }

        Ok((ticket, fcm_instance, packet))
    }



    /// Generates the bytes of the underlying [ClientNetworkAccountInner]
    pub async fn generate_bytes_async(&self) -> Result<Vec<u8>, AccountError<String>> where ClientNetworkAccountInner<R, Fcm>: AsyncIO {
        self.write().async_serialize_to_vector().await.map_err(|err| AccountError::IoError(err.to_string()))
    }

    /// Useful for transmission
    pub fn generate_bytes_sync(&self) -> Result<Vec<u8>, AccountError<String>> where ClientNetworkAccountInner<R, Fcm>: SyncIO {
        self.write().serialize_to_vector().map_err(|err| err.into())
    }

    /// Visit the inner device
    pub fn visit<J>(&self, fx: impl FnOnce(ShardedLockReadGuard<'_, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.read())
    }

    /// Visit the inner device mutably
    pub fn visit_mut<J>(&self, fx: impl FnOnce(ShardedLockWriteGuard<'_, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.write())
    }

    /// Blocking version of `async_save_to_local_fs`
    pub fn blocking_save_to_local_fs(&self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner<R, Fcm>: SyncIO, NetworkAccountInner: SyncIO {
        let mut ptr = self.write();
        let dirs = ptr.dirs.clone().ok_or_else(|| AccountError::Generic("Directory store not loaded".to_string()))?;
        //debug_assert!(ptr.hyxefile_save_path.is_none());
        //debug_assert!(ptr.inner_encrypted_nac.is_none());

        let static_hyper_ratchet = ptr.crypt_container.toolset.get_static_auxiliary_ratchet().clone();
        //let path = ptr.local_save_path.clone();

        // impersonals store the password, NOT personals!
        if !ptr.is_local_personal {
            // We save the password locally if self is server. FIRST, check to see if the old password hyxefile exists
            if let Some(ref old_pswd_hyxefile) = ptr.hyxefile_save_path {
                std::fs::remove_file(old_pswd_hyxefile).map_err(|err| AccountError::IoError(err.to_string()))?
            }

            let password_bytes = ptr.password_in_ram.as_ref().unwrap().unsecure().to_vec();
            let password_hyxefile = ptr.password_hyxefile.as_mut().unwrap();
            let _ = password_hyxefile.replace_contents(&static_hyper_ratchet, password_bytes.as_slice(), false, SecurityLevel::DIVINE).map_err(|err| AccountError::IoError(err.to_string()))?;
            let path = password_hyxefile.save_locally_blocking(&dirs).map_err(|err| AccountError::IoError(err.to_string()))?;
            ptr.hyxefile_save_path = Some(path.clone());
        } else {
            debug_assert!(ptr.password_in_ram.is_none());
        }

        // We don't save the password locally if self is client

        // next, we must encrypt the inner [NetworkAccount] into the HyxeFile, whether self is client or not
        let mut new_hyxefile = HyxeFile::new(&ptr.full_name, ptr.cid, "encrypted_nac", None);
        let nac_unencrypted_bytes = ptr.adjacent_nac.as_ref().unwrap().read().serialize_to_vector().map_err(|err| AccountError::IoError(err.to_string()))?;
        // We save the bytes inside the HyxeFile.
        new_hyxefile.drill_contents(&static_hyper_ratchet, nac_unencrypted_bytes.as_slice(), SecurityLevel::DIVINE).map_err(|err| AccountError::IoError(err.to_string()))?;
        // Place the HyxeFile inside
        assert!(ptr.inner_encrypted_nac.replace(new_hyxefile).is_none());
        ptr.kem_state_containers.retain(|_, con| con.is_fcm());

        // finally, save the CNAC to the local hard drive, but using the save path for the CNAC instead of the password HyxeFile
        let save_path = ptr.local_save_path.as_path().clone();
        log::info!("Saving CNAC {} to {}", ptr.cid, save_path.display());
        ptr.serialize_to_local_fs(save_path).map_err(|err| AccountError::IoError(err.to_string()))?;
        ptr.inner_encrypted_nac = None; // to free memory from the heap
        Ok(())
    }

    /// Returns the CID
    pub fn get_cid(&self) -> u64 {
        self.get_id()
    }

    /// This will panic if the adjacent NAC is not loaded
    pub fn get_adjacent_nid(&self) -> u64 {
        self.inner.adjacent_nid
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> HyperNodeAccountInformation for ClientNetworkAccount<R, Fcm> {
    fn get_id(&self) -> u64 {
        self.inner.cid
    }

    // TODO: Make the syncing process cleaner. This is "blocking", but not really because a small amount of data is written to the disk
    async fn async_save_to_local_fs(self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner: SyncIO, NetworkAccountInner: SyncIO {
        self.blocking_save_to_local_fs()
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Debug for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CNAC | CID: {}, Adjacent NID: {}", self.inner.cid, self.inner.adjacent_nid)
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Display for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let inner = self.read();
        writeln!(f, "{}\t\t{}\t\t{}\t\t{}", self.inner.cid, &inner.username, &inner.full_name, self.inner.is_personal)
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<ClientNetworkAccountInner<R, Fcm>> for MetaInner<R, Fcm> {
    fn from(inner: ClientNetworkAccountInner<R, Fcm>) -> Self {
        let adjacent_nid = inner.adjacent_nac.as_ref().unwrap().get_id();
        Self { cid: inner.cid, adjacent_nid, is_personal: inner.is_local_personal, inner: ShardedLock::new(inner) }
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<MetaInner<R, Fcm>> for ClientNetworkAccount<R, Fcm> {
    fn from(inner: MetaInner<R, Fcm>) -> Self {
        Self { inner: Arc::new(inner) }
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<ClientNetworkAccountInner<R, Fcm>> for ClientNetworkAccount<R, Fcm> {
    fn from(inner: ClientNetworkAccountInner<R, Fcm>) -> Self {
        ClientNetworkAccount::from(MetaInner::from(inner))
    }
}

impl<R: Ratchet, Fcm: Ratchet> Clone for ClientNetworkAccount<R, Fcm> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}