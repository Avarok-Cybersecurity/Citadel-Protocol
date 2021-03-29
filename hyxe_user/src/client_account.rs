use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use hyxe_fs::hyxe_crypt::prelude::*;
use hyxe_fs::env::DirectoryStore;
use hyxe_fs::hyxe_file::HyxeFile;
use hyxe_fs::prelude::SyncIO;

use crate::hypernode_account::{CNAC_SERIALIZED_EXTENSION, HyperNodeAccountInformation};
use crate::misc::{AccountError, check_credential_formatting};
use std::net::SocketAddr;
use multimap::MultiMap;
use crate::prelude::NetworkAccount;
use hyxe_fs::system_file_manager::bytes_to_type;
use crate::network_account::NetworkAccountInner;
use log::info;

use std::fmt::Formatter;
use hyxe_fs::misc::{get_present_formatted_timestamp, get_pathbuf};
use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};
use hyxe_fs::hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_fs::hyxe_crypt::toolset::UpdateStatus;
use hyxe_fs::hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use std::ops::RangeInclusive;

use std::collections::{HashMap, BTreeMap};
use hyxe_crypt::fcm::fcm_ratchet::{FcmAliceToBobTransfer, FcmRatchet};
use hyxe_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use hyxe_crypt::hyper_ratchet::constructor::{ConstructorType, AliceToBobTransferType};
use fcm::{Client, FcmResponse};
use crate::fcm::fcm_instance::FCMInstance;
use crate::fcm::data_structures::{FcmTicket, RawFcmPacket};
use crate::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, FcmPacketMaybeNeedsSending};
use crate::fcm::fcm_packet_processor::peer_post_register::InvitationType;
use crate::fcm::kem::FcmPostRegister;
use hyxe_crypt::fcm::keys::FcmKeys;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use crate::backend::PersistenceHandler;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::argon_container::{ArgonContainerType, AsyncArgon, ArgonStatus};
use crate::proposed_credentials::ProposedCredentials;


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
    #[serde(with = "crate::fcm::data_structures::none")]
    pub adjacent_nac: Option<NetworkAccount<R, Fcm>>,
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
    /// The PathBuf stored the local save location (only relevant for filesystem storage)
    #[serde(skip)]
    local_save_path: Option<PathBuf>,
    /// The HyxeFile for the NAC. Serde skips serializing the `client_nac`, and instead it gets encrypted into here during
    /// the serializing process. During the load_safe process, this must have some value. During execution, this should be none
    inner_encrypted_nac: Option<HyxeFile>,
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
    /// Only the server should store these values. The first key is the peer cid, the second key is the raw ticket ID, used for organizing proper order
    fcm_packet_store: Option<HashMap<u64, BTreeMap<u64, RawFcmPacket>>>,
    #[serde(with = "crate::fcm::data_structures::none")]
    persistence_handler: Option<PersistenceHandler<R, Fcm>>,
    argon_container: ArgonContainerType
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
    pub async fn new<T: ToString, V: ToString>(valid_cid: u64, is_personal: bool, adjacent_nac: NetworkAccount<R, Fcm>, username: T, full_name: V, argon_container: ArgonContainerType, base_hyper_ratchet: R, persistence_handler: PersistenceHandler<R, Fcm>, fcm_keys: Option<FcmKeys>) -> Result<Self, AccountError<String>> {
        info!("Creating CNAC w/valid cid: {:?}", valid_cid);
        let username = username.to_string();
        let full_name = full_name.to_string();

        check_credential_formatting::<_, &str, _>(&username, None, &full_name)?;

        let creation_date = get_present_formatted_timestamp();
        // the static & f(0) hyper ratchets will be the provided hyper ratchet
        let mut crypt_container = PeerSessionCrypto::<R>::new(Toolset::<R>::new(valid_cid, base_hyper_ratchet), is_personal);
        crypt_container.fcm_keys = fcm_keys;
        //debug_assert_eq!(is_personal, is_client);


        let local_save_path = persistence_handler.maybe_generate_cnac_local_save_path(valid_cid, is_personal);

        let mutuals = MultiMap::new();
        let persistence_handler = Some(persistence_handler);

        let fcm_crypt_container = HashMap::with_capacity(0);
        let kem_state_containers = HashMap::with_capacity(0);
        let fcm_invitations = HashMap::with_capacity(0);
        let fcm_packet_store = None;

        let inner = ClientNetworkAccountInner::<R, Fcm> { fcm_packet_store, fcm_invitations, kem_state_containers, fcm_crypt_container, persistence_handler, creation_date, cid: valid_cid, argon_container, username, adjacent_nac: Some(adjacent_nac), is_local_personal: is_personal, full_name, mutuals, local_save_path, inner_encrypted_nac: None, crypt_container };
        let this = Self::from(inner);

        this.save().await?;

        Ok(this)
    }

    /// saves to db/fs
    #[allow(unused_results)]
    pub fn spawn_save_task_on_threadpool(&self) {
        let this = self.clone();
        tokio::task::spawn(async move {
            if let Err(err) = this.save().await {
                log::error!("Unable to save cnac {}: {:?}", this.get_cid(), err);
            }
        });
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

    /// Towards the end of the registration phase, the [ClientNetworkAccountInner] gets transmitted to Alice.
    pub async fn new_from_network_personal<X: ToString, K: ToString>(valid_cid: u64, hyper_ratchet: R, username: X, full_name: K, argon_container: ArgonContainerType, adjacent_nac: NetworkAccount<R, Fcm>, persistence_handler: PersistenceHandler<R, Fcm>, fcm_keys: Option<FcmKeys>) -> Result<Self, AccountError<String>> {
        const IS_PERSONAL: bool = true;

        // We supply none to the valid cid
        Self::new(valid_cid, IS_PERSONAL, adjacent_nac, username, full_name, argon_container,hyper_ratchet, persistence_handler, fcm_keys).await
    }

    /// When the client received its inner CNAC, it will not have the NAC of the server. Therefore, the client-version of the CNAC must be updated
    pub fn update_inner_nac(&self, server_nac_for_this_cnac: NetworkAccount<R, Fcm>) {
        let mut write = self.write();
        write.adjacent_nac = Some(server_nac_for_this_cnac);
    }

    /// Returns the username of this client
    pub fn get_username(&self) -> String {
        self.read().username.clone()
    }

    /// Returns the [NetworkAccount] associated with the [ClientNetworkAccount]. Before being called,
    /// validate_ip should be ran in order to update the internal IP address for this session
    pub fn get_nac(&self) -> NetworkAccount<R, Fcm> {
        self.read().adjacent_nac.clone().unwrap()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub async fn validate_credentials<T: AsRef<[u8]>>(&self, username: T, password_hashed: SecBuffer) -> Result<(), AccountError<String>> {
        let (argon_container, username_internal) = {
            let read = self.read();
            (read.argon_container.clone(), read.username.clone())
        };


        match argon_container {
            ArgonContainerType::Server(server_container) => {
                if username.as_ref() != username_internal.as_bytes() {
                    return Err(AccountError::InvalidUsername);
                }

                match AsyncArgon::verify(password_hashed, server_container).await.map_err(|err| AccountError::Generic(err.to_string()))? {
                    ArgonStatus::VerificationSuccess => {
                        Ok(())
                    }

                    _ => {
                        Err(AccountError::InvalidPassword)
                    }
                }
            }

            _ => {
                return Err(AccountError::Generic("Account does not have password loaded; account is personal".to_string()))
            }
        }
    }

    /// This should be called on the client before passing a connect request to the protocol
    pub async fn hash_password_as_client(&self, input: SecBuffer) -> Result<ProposedCredentials, AccountError> {
        let (settings, full_name, username) = {
          let read = self.read();
            (read.argon_container.clone(), read.full_name.clone(), read.username.clone())
        };

        match settings {
            ArgonContainerType::Client(client_container) => {
                match AsyncArgon::hash(input, client_container.settings).await.map_err(|err| AccountError::Generic(err.to_string()))? {
                    ArgonStatus::HashSuccess(hashed_password) => {
                        Ok(ProposedCredentials::new(full_name, username, hashed_password))
                    }

                    _ => {
                        Err(AccountError::Generic("Unable to hash password".to_string()))
                    }
                }
            }

            _ => {
                Err(AccountError::Generic("Local is not a client type".to_string()))
            }
        }
    }

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

    /// Purges this from the hard drive
    pub fn purge_from_fs_blocking(&self) -> Result<(), AccountError<String>> {
        let read = self.read();
        if let Some(ref path) = read.local_save_path {
            std::fs::remove_file(path).map_err(|err| err.into())
        } else {
            Err(AccountError::Generic("Save path not loaded inside".into()))
        }
    }

    /// Allows shared interior access
    pub fn read(&self) -> ShardedLockReadGuard<ClientNetworkAccountInner<R, Fcm>> {
        self.inner.inner.read().unwrap()
    }

    /// Allows exclusive interior access
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
    pub fn get_hyperlan_peer_list_with_fcm_keys(&self) -> Option<Vec<(u64, Option<FcmKeys>)>> {
        let this = self.read();
        let hyperlan_peers = this.mutuals.get_vec(&HYPERLAN_IDX)?;

        Some(hyperlan_peers.into_iter()
            .map(|peer| {
                if let Some(fcm_crypt_container) = this.fcm_crypt_container.get(&peer.cid) {
                    if let Some(keys) = fcm_crypt_container.fcm_keys.clone() {
                        return (peer.cid, Some(keys))
                    }
                }

                (peer.cid, None)
            }).collect())
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
    pub fn register_hyperlan_p2p_as_server_filesystem(&self, other_orig: &ClientNetworkAccount<R, Fcm>) {
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
            if let Err(err) = this.save().await {
                log::error!("Unable to save CNAC {}: {:?}", this_cid, err);
            }

            if let Err(err) = other.save().await {
                log::error!("Unable to save CNAC {}: {:?}", other_cid, err);
            }
        });
    }

    /// Gets the FCM send addr, if available
    pub fn get_fcm_keys(&self) -> Option<FcmKeys> {
        self.read().crypt_container.fcm_keys.clone()
    }

    /// Deregisters two peers as server
    #[allow(unused_results)]
    pub fn deregister_hyperlan_p2p_as_server_filesystem(&self, other: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        self.remove_hyperlan_peer(other.get_cid()).ok_or(AccountError::ClientNonExists(other.get_cid()))?;
        other.remove_hyperlan_peer(self.get_cid()).ok_or(AccountError::Generic("Could not remove self from other cnac".to_string()))?;

        Ok(())
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
            log::info!("No mutuals registered on this accounts");
            false
        }
    }

    /// Returns true if a registration is currently pending
    pub fn fcm_hyperlan_peer_registration_pending(&self, target_cid: u64) -> bool {
        let read = self.read();
        read.kem_state_containers.contains_key(&target_cid) || read.fcm_invitations.contains_key(&target_cid)
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
    ///
    /// Returns true if the data was mutated
    pub fn synchronize_hyperlan_peer_list(&self, peers: &Vec<(u64, Option<FcmKeys>)>) -> bool {
        let mut this = self.write();
        let mut needs_save = false;

        if let Some(hyperlan_peers) = this.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            hyperlan_peers.retain(|hyperlan_peer| {
                for (peer, _) in peers {
                    if *peer == hyperlan_peer.cid {
                        // found a match; retain the entry
                        return true;
                    }
                }
                // no match found; do no retain the entry
                log::warn!("[CNAC Synchronize]: peer {} does not exist in the HyperLAN Server; removing", hyperlan_peer.cid);
                needs_save = true;
                false
            });


            for (peer_cid, fcm_keys) in peers {
                if let Some(fcm_keys) = fcm_keys {
                    if let Some(fcm_crypt_container) = this.fcm_crypt_container.get_mut(peer_cid) {
                        fcm_crypt_container.fcm_keys = Some(fcm_keys.clone());
                        needs_save = true;
                    } else {
                        log::warn!("Attemped to synchronize peer list, but local's state is corrupt (fcm)");
                    }
                }
            }
        } else {
            // TODO: Network recovery mode
            log::warn!("Attempted to synchronize peer list, but local's state is corrupt")
        }

        needs_save
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
            if let Some(idx) = hyperlan_peers.iter().position(|peer| peer.cid == cid) {
                let removed_peer = hyperlan_peers.remove(idx);
                // now, remove the fcm just incase we're at the endpoints
                write.fcm_crypt_container.remove(&cid);
                std::mem::drop(write);

                self.spawn_save_task_on_threadpool();
                return Some(removed_peer);
            } else {
                log::warn!("Peer {} not found within cnac {}", cid, write.cid);
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
            if let Some(idx) = hyperlan_peers.iter().position(|peer| peer.username.as_ref().map(|name| name == username).unwrap_or(false)) {
                let removed = hyperlan_peers.remove(idx);
                write.fcm_crypt_container.remove(&removed.cid);
                std::mem::drop(write);
                self.spawn_save_task_on_threadpool();
                return Some(removed);
            }
        }

        log::info!("Attempted to remove a HyperLAN Peer, but it doesn't exist!");

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

    /// Gets the FCM keys of the peer
    pub fn get_peer_fcm_keys(&self, peer_cid: u64) -> Option<FcmKeys> {
        self.read().fcm_crypt_container.get(&peer_cid)?.fcm_keys.clone()
    }

    #[allow(unused_results)]
    /// Returns the FcmPostRegister instance meant to be sent through the ordinary network. Additionally, returns the ticket associated with the transaction
    pub async fn fcm_prepare_accept_register(&self, peer_cid: u64, accept: bool) -> Result<(FcmPostRegister, u64), AccountError> {
        let mut write = self.write();
        let local_cid = write.cid;

        let local_fcm_keys = write.crypt_container.fcm_keys.clone().ok_or(AccountError::Generic("Local client cannot accept an FCM request since local has no FCM keys to reciprocate".to_string()))?;
        // remove regardless
        let invite = write.fcm_invitations.remove(&peer_cid).ok_or(AccountError::Generic("Invitation for client does not exist, or, expired".to_string()))?;

        /*if write.fcm_crypt_container.contains_key(&peer_cid) {
            return Err(AccountError::ClientExists(peer_cid))
        }*/

        match invite {
            InvitationType::PostRegister(FcmPostRegister::AliceToBobTransfer(transfer, peer_fcm_keys, ..), username, ticket) => {

                if accept {
                    // now, construct the endpoint container
                    let bob_constructor = Fcm::Constructor::new_bob(0, local_cid, 0,AliceToBobTransferType::Fcm(FcmAliceToBobTransfer::deserialize_from_vector(&transfer[..]).map_err(|err| AccountError::Generic(err.to_string()))?)).ok_or(AccountError::IoError("Bad ratchet container".to_string()))?;
                    let fcm_post_register = FcmPostRegister::BobToAliceTransfer(bob_constructor.stage0_bob().ok_or(AccountError::IoError("Stage0/Bob failed".to_string()))?.assume_fcm().unwrap(), local_fcm_keys, local_cid);
                    let fcm_ratchet = bob_constructor.finish_with_custom_cid(local_cid).ok_or(AccountError::IoError("Unable to construct Bob's ratchet".to_string()))?;

                    write.fcm_crypt_container.insert(peer_cid, PeerSessionCrypto::new_fcm(Toolset::new(local_cid, fcm_ratchet), false, peer_fcm_keys));
                    write.mutuals.insert(HYPERLAN_IDX, MutualPeer { parent_icid: HYPERLAN_IDX, cid: peer_cid, username: Some(username) });
                    std::mem::drop(write);
                    //self.blocking_save_to_local_fs()?;
                    self.save().await?;
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
        let read = self.read();
        let fcm_keys = if target_cid == 0 {
            read.crypt_container.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?
        } else {
            read.fcm_crypt_container.get(&target_cid).ok_or(AccountError::ClientNonExists(target_cid))?.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?
        };

        let instance = FCMInstance::new(fcm_keys, fcm_client.clone());
        instance.send_to_fcm_user(raw_fcm_packet).await
    }

    /// For sending a raw packet obtained as a result of using the function-supplied ratchet. Target_cid must be nonzero
    pub async fn fcm_raw_send_to_peer(&self, target_cid: u64, raw_fcm_packet: impl FnOnce(&Fcm) -> RawFcmPacket, fcm_client: &Arc<Client>) -> Result<FcmResponse, AccountError> {
        if target_cid == 0 {
            return Err(AccountError::Generic("Target CID cannot be zero".to_string()))
        }

        let read = self.read();
        let crypt_container = read.fcm_crypt_container.get(&target_cid).ok_or(AccountError::ClientNonExists(target_cid))?;

        let fcm_keys = crypt_container.fcm_keys.clone().ok_or(AccountError::Generic("Target peer cannot received FCM messages at this time".to_string()))?;

        let latest_fcm_ratchet = crypt_container.get_hyper_ratchet(None).ok_or(AccountError::Generic("Ratchet missing".to_string()))?;

        let instance = FCMInstance::new(fcm_keys, fcm_client.clone());
        instance.send_to_fcm_user(raw_fcm_packet(latest_fcm_ratchet)).await
    }

    /// Sends to all FCM-registered peers. Enforces the use of endpoint encryption
    pub async fn fcm_raw_broadcast_to_all_peers(&self, fcm_client: Arc<Client>, raw_fcm_constructor: impl Fn(&Fcm, u64) -> RawFcmPacket) -> Result<(), AccountError> {
        let read = self.read();
        let tasks = FuturesUnordered::new();

        for (peer_cid, container) in &read.fcm_crypt_container {
            if let Some(fcm_keys) = container.fcm_keys.clone() {
                let instance = FCMInstance::new(fcm_keys, fcm_client.clone());
                let packet = (raw_fcm_constructor)(container.get_hyper_ratchet(None).unwrap(), *peer_cid);
                let future = instance.send_to_fcm_user_by_value(packet);
                tasks.push(Box::pin(future));
            }
        }

        std::mem::drop(read);

        tasks.map(|_| ()).collect::<()>().await;
        Ok(())
    }

    /// sends, blocking on an independent single-threaded executor
    pub async fn blocking_fcm_send_to(&self, target_peer_cid: u64, message: SecBuffer, ticket: u64, client: &Arc<Client>) -> Result<FcmProcessorResult, AccountError> {
        /*let this = self.clone();
        let client = client.clone();
        block_on_async(move || async move {
            this.fcm_send_message_to(target_peer_cid, message, ticket, &client).await
        })?*/
        self.fcm_send_message_to(target_peer_cid, message, ticket, client).await
    }

    /// Sends the request to the FCM server, returns the ticket for the request
    pub async fn fcm_send_message_to(&self, target_peer_cid: u64, message: SecBuffer, ticket: u64, client: &Arc<Client>) -> Result<FcmProcessorResult, AccountError> {
        let (ticket, fcm_instance, packet) = self.prepare_fcm_send_message(target_peer_cid, message, ticket, client).await?;
        fcm_instance.send_to_fcm_user(packet.clone()).await.map(|_| FcmProcessorResult::Value(FcmResult::MessageSent { ticket }, FcmPacketMaybeNeedsSending::some(None, packet)))
    }

    /// Prepares the requires abstractions needed to send data
    async fn prepare_fcm_send_message(&self, target_peer_cid: u64, message: SecBuffer, ticket_id: u64, client: &Arc<Client>) -> Result<(FcmTicket, FCMInstance, RawFcmPacket), AccountError> {
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

        let ticket = FcmTicket::new(*cid, target_peer_cid, ticket_id);

        let constructor = crypt_container.get_next_constructor(None);
        let transfer = constructor.as_ref().map(|con| con.stage0_alice());
        let packet = crate::fcm::fcm_packet_crafter::craft_group_header(ratchet, object_id, group_id, target_peer_cid, ticket_id, message, transfer).ok_or(AccountError::Generic("Report to developers (x-77)".to_string()))?;

        // store constructor if required (may not be required if an update is already in progress)
        if let Some(constructor) = constructor {
            if kem_state_containers.insert(target_peer_cid, ConstructorType::Fcm(constructor)).is_some() {
                log::warn!("[FCM] overwrote pre-existing KEM constructor. Please report to developers")
            }

            std::mem::drop(write);
            //self.blocking_save_to_local_fs()?;
            self.save().await?;
        }

        Ok((ticket, fcm_instance, packet))
    }

    /// Generates the serialized bytes
    pub fn generate_proper_bytes(&self) -> Result<Vec<u8>, AccountError> where ClientNetworkAccountInner<R, Fcm>: SyncIO {
        let mut ptr = self.write();
        let static_hyper_ratchet = ptr.crypt_container.toolset.get_static_auxiliary_ratchet();
        // next, we must encrypt the inner [NetworkAccount] into the HyxeFile, whether self is client or not
        let mut new_hyxefile = HyxeFile::new(&ptr.full_name, ptr.cid, "encrypted_nac", None);
        let nac_unencrypted_bytes = ptr.adjacent_nac.as_ref().unwrap().read().serialize_to_vector()?;
        // We save the bytes inside the HyxeFile.
        new_hyxefile.drill_contents(static_hyper_ratchet, nac_unencrypted_bytes.as_slice(), SecurityLevel::DIVINE)?;
        // Place the HyxeFile inside
        ptr.inner_encrypted_nac = Some(new_hyxefile);
        // now that the nac is encrypted internally, we can serialize
        let serialized = (&ptr as &ClientNetworkAccountInner<R, Fcm>).serialize_to_vector()?;

        ptr.inner_encrypted_nac = None; // free memory

        Ok(serialized)
    }

    /// This should be called after retrieving a CNAC from a database
    ///
    /// Note: if persistence handler is not specified, it will have to be loaded later, before any other program execution
    pub fn load_safe(mut inner: ClientNetworkAccountInner<R, Fcm>, file_path: Option<PathBuf>, persistence_handler: Option<PersistenceHandler<R, Fcm>>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        // unpack the inner encrypted nac
        let encrypted_nac = inner.inner_encrypted_nac.take().ok_or(AccountError::Generic("Inner encrypted NAC missing".to_string()))?;
        let static_aux_ratchet = inner.crypt_container.toolset.get_static_auxiliary_ratchet();
        let decrypted_bytes = encrypted_nac.read_contents(static_aux_ratchet)?;
        let deserialized = bytes_to_type::<NetworkAccountInner<R, Fcm>>(&decrypted_bytes[..])?;
        let nac = NetworkAccount::<R, Fcm>::from(deserialized);
        inner.adjacent_nac = Some(nac);
        inner.local_save_path = file_path;
        inner.persistence_handler = persistence_handler;

        Ok(ClientNetworkAccount::<R, Fcm>::from(inner))
    }

    /// Stores the persistence handler
    pub fn store_persistence_handler(&self, persistence_handler: &PersistenceHandler<R, Fcm>) {
        self.write().persistence_handler = Some(persistence_handler.clone());
    }

    /// Visit the inner device
    pub fn visit<J>(&self, fx: impl FnOnce(ShardedLockReadGuard<'_, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.read())
    }

    /// Visit the inner device mutably
    pub fn visit_mut<J>(&self, fx: impl FnOnce(ShardedLockWriteGuard<'_, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.write())
    }

    /// This should only be called by the server. The `from_peer_cid` argument should be from whom the packet was sent, while this CNAC should be the recipient
    ///
    /// NOTE: Ordering should be consequent. I.e.. no missing values, 3,4,5,6 is OK, 3,4,6,7 is not
    #[allow(unused_results)]
    pub async fn store_raw_fcm_packet_into_recipient(&self, ticket: FcmTicket, packet: RawFcmPacket) -> Result<(), AccountError> {
        let mut write = self.write();

        if write.fcm_packet_store.is_none() {
            write.fcm_packet_store = Some(HashMap::new());
        }

        let map = write.fcm_packet_store.as_mut().unwrap();

        if !map.contains_key(&ticket.source_cid) {
            map.insert(ticket.source_cid, BTreeMap::new());
        }

        let peer_store = map.get_mut(&ticket.source_cid).unwrap();
        if peer_store.contains_key(&ticket.ticket) {
           return Err(AccountError::Generic(format!("Packet with ID {} already stored", ticket.ticket)))
        }

        peer_store.insert(ticket.ticket, packet);

        std::mem::drop(write);
        self.save().await
    }

    /// Retrieves the raw packets delivered to this CNAC
    pub async fn retrieve_raw_fcm_packets(&self) -> Result<Option<HashMap<u64, BTreeMap<u64, RawFcmPacket>>>, AccountError> {
        let ret = self.write().fcm_packet_store.take();

        if ret.is_some() {
            self.save().await?;
        }

        Ok(ret)
    }

    /// Saves, capturing by value
    pub async fn save_by_value(self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner<R, Fcm>: SyncIO, NetworkAccountInner<R, Fcm>: SyncIO {
        self.save().await
    }

    /// Blocking version of `async_save_to_local_fs`
    pub async fn save(&self) -> Result<(), AccountError<String>> where ClientNetworkAccountInner<R, Fcm>: SyncIO, NetworkAccountInner<R, Fcm>: SyncIO {
        let persistence_handler = {
            let ptr = self.write();
            ptr.persistence_handler.clone().ok_or_else(|| AccountError::Generic("Persistence handler not loaded".to_string()))?
        };

        persistence_handler.save_cnac(self.clone()).await
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

impl<R: Ratchet, Fcm: Ratchet> HyperNodeAccountInformation for ClientNetworkAccount<R, Fcm> {
    fn get_id(&self) -> u64 {
        self.inner.cid
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