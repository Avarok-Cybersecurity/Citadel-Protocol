use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::misc::{AccountError, check_credential_formatting, CNACMetadata, get_present_formatted_timestamp};
use multimap::MultiMap;
use crate::prelude::ConnectionInfo;

use std::fmt::Formatter;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::toolset::UpdateStatus;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use std::ops::RangeInclusive;

use std::collections::HashMap;
use hyxe_crypt::fcm::fcm_ratchet::ThinRatchet;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::external_services::rtdb::RtdbClientConfig;
use crate::auth::DeclaredAuthenticationMode;
use std::marker::PhantomData;
use hyxe_crypt::prelude::{SecBuffer, Toolset, CryptError};
use crate::serialization::SyncIO;


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
        self.parent_icid == other.parent_icid
            && self.cid == other.cid
            && self.username.as_ref() == other.username.as_ref()
    }
}

///use futures::{TryFutureExt, TryStreamExt};
#[derive(Serialize, Deserialize)]
/// Inner device
pub struct ClientNetworkAccountInner<R: Ratchet = HyperRatchet, Fcm: Ratchet = ThinRatchet> {
    /// The client identification number
    pub cid: u64,
    /// While this NAC should be session-oriented, it may be replaced if [PINNED_IP_MODE] is disabled, meaning, a new IP
    /// address can enact as the CNAC, otherwise the IP address must stay constant
    pub adjacent_nac: ConnectionInfo,
    /// If this CNAC is for a personal connection, this is true
    pub is_local_personal: bool,
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
    /// Toolset which contains all the drills
    #[serde(bound = "")]
    pub crypt_container: PeerSessionCrypto<R>,
    /// RTDB config for client-side communications
    pub client_rtdb_config: Option<RtdbClientConfig>,
    /// For storing critical ID information for this CNAC
    pub auth_store: DeclaredAuthenticationMode,
    /// peer id -> key -> sub_key -> bytes
    pub byte_map: HashMap<u64, HashMap<String, HashMap<String, Vec<u8>>>>,
    _pd: PhantomData<Fcm>
}

/// A thread-safe handle for sharing data across threads and applications
/// 
/// SAFETY: The `cid`, `adjacent_nid`, and `is_personal` is private. These values
/// should NEVER be edited within this source file
pub struct ClientNetworkAccount<R: Ratchet = HyperRatchet, Fcm: Ratchet = ThinRatchet> {
    /// The inner thread-safe device
    inner: Arc<MetaInner<R, Fcm>>
}

struct MetaInner<R: Ratchet = HyperRatchet, Fcm: Ratchet = ThinRatchet> {
    cid: u64,
    is_personal: bool,
    passwordless: bool,
    inner: RwLock<ClientNetworkAccountInner<R, Fcm>>
}

impl<R: Ratchet, Fcm: Ratchet> ClientNetworkAccount<R, Fcm> {
    /// Note: This should ONLY be called from a server node.
    #[allow(unused_results)]
    pub async fn new(valid_cid: u64, is_personal: bool, adjacent_nac: ConnectionInfo, auth_store: DeclaredAuthenticationMode, base_hyper_ratchet: R) -> Result<Self, AccountError> {
        log::trace!(target: "lusna", "Creating CNAC w/valid cid: {:?}", valid_cid);
        // TODO: move this to validation in hyxe_net (or this may be redunant)
        check_credential_formatting::<_, &str, _>(auth_store.username(), None, auth_store.full_name())?;
        let creation_date = get_present_formatted_timestamp();
        let crypt_container = PeerSessionCrypto::<R>::new(Toolset::<R>::new(valid_cid, base_hyper_ratchet), is_personal);
        let mutuals = MultiMap::new();
        let byte_map = HashMap::with_capacity(0);
        let client_rtdb_config = None;
        let inner = ClientNetworkAccountInner::<R, Fcm> { client_rtdb_config, creation_date, cid: valid_cid, auth_store, adjacent_nac, is_local_personal: is_personal, mutuals, crypt_container, byte_map, _pd: Default::default() };
        Ok(Self::from(inner))
    }

    /// Resets the toolset, if necessary. If the CNAC was freshly serialized, the hyper ratchet
    /// is not updated. In either case, returns the static aux hyper ratchet
    #[allow(unused_results)]
    pub fn refresh_static_hyper_ratchet(&self) -> R {
        let mut write = self.write();
        write.crypt_container.toolset.verify_init_state();
        write.crypt_container.refresh_state();
        write.crypt_container.toolset.get_static_auxiliary_ratchet().clone()
    }

    /// Returns true if the NAC is a personal type
    pub fn is_personal(&self) -> bool {
        self.inner.is_personal
    }

    /// Towards the end of the registration phase, the [`ClientNetworkAccountInner`] gets transmitted to Alice.
    pub async fn new_from_network_personal(valid_cid: u64, hyper_ratchet: R, auth_store: DeclaredAuthenticationMode, conn_info: ConnectionInfo) -> Result<Self, AccountError> {
        const IS_PERSONAL: bool = true;
        // We supply none to the valid cid
        Self::new(valid_cid, IS_PERSONAL, conn_info, auth_store,hyper_ratchet).await
    }


    /// Returns the username of this client
    pub fn get_username(&self) -> String {
        self.read().auth_store.username().to_string()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub async fn validate_credentials(&self, creds: ProposedCredentials) -> Result<(), AccountError> {
        let argon_container = {
            let read = self.read();
            let username = read.auth_store.username();

            if !creds.compare_username(username.as_bytes()) {
                return Err(AccountError::InvalidUsername);
            }

            match &read.auth_store {
                DeclaredAuthenticationMode::Argon { argon, .. } => argon.clone(),
                DeclaredAuthenticationMode::Passwordless { .. } => return Ok(())
            }
        };

        creds.validate_credentials(argon_container).await
    }

    /// This should be called on the client before passing a connect request to the protocol
    pub async fn generate_connect_credentials(&self, password_raw: SecBuffer) -> Result<ProposedCredentials, AccountError> {
        let (settings, full_name, username) = {
          let read = self.read();
            match &read.auth_store {
                DeclaredAuthenticationMode::Argon { argon, full_name, username } => (argon.settings().clone(), full_name.clone(), username.clone()),
                DeclaredAuthenticationMode::Passwordless { username, .. } => return Ok(ProposedCredentials::passwordless(username.clone()))
            }
        };

        ProposedCredentials::new_connect(full_name, username, password_raw, settings).await
    }

    /// If no version is supplied, the latest drill will be retrieved
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

    /// Allows shared interior access
    pub fn read(&self) -> RwLockReadGuard<ClientNetworkAccountInner<R, Fcm>> {
        self.inner.inner.read()
    }

    /// Allows exclusive interior access
    pub fn write(&self) -> RwLockWriteGuard<ClientNetworkAccountInner<R, Fcm>> {
        self.inner.inner.write()
    }

    /*
            Start of the mutual peer-related functions
     */

    /// Returns a set of hyperlan peers
    pub(crate) fn get_hyperlan_peer_list(&self) -> Option<Vec<u64>> {
        let this = self.read();
        let hyperlan_peers = this.mutuals.get_vec(&HYPERLAN_IDX)?;
        Some(hyperlan_peers.iter().map(|peer| peer.cid).collect::<Vec<u64>>())
    }

    /// Returns a set of hyperlan peers
    pub(crate) fn get_hyperlan_peer_mutuals(&self) -> Option<Vec<MutualPeer>> {
        let this = self.read();
        this.mutuals.get_vec(&HYPERLAN_IDX).cloned()
    }

    /// Returns a set of hyperlan peers
    #[allow(dead_code)]
    pub(crate) fn get_hyperwan_peer_list(&self, icid: u64) -> Option<Vec<u64>> {
        let this = self.read();
        let hyperwan_peers = this.mutuals.get_vec(&icid)?;
        Some(hyperwan_peers.iter().map(|peer| peer.cid).collect::<Vec<u64>>())
    }

    /// Gets the desired HyperLAN peer by CID (clones)
    pub(crate) fn get_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        hyperlan_peers.iter().find(|peer| peer.cid == cid).cloned()
    }

    /// Returns the wanted peers
    pub(crate) fn get_hyperlan_peers(&self, peers: &Vec<u64>) -> Option<Vec<MutualPeer>> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        Some(peers.iter().filter_map(|peer_wanted| hyperlan_peers.iter().find(|peer| peer.cid == *peer_wanted).cloned()).collect())
    }

    /// This function handles the registration for BOTH CNACs. Then, it synchronizes both to
    #[allow(unused_results)]
    pub(crate) fn register_hyperlan_p2p_as_server(&self, other_orig: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let this_cid = self.inner.cid;
        let other_cid = other_orig.inner.cid;

        let mut this = self.write();
        let mut other = other_orig.write();

        let this_username = this.auth_store.username().to_string();
        let other_username = other.auth_store.username().to_string();

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

        Ok(())
    }

    /// Deregisters two peers as server
    #[allow(unused_results)]
    pub(crate) fn deregister_hyperlan_p2p_as_server(&self, other: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        self.remove_hyperlan_peer(other.get_cid()).ok_or(AccountError::ClientNonExists(other.get_cid()))?;
        other.remove_hyperlan_peer(self.get_cid()).ok_or(AccountError::Generic("Could not remove self from other cnac".to_string()))?;

        Ok(())
    }

    /// Returns a set of registration statuses (true/false) for each co-responding peer. True if registered, false otherwise
    pub(crate) fn hyperlan_peers_exist(&self, peers: &Vec<u64>) -> Vec<bool> {
        let read = self.read();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            peers.iter().map(|peer| hyperlan_peers.iter().any(|hyperlan_peer| hyperlan_peer.cid == *peer)).collect()
        } else {
            log::warn!(target: "lusna", "Attempted to check hyperlan list, but it non-exists");
            peers.iter().map(|_| false).collect()
        }
    }

    /// Removes any inputs from the internal map that are not present in `peers`. The set `peers` should be
    /// obtained from the HyperLAN Server
    ///
    /// Returns true if the data was mutated
    pub(crate) fn synchronize_hyperlan_peer_list(&self, peers: Vec<MutualPeer>) {
        let mut this = self.write();
        let ClientNetworkAccountInner::<R, Fcm> {
            mutuals,
            ..
        } = &mut *this;

        let _ = mutuals.remove(&HYPERLAN_IDX);
        mutuals.insert_many(HYPERLAN_IDX, peers);
    }

    /// ONLY run this after you're sure the peer doesn't already exist
    pub(crate) fn insert_hyperlan_peer<T: Into<String>>(&self, cid: u64, username: T) {
        let mut write = self.write();
        let username = Some(username.into());

        write.mutuals.insert(HYPERLAN_IDX, MutualPeer { username, parent_icid: HYPERLAN_IDX, cid });
    }

    /// Returns Some if success, None otherwise. Also syncs to the disk in via the threadpool
    #[allow(unused_results)]
    pub(crate) fn remove_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        let mut write = self.write();
        if let Some(hyperlan_peers) = write.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            if let Some(idx) = hyperlan_peers.iter().position(|peer| peer.cid == cid) {
                let removed_peer = hyperlan_peers.remove(idx);
                return Some(removed_peer);
            } else {
                log::warn!(target: "lusna", "Peer {} not found within cnac {}", cid, write.cid);
            }
        }

        None
    }

    /*
         End of the mutual peer-related functions
     */


    /// Generates the serialized bytes
    pub fn generate_proper_bytes(&self) -> Result<Vec<u8>, AccountError> where ClientNetworkAccountInner<R, Fcm>: SyncIO {
        // get write lock to ensure no further writes
        let ptr = self.write();
        // now that the nac is encrypted internally, we can serialize
        let serialized = (&ptr as &ClientNetworkAccountInner<R, Fcm>).serialize_to_vector()?;

        Ok(serialized)
    }

    /// This should be called after retrieving a CNAC from a database
    ///
    /// Note: if persistence handler is not specified, it will have to be loaded later, before any other program execution
    pub(crate) fn load_safe(inner: ClientNetworkAccountInner<R, Fcm>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        Ok(ClientNetworkAccount::<R, Fcm>::from(inner))
    }

    /// Visit the inner device
    pub fn visit<J>(&self, fx: impl FnOnce(RwLockReadGuard<'_, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.read())
    }

    /// Visit the inner device mutably
    /// NOTE! The only fields that should be mutated internally are the (fcm) crypt containers. The peer information should
    /// only be mutated through the persistence handler. In the case of an FCM crypt container, saving should be called after mutating
    /// TODO: Make visit with restricted input parameter to reflect the above
    pub fn visit_mut<'a, 'b: 'a, J: 'b>(&'b self, fx: impl FnOnce(RwLockWriteGuard<'a, ClientNetworkAccountInner<R, Fcm>>) -> J) -> J {
        fx(self.write())
    }

    /// Returns the metadata for this CNAC
    pub(crate) fn get_metadata(&self) -> CNACMetadata {
        let read = self.read();
        let cid = read.cid;
        let username = read.auth_store.username().to_string();
        let full_name = read.auth_store.full_name().to_string();
        let is_personal = read.is_local_personal;
        let creation_date = read.creation_date.clone();
        CNACMetadata { cid, username, full_name, is_personal, creation_date }
    }

    /// Returns the CID
    pub fn get_cid(&self) -> u64 {
        self.inner.cid
    }

    /// Returns true if passwordless
    pub fn passwordless(&self) -> bool {
        self.inner.passwordless
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Debug for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CNAC | CID: {}", self.inner.cid)
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Display for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let inner = self.read();
        writeln!(f, "{}\t\t{}\t\t{}\t\t{}", self.inner.cid, inner.auth_store.username(), inner.auth_store.full_name(), self.inner.is_personal)
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<ClientNetworkAccountInner<R, Fcm>> for MetaInner<R, Fcm> {
    fn from(inner: ClientNetworkAccountInner<R, Fcm>) -> Self {
        let authless = inner.auth_store.is_passwordless();
        Self { cid: inner.cid, is_personal: inner.is_local_personal, passwordless: authless, inner: RwLock::new(inner) }
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