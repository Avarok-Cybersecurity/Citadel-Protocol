//! # Client Network Account Management
//!
//! This module provides comprehensive client account management functionality for the Citadel Protocol.
//! It handles both personal and impersonal connection modes, secure credential management, and peer relationships
//! within HyperLAN and HyperWAN networks.
//!
//! ## Features
//!
//! * **Connection Modes**
//!   - Personal mode with full authentication and encryption
//!   - Impersonal mode for temporary or anonymous connections
//!
//! * **Security**
//!   - Secure credential storage and validation
//!   - Ratchet-based cryptographic state management
//!   - Immutable critical security fields
//!
//! * **Network Management**
//!   - HyperLAN and HyperWAN peer relationship handling
//!   - Peer list synchronization
//!   - P2P connection support
//!   - Connection endpoint configuration
//!
//! * **Thread Safety**
//!   - All operations are thread-safe through RwLock
//!   - Concurrent access to shared resources
//!
//! ## Important Notes
//!
//! 1. Always use strong passwords and proper credential management
//! 2. Keep cryptographic state synchronized between peers
//! 3. Handle connection errors and implement proper retry logic
//! 4. Regularly clean up stale peer connections
//! 5. Monitor connection quality and implement appropriate fallbacks
//!
//! ## Related Components
//!
//! * `NetworkMode` - Defines the network operation mode
//! * `PeerConnection` - Manages individual peer connections
//! * `SecurityState` - Handles cryptographic state
//! * `EndpointConfig` - Configures connection endpoints
//!
//! Manages individual client connections within the Citadel Protocol network. Each ClientNetworkAccount
//! represents a unique connection endpoint, handling authentication, peer relationships, and cryptographic
//! state for both personal and impersonal connection modes.
//!
//! ## Features
//!
//! * **Connection Management**:
//!   - Personal and impersonal connection modes
//!   - HyperLAN and HyperWAN peer management
//!   - Connection state tracking
//!   - Network endpoint configuration
//!
//! * **Authentication**:
//!   - Secure credential management
//!   - Password-based authentication
//!   - Passwordless authentication support
//!   - Credential validation and generation
//!
//! * **Cryptographic Operations**:
//!   - Ratchet-based key management
//!   - Session crypto state handling
//!   - Static and dynamic key management
//!   - Forward secrecy support
//!
//! * **Peer Management**:
//!   - HyperLAN peer registration
//!   - Peer list synchronization
//!   - Mutual peer relationship tracking
//!   - P2P connection support
//!
//!
//! ## Important Notes
//!
//! * Each account represents a unique connection endpoint
//! * Thread-safe operations through RwLock protection
//! * Supports both personal and impersonal connection modes
//! * Automatic peer list synchronization with HyperLAN server
//! * Critical fields (cid, adjacent_nid, is_personal) are immutable
//!
//! ## Related Components
//!
//! * `auth`: Authentication and credential management
//! * `network_account`: Network node configuration
//! * `hypernode_account`: Base account functionality
//! * `citadel_crypt`: Cryptographic operations
//!

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::misc::{get_present_formatted_timestamp, AccountError, CNACMetadata};
use crate::prelude::ConnectionInfo;
use multimap::MultiMap;

use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::ratchets::Ratchet;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::fmt::Formatter;

use crate::auth::proposed_credentials::ProposedCredentials;
use crate::auth::DeclaredAuthenticationMode;
use crate::serialization::SyncIO;
use citadel_crypt::prelude::Toolset;
use citadel_crypt::ratchets::mono::MonoRatchet;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_types::crypto::SecBuffer;
use citadel_types::user::MutualPeer;
use std::collections::HashMap;
use std::marker::PhantomData;

/// The password file needs to have a hard-to-guess password enclosing in the case it is accidentally exposed over the network
pub const HYXEFILE_PASSWORD_LENGTH: usize = 222;
/// The maximum size a password can be. This upper limit was made inconsideration of the idea that passwords can bloat to the size of MAX_PACKET_SIZE, and force a split of data
/// which we want to prevent
pub const MAX_PASSWORD_SIZE: usize = 33;
/// The minimum size was selected quasi-randomly
pub const MIN_PASSWORD_SIZE: usize = 7;
/// The default index for denoting a HyperLAN connection (relative to THIS cnac)
pub const HYPERLAN_IDX: u64 = 0;

///use futures::{TryFutureExt, TryStreamExt};
#[derive(Serialize, Deserialize)]
/// Inner device
pub struct ClientNetworkAccountInner<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
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
    /// Toolset which contains all the entropy_banks
    #[serde(bound = "")]
    pub crypt_container: PeerSessionCrypto<R>,
    /// RTDB config for client-side communications
    #[cfg(feature = "google-services")]
    pub client_rtdb_config: Option<crate::external_services::rtdb::RtdbClientConfig>,
    #[cfg(not(feature = "google-services"))]
    pub client_rtdb_config: Option<()>,
    /// For storing critical ID information for this CNAC
    pub auth_store: DeclaredAuthenticationMode,
    /// peer id -> key -> sub_key -> bytes
    pub byte_map: HashMap<u64, HashMap<String, HashMap<String, Vec<u8>>>>,
    _pd: PhantomData<Fcm>,
}

/// A thread-safe handle for sharing data across threads and applications
///
/// SAFETY: The `cid`, `adjacent_nid`, and `is_personal` is private. These values
/// should NEVER be edited within this source file
pub struct ClientNetworkAccount<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
    /// The inner thread-safe device
    inner: Arc<MetaInner<R, Fcm>>,
}

struct MetaInner<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
    cid: u64,
    is_personal: bool,
    passwordless: bool,
    inner: RwLock<ClientNetworkAccountInner<R, Fcm>>,
}

impl<R: Ratchet, Fcm: Ratchet> ClientNetworkAccount<R, Fcm> {
    /// Note: This should ONLY be called from a server node.
    #[allow(unused_results)]
    pub async fn new(
        valid_cid: u64,
        is_personal: bool,
        adjacent_nac: ConnectionInfo,
        auth_store: DeclaredAuthenticationMode,
        base_stacked_ratchet: R,
    ) -> Result<Self, AccountError> {
        log::trace!(target: "citadel", "Creating CNAC w/valid cid: {:?}", valid_cid);
        let creation_date = get_present_formatted_timestamp();
        let crypt_container = PeerSessionCrypto::<R>::new(
            Toolset::<R>::new(valid_cid, base_stacked_ratchet),
            is_personal,
        );
        let mutuals = MultiMap::new();
        let byte_map = HashMap::default();
        let client_rtdb_config = None;
        let inner = ClientNetworkAccountInner::<R, Fcm> {
            client_rtdb_config,
            creation_date,
            cid: valid_cid,
            auth_store,
            adjacent_nac,
            is_local_personal: is_personal,
            mutuals,
            crypt_container,
            byte_map,
            _pd: Default::default(),
        };
        let this = Self::from(inner);
        Ok(this)
    }

    /// Resets the toolset, if necessary. If the CNAC was freshly serialized, the hyper ratchet
    /// is not updated. In either case, returns the static aux hyper ratchet
    #[allow(unused_results)]
    pub fn refresh_static_ratchet(&self) -> R {
        let mut write = self.write();
        write.crypt_container.toolset.verify_init_state();
        write.crypt_container.refresh_state();
        write
            .crypt_container
            .toolset
            .get_static_auxiliary_ratchet()
            .clone()
    }

    /// Stores the rtdb config
    #[cfg(feature = "google-services")]
    pub fn store_rtdb_config(&self, cfg: crate::external_services::rtdb::RtdbClientConfig) {
        self.write().client_rtdb_config = Some(cfg);
    }

    /// Returns true if the NAC is a personal type
    pub fn is_personal(&self) -> bool {
        self.inner.is_personal
    }

    /// Towards the end of the registration phase, the [`ClientNetworkAccountInner`] gets transmitted to Alice.
    pub async fn new_from_network_personal(
        valid_cid: u64,
        stacked_ratchet: R,
        auth_store: DeclaredAuthenticationMode,
        conn_info: ConnectionInfo,
    ) -> Result<Self, AccountError> {
        const IS_PERSONAL: bool = true;
        // We supply none to the valid cid
        Self::new(
            valid_cid,
            IS_PERSONAL,
            conn_info,
            auth_store,
            stacked_ratchet,
        )
        .await
    }

    /// Returns the username of this client
    pub fn get_username(&self) -> String {
        self.read().auth_store.username().to_string()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub async fn validate_credentials(
        &self,
        creds: ProposedCredentials,
    ) -> Result<(), AccountError> {
        let argon_container = {
            let read = self.read();
            let username = read.auth_store.username();

            if !creds.compare_username(username.as_bytes()) {
                return Err(AccountError::InvalidUsername);
            }

            match &read.auth_store {
                DeclaredAuthenticationMode::Argon { argon, .. } => argon.clone(),
                DeclaredAuthenticationMode::Passwordless { .. } => return Ok(()),
            }
        };

        creds.validate_credentials(argon_container).await
    }

    /// This should be called on the client before passing a connect request to the protocol
    pub async fn generate_connect_credentials(
        &self,
        password_raw: SecBuffer,
    ) -> Result<ProposedCredentials, AccountError> {
        let (settings, full_name, username) = {
            let read = self.read();
            match &read.auth_store {
                DeclaredAuthenticationMode::Argon {
                    argon,
                    full_name,
                    username,
                } => (
                    argon.settings().clone(),
                    full_name.clone(),
                    username.clone(),
                ),
                DeclaredAuthenticationMode::Passwordless { username, .. } => {
                    return Ok(ProposedCredentials::transient(username.clone()))
                }
            }
        };

        ProposedCredentials::new_connect(full_name, username, password_raw, settings).await
    }

    /// Replaces the internal toolset. This should ONLY be called (if absolutely necessary) during the PRE_CONNECT stage
    /// if synchronization is required
    pub fn replace_toolset(&self, toolset: Toolset<R>) {
        self.write().crypt_container.toolset = toolset;
    }

    /// This should ONLY be used for recovery mode
    pub fn get_static_auxiliary_stacked_ratchet(&self) -> R {
        let this = self.read();
        this.crypt_container
            .toolset
            .get_static_auxiliary_ratchet()
            .clone()
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
        Some(
            hyperlan_peers
                .iter()
                .map(|peer| peer.cid)
                .collect::<Vec<u64>>(),
        )
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
        Some(
            hyperwan_peers
                .iter()
                .map(|peer| peer.cid)
                .collect::<Vec<u64>>(),
        )
    }

    /// Gets the desired HyperLAN peer by CID (clones)
    pub(crate) fn get_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        let read = self.read();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        hyperlan_peers.iter().find(|peer| peer.cid == cid).cloned()
    }

    /// Returns the wanted peers
    pub(crate) fn get_hyperlan_peers(&self, peers: impl AsRef<[u64]>) -> Option<Vec<MutualPeer>> {
        let read = self.read();
        let peers = peers.as_ref();
        let hyperlan_peers = read.mutuals.get_vec(&HYPERLAN_IDX)?;
        Some(
            peers
                .iter()
                .filter_map(|peer_wanted| {
                    hyperlan_peers
                        .iter()
                        .find(|peer| peer.cid == *peer_wanted)
                        .cloned()
                })
                .collect(),
        )
    }

    /// This function handles the registration for BOTH CNACs. Then, it synchronizes both to
    #[allow(unused_results)]
    pub(crate) fn register_hyperlan_p2p_as_server(
        &self,
        other_orig: &ClientNetworkAccount<R, Fcm>,
    ) -> Result<(), AccountError> {
        let this_cid = self.inner.cid;
        let other_cid = other_orig.inner.cid;

        let mut this = self.write();
        let mut other = other_orig.write();

        let this_username = this.auth_store.username().to_string();
        let other_username = other.auth_store.username().to_string();

        this.mutuals.insert(
            HYPERLAN_IDX,
            MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid: other_cid,
                username: Some(other_username),
            },
        );

        other.mutuals.insert(
            HYPERLAN_IDX,
            MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid: this_cid,
                username: Some(this_username),
            },
        );

        Ok(())
    }

    /// Deregisters two peers as server
    #[allow(unused_results)]
    pub(crate) fn deregister_hyperlan_p2p_as_server(
        &self,
        other: &ClientNetworkAccount<R, Fcm>,
    ) -> Result<(), AccountError> {
        self.remove_hyperlan_peer(other.get_cid())
            .ok_or_else(|| AccountError::ClientNonExists(other.get_cid()))?;
        other.remove_hyperlan_peer(self.get_cid()).ok_or_else(|| {
            AccountError::Generic("Could not remove self from other cnac".to_string())
        })?;

        Ok(())
    }

    /// Returns a set of registration statuses (true/false) for each co-responding peer. True if registered, false otherwise
    pub(crate) fn hyperlan_peers_exist(&self, peers: impl AsRef<[u64]>) -> Vec<bool> {
        let read = self.read();
        let peers = peers.as_ref();
        if let Some(hyperlan_peers) = read.mutuals.get_vec(&HYPERLAN_IDX) {
            peers
                .iter()
                .map(|peer| {
                    hyperlan_peers
                        .iter()
                        .any(|hyperlan_peer| hyperlan_peer.cid == *peer)
                })
                .collect()
        } else {
            log::warn!(target: "citadel", "Attempted to check hyperlan list, but it does not exists");
            peers.iter().map(|_| false).collect()
        }
    }

    /// Removes any inputs from the internal map that are not present in `peers`. The set `peers` should be
    /// obtained from the HyperLAN Server
    ///
    /// Returns true if the data was mutated
    pub(crate) fn synchronize_hyperlan_peer_list(&self, peers: Vec<MutualPeer>) {
        let mut this = self.write();
        let ClientNetworkAccountInner::<R, Fcm> { mutuals, .. } = &mut *this;

        let _ = mutuals.remove(&HYPERLAN_IDX);
        mutuals.insert_many(HYPERLAN_IDX, peers);
    }

    /// ONLY run this after you're sure the peer doesn't already exist
    pub(crate) fn insert_hyperlan_peer<T: Into<String>>(&self, cid: u64, username: T) {
        let mut write = self.write();
        let username = Some(username.into());

        write.mutuals.insert(
            HYPERLAN_IDX,
            MutualPeer {
                username,
                parent_icid: HYPERLAN_IDX,
                cid,
            },
        );
    }

    /// Returns Some if success, None otherwise
    #[allow(unused_results)]
    pub(crate) fn remove_hyperlan_peer(&self, cid: u64) -> Option<MutualPeer> {
        log::trace!(target: "citadel", "[remove peer] session_cid: {} | peer_cid: {}", self.get_cid(), cid);
        let mut write = self.write();
        if let Some(hyperlan_peers) = write.mutuals.get_vec_mut(&HYPERLAN_IDX) {
            if let Some(idx) = hyperlan_peers.iter().position(|peer| peer.cid == cid) {
                let removed_peer = hyperlan_peers.remove(idx);
                return Some(removed_peer);
            } else {
                log::warn!(target: "citadel", "Peer {} not found within cnac {}", cid, write.cid);
            }
        }

        None
    }

    /*
        End of the mutual peer-related functions
    */

    /// Generates the serialized bytes
    pub fn generate_proper_bytes(&self) -> Result<Vec<u8>, AccountError>
    where
        ClientNetworkAccountInner<R, Fcm>: SyncIO,
    {
        // get write lock to ensure no further writes
        let ptr = self.write();
        // now that the nac is encrypted internally, we can serialize
        let serialized = (&ptr as &ClientNetworkAccountInner<R, Fcm>).serialize_to_vector()?;

        Ok(serialized)
    }

    /// Returns the metadata for this CNAC
    pub(crate) fn get_metadata(&self) -> CNACMetadata {
        let read = self.read();
        let cid = read.cid;
        let username = read.auth_store.username().to_string();
        let full_name = read.auth_store.full_name().to_string();
        let is_personal = read.is_local_personal;
        let creation_date = read.creation_date.clone();
        CNACMetadata {
            cid,
            username,
            full_name,
            is_personal,
            creation_date,
        }
    }

    /// Returns the information related to the network endpoints (e.g., socket addrs)
    pub fn get_connect_info(&self) -> ConnectionInfo {
        self.inner.inner.read().adjacent_nac.clone()
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
        writeln!(
            f,
            "{}\t\t{}\t\t{}\t\t{}",
            self.inner.cid,
            inner.auth_store.username(),
            inner.auth_store.full_name(),
            self.inner.is_personal
        )
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<ClientNetworkAccountInner<R, Fcm>> for MetaInner<R, Fcm> {
    fn from(inner: ClientNetworkAccountInner<R, Fcm>) -> Self {
        let authless = inner.auth_store.is_passwordless();
        Self {
            cid: inner.cid,
            is_personal: inner.is_local_personal,
            passwordless: authless,
            inner: RwLock::new(inner),
        }
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<MetaInner<R, Fcm>> for ClientNetworkAccount<R, Fcm> {
    fn from(inner: MetaInner<R, Fcm>) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<ClientNetworkAccountInner<R, Fcm>>
    for ClientNetworkAccount<R, Fcm>
{
    fn from(inner: ClientNetworkAccountInner<R, Fcm>) -> Self {
        ClientNetworkAccount::from(MetaInner::from(inner))
    }
}

impl<R: Ratchet, Fcm: Ratchet> Clone for ClientNetworkAccount<R, Fcm> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
