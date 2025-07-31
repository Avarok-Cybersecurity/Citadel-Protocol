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

/// The default index for denoting a HyperLAN connection (relative to THIS cnac)
pub const HYPERLAN_IDX: u64 = 0;

///use futures::{TryFutureExt, TryStreamExt};
#[derive(Serialize, Deserialize)]
/// Inner device
pub struct AccountState {
    /// RTDB config for client-side communications
    #[cfg(feature = "google-services")]
    pub client_rtdb_config: Option<crate::external_services::rtdb::RtdbClientConfig>,
    #[cfg(not(feature = "google-services"))]
    pub client_rtdb_config: Option<()>,
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
    /// peer id -> key -> sub_key -> bytes
    pub byte_map: HashMap<u64, HashMap<String, HashMap<String, Vec<u8>>>>,
}

/// A thread-safe handle for sharing data across threads and applications
///
/// SAFETY: The `cid`, `adjacent_nid`, and `is_personal` is private. These values
/// should NEVER be edited within this source file
#[derive(Serialize, Deserialize)]
pub struct ClientNetworkAccount<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
    /// The inner thread-safe device
    #[serde(bound = "")]
    inner: Arc<ClientNetworkAccountInner<R, Fcm>>,
}

#[derive(Serialize, Deserialize)]
struct ClientNetworkAccountInner<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
    /// The client identification number
    cid: u64,
    is_personal: bool,
    is_transient: bool,
    pub creation_date: String,
    pub adjacent_nac: ConnectionInfo,
    #[serde(bound = "")]
    pub crypto_session_state: Option<PeerSessionCrypto<R>>,
    /// For storing critical ID information for this CNAC
    pub auth_store: DeclaredAuthenticationMode,
    peer_state: RwLock<AccountState>,
    // For future use cases
    _phantom: PhantomData<Fcm>,
}

impl<R: Ratchet, Fcm: Ratchet> ClientNetworkAccount<R, Fcm> {
    /// Note: This should ONLY be called from a server node.
    #[allow(unused_results)]
    pub async fn new(
        valid_cid: u64,
        is_personal: bool,
        adjacent_nac: ConnectionInfo,
        auth_store: DeclaredAuthenticationMode,
        crypto_session_state: Option<PeerSessionCrypto<R>>,
    ) -> Result<Self, AccountError> {
        if valid_cid == 0 && crypto_session_state.is_some() {
            return Err(AccountError::Generic(
                "Cannot create a cryptographically secure CNAC with a CID of 0".to_string(),
            ));
        }

        log::trace!(target: "citadel", "Creating CNAC w/valid cid: {valid_cid:?}");
        let creation_date = get_present_formatted_timestamp();

        let peer_state = AccountState {
            mutuals: MultiMap::new(),
            byte_map: HashMap::default(),
            client_rtdb_config: None,
        };

        let is_transient = auth_store.is_transient();

        Ok(Self {
            inner: Arc::new(ClientNetworkAccountInner {
                creation_date,
                cid: valid_cid,
                auth_store,
                adjacent_nac,
                is_personal,
                is_transient,
                crypto_session_state,
                peer_state: RwLock::new(peer_state),
                _phantom: PhantomData,
            }),
        })
    }

    pub fn get_session_crypto(&self) -> &PeerSessionCrypto<R> {
        self.inner.crypto_session_state.as_ref().expect("Unauthorized access to the zero CID. Raising to panic. Access to the zero CID is prohibited.")
    }

    /// Resets the toolset, if necessary. If the CNAC was freshly serialized, the hyper ratchet
    /// is not updated. In either case, returns the static aux hyper ratchet
    #[allow(unused_results)]
    pub fn refresh_static_ratchet(&self) -> R {
        self.get_session_crypto().refresh_state();
        // Use write to enforce one accessor
        let write = self.get_session_crypto().toolset().write();
        write.verify_init_state();
        write.get_static_auxiliary_ratchet().clone()
    }

    /// Stores the rtdb config
    #[cfg(feature = "google-services")]
    pub fn store_rtdb_config(&self, cfg: crate::external_services::rtdb::RtdbClientConfig) {
        self.write().client_rtdb_config = Some(cfg);
    }

    pub fn auth_store(&self) -> &DeclaredAuthenticationMode {
        &self.inner.auth_store
    }

    /// Returns true if the NAC is a personal type
    pub fn is_personal(&self) -> bool {
        self.inner.is_personal
    }

    /// Towards the end of the registration phase, the [`AccountState`] gets transmitted to Alice.
    pub async fn new_from_network_personal(
        valid_cid: u64,
        session_crypto_state: Option<PeerSessionCrypto<R>>,
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
            session_crypto_state,
        )
        .await
    }

    /// Returns the username of this client
    pub fn get_username(&self) -> String {
        self.inner.auth_store.username().to_string()
    }

    /// Checks the credentials for validity. Used for the login process.
    pub async fn validate_credentials(
        &self,
        creds: ProposedCredentials,
    ) -> Result<(), AccountError> {
        let argon_container = {
            let username = self.inner.auth_store.username();

            if !creds.compare_username(username.as_bytes()) {
                return Err(AccountError::InvalidUsername);
            }

            match &self.inner.auth_store {
                DeclaredAuthenticationMode::Argon { argon, .. } => argon.clone(),
                DeclaredAuthenticationMode::Transient { .. } => return Ok(()),
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
            match &self.inner.auth_store {
                DeclaredAuthenticationMode::Argon {
                    argon,
                    full_name,
                    username,
                } => (
                    argon.settings().clone(),
                    full_name.clone(),
                    username.clone(),
                ),
                DeclaredAuthenticationMode::Transient { username, .. } => {
                    return Ok(ProposedCredentials::transient(username.clone()))
                }
            }
        };

        ProposedCredentials::new_connect(full_name, username, password_raw, settings).await
    }

    /// Replaces the internal toolset. This should ONLY be called (if absolutely necessary) during the PRE_CONNECT stage
    /// if synchronization is required
    pub fn on_session_init(&self, toolset: Toolset<R>) {
        *self.get_session_crypto().toolset().write() = toolset;
    }

    /// This should ONLY be used for recovery mode
    pub fn get_static_auxiliary_ratchet(&self) -> R {
        self.get_session_crypto()
            .toolset()
            .read()
            .get_static_auxiliary_ratchet()
            .clone()
    }

    /// Allows shared interior access
    pub fn read(&self) -> RwLockReadGuard<AccountState> {
        self.inner.peer_state.read()
    }

    /// Allows exclusive interior access
    pub fn write(&self) -> RwLockWriteGuard<AccountState> {
        self.inner.peer_state.write()
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

        let this_username = self.inner.auth_store.username().to_string();
        let other_username = other_orig.inner.auth_store.username().to_string();

        let mut this = self.write();
        let mut other = other_orig.write();

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
        let AccountState { mutuals, .. } = &mut *this;

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
                log::warn!(target: "citadel", "Peer {} not found within cnac {}", cid, self.inner.cid);
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
        Self: SyncIO,
    {
        self.serialize_to_vector()
    }

    /// Returns the metadata for this CNAC
    pub(crate) fn get_metadata(&self) -> CNACMetadata {
        let read = &self.inner;
        let cid = read.cid;
        let username = read.auth_store.username().to_string();
        let full_name = read.auth_store.full_name().to_string();
        let is_personal = read.is_personal;
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
        self.inner.adjacent_nac.clone()
    }

    /// Returns the CID
    pub fn get_cid(&self) -> u64 {
        self.inner.cid
    }

    /// Returns true if passwordless
    pub fn is_transient(&self) -> bool {
        self.inner.is_transient
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Debug for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CNAC | CID: {}", self.inner.cid)
    }
}

impl<R: Ratchet, Fcm: Ratchet> std::fmt::Display for ClientNetworkAccount<R, Fcm> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{}\t\t{}\t\t{}\t\t{}",
            self.inner.cid,
            self.inner.auth_store.username(),
            self.inner.auth_store.full_name(),
            self.inner.is_personal
        )
    }
}

impl<R: Ratchet, Fcm: Ratchet> Clone for ClientNetworkAccount<R, Fcm> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
