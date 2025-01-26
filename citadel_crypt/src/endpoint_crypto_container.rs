//! Peer Session Cryptographic Container
//!
//! This module provides a thread-safe container for managing cryptographic state
//! between peer sessions. It handles ratchet updates, version management, and
//! concurrent access control for secure peer-to-peer communication.
//!
//! # Features
//!
//! - Thread-safe cryptographic state management
//! - Ratchet version control and updates
//! - Concurrent update conflict resolution
//! - Session key management and rotation
//! - Atomic state transitions
//! - Rolling object and group ID management
//! - Post-quantum cryptography support
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus};
//! use citadel_crypt::toolset::Toolset;
//! use citadel_crypt::ratchets::stacked::StackedRatchet;
//! use citadel_crypt::misc::CryptError;
//!
//! # fn get_ratchet() -> StackedRatchet { todo!() }
//! fn setup_session() -> Result<(), CryptError> {
//!     // Create ratchet
//!     let ratchet = get_ratchet();
//!     let cid = 12345;
//!     // Create toolset with default parameters
//!     let toolset = Toolset::new(cid, ratchet);
//!
//!     // Initialize peer session (as initiator)
//!     let session = PeerSessionCrypto::new(toolset, true);
//!     // Set to "false" for the other peer
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Updates are atomic and thread-safe
//! - Version conflicts resolved by initiator priority
//! - Requires proper lock management
//! - State transitions must be synchronized
//! - Supports multiple ratchet versions
//!
//! # Related Components
//!
//! - [`crate::toolset::Toolset`] - Cryptographic toolset
//! - [`crate::ratchets::stacked::ratchet::StackedRatchet`] - Ratchet implementation
//! - [`crate::misc::CryptError`] - Error handling
//!

#![allow(missing_docs)]

use crate::misc::CryptError;
use crate::ratchets::Ratchet;
use crate::sync_toggle::{CurrentToggleState, SyncToggle};
use crate::toolset::{Toolset, ToolsetUpdateStatus};
use citadel_io::RwLock;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::CryptoParameters;
use citadel_types::prelude::{ObjectId, SecurityLevel};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// A container that holds the toolset as well as some boolean flags to ensure validity
/// in tight concurrency situations. It is up to the networking protocol to ensure
/// that the inner functions are called when appropriate
#[derive(Serialize, Deserialize, Clone)]
pub struct PeerSessionCrypto<R: Ratchet> {
    #[serde(bound = "")]
    toolset: Arc<RwLock<Toolset<R>>>,
    pub update_in_progress: SyncToggle,
    // if local is initiator, then in the case both nodes send a FastMessage at the same time (causing an update to the keys), the initiator takes preference, and the non-initiator's upgrade attempt gets dropped (if update_in_progress)
    local_is_initiator: bool,
    cid: u64,
    incrementing_group_id_messaging: Arc<AtomicU64>,
    pub incrementing_group_id_file_transfer: Arc<AtomicU64>,
    /// Alice sends to Bob, then bob updates internally the toolset. However. Bob can't send packets to Alice quite yet using that newest version. He must first wait from Alice to commit on her end and wait for an ACK.
    /// If alice sends a packet using the latest version, that's okay since we already have that entropy_bank version on Bob's side; it's just that Bob can't send packets using the latest version until AFTER receiving the ACK
    pub latest_usable_version: Arc<AtomicU32>,
}

const ORDERING: Ordering = Ordering::Relaxed;

impl<R: Ratchet> PeerSessionCrypto<R> {
    /// Creates a new [`PeerSessionCrypto`] instance
    ///
    /// `local_is_initiator`: May also be "local_is_server", or any constant designation used to determine
    /// priority in case of concurrent conflicts
    ///
    /// This should only be called by the RatchetConstructor
    pub fn new(toolset: Toolset<R>, local_is_initiator: bool) -> Self {
        Self {
            cid: toolset.cid,
            toolset: Arc::new(RwLock::new(toolset)),
            update_in_progress: SyncToggle::new(),
            local_is_initiator,
            incrementing_group_id_messaging: Arc::new(AtomicU64::new(0)),
            incrementing_group_id_file_transfer: Arc::new(AtomicU64::new(0)),
            latest_usable_version: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Gets a specific entropy_bank version, or, gets the latest version committed
    pub fn get_ratchet(&self, version: Option<u32>) -> Option<R> {
        self.toolset
            .read()
            .get_ratchet(version.unwrap_or_else(|| self.latest_usable_version.load(ORDERING)))
            .cloned()
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    #[allow(clippy::type_complexity)]
    pub fn commit_next_ratchet_version(
        &self,
        mut newest_version: R::Constructor,
        local_cid: u64,
        generate_next: bool,
    ) -> Result<
        (
            Option<<R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer>,
            ToolsetUpdateStatus,
        ),
        CryptError,
    > {
        let mut toolset = self.toolset.write();
        let cur_vers = toolset.get_most_recent_ratchet_version();
        let next_vers = cur_vers.wrapping_add(1);

        // Update version before any stage operations
        newest_version.update_version(next_vers).ok_or_else(|| {
            CryptError::RekeyUpdateError("Unable to progress past update_version".to_string())
        })?;

        if !generate_next {
            let latest_ratchet = newest_version
                .finish_with_custom_cid(local_cid)
                .ok_or_else(|| {
                    CryptError::RekeyUpdateError(
                        "Unable to progress past finish_with_custom_cid for bob-to-alice trigger"
                            .to_string(),
                    )
                })?;
            let status = toolset.update_from(latest_ratchet).ok_or_else(|| {
                CryptError::RekeyUpdateError(
                    "Unable to progress past update_from for bob-to-alice trigger".to_string(),
                )
            })?;

            return Ok((None, status));
        }

        // Generate transfer after version update
        let transfer = newest_version.stage0_bob().ok_or_else(|| {
            CryptError::RekeyUpdateError("Unable to progress past stage0_bob".to_string())
        })?;

        let next_ratchet = newest_version
            .finish_with_custom_cid(local_cid)
            .ok_or_else(|| {
                CryptError::RekeyUpdateError(
                    "Unable to progress past finish_with_custom_cid".to_string(),
                )
            })?;
        let status = toolset.update_from(next_ratchet).ok_or_else(|| {
            CryptError::RekeyUpdateError("Unable to progress past update_from".to_string())
        })?;
        log::trace!(target: "citadel", "[E2E] Client {local_cid} successfully updated Ratchet from v{cur_vers} to v{next_vers}");

        Ok((Some(transfer), status))
    }

    /// Deregisters the oldest StackedRatchet version. Requires the version input to ensure program/network consistency for debug purposes
    pub fn deregister_oldest_ratchet(&self, version: u32) -> Result<(), CryptError<String>> {
        self.toolset.write().deregister_oldest_ratchet(version)
    }

    /// Performs an update internally, only if sync conditions allow
    pub fn update_sync_safe(
        &self,
        constructor: R::Constructor,
        triggered_by_bob_to_alice_transfer: bool,
    ) -> Result<KemTransferStatus<R>, CryptError> {
        let local_cid = self.cid;
        let update_in_progress =
            self.update_in_progress.toggle_on_if_untoggled() == CurrentToggleState::AlreadyToggled;

        log::trace!(target: "citadel", "[E2E] Calling UPDATE (triggered by bob_to_alice tx: {triggered_by_bob_to_alice_transfer}. Update in progress: {update_in_progress})");

        if update_in_progress && !triggered_by_bob_to_alice_transfer {
            // update is in progress. We only update if local is NOT the initiator (this implies the packet triggering this was sent by the initiator, which takes the preference as desired)
            // if local is initiator, then the packet was sent by the non-initiator, and as such, we don't update on local
            if !self.local_is_initiator {
                return Ok(KemTransferStatus::Contended);
            }
        }

        // There is one last special possibility. Let's say the initiator spam sends a bunch of FastMessage packets. Since the initiator's local won't have the appropriate proposed version ID
        // we need to ensure that it gets the right version, The crypt container will take care of that for us
        let result = self.commit_next_ratchet_version(
            constructor,
            local_cid,
            !triggered_by_bob_to_alice_transfer,
        );

        if let Err(err) = &result {
            log::error!(target: "citadel", "[E2E] Error during update: {:?}", err);
            self.update_in_progress.toggle_off();
        }

        let (transfer, status) = result?;

        if let Some(transfer) = transfer {
            Ok(KemTransferStatus::Some(transfer, status))
        } else {
            // if it returns with None, and this wasn't triggered by a bob to alice tx return an error since we expected Some
            if !triggered_by_bob_to_alice_transfer {
                return Err(CryptError::RekeyUpdateError(
                    "This should only be reached if triggered by a bob-to-alice transfer event, yet, conflicting program state".to_string(),
                ));
            }

            Ok(KemTransferStatus::StatusNoTransfer(status))
        }
    }

    /// Unlocks the hold on future updates, then returns the latest ratchet
    pub fn maybe_unlock(&self) -> Option<R> {
        if self.update_in_progress.reset_and_get_previous() != CurrentToggleState::AlreadyToggled {
            log::error!(target: "citadel", "Client {} expected update_in_progress to be true", self.cid);
            return None;
        }

        log::trace!(target: "citadel", "Unlocking for {}", self.cid);

        self.get_ratchet(None)
    }

    /// For alice: this should be called ONLY if the update occurred locally. This updates the latest usable version at the endpoint
    /// For bob: this should be called AFTER receiving the TRUNCATE_STATUS/ACK packet
    pub fn post_alice_stage1_or_post_stage1_bob(&self) {
        log::trace!(target: "citadel", "post_alice_stage1_or_post_stage1_bob for {}: Upgrading from {} to {}", self.cid, self.latest_usable_version(), self.latest_usable_version().wrapping_add(1));
        let _ = self.latest_usable_version.fetch_add(1, ORDERING);
    }

    pub fn get_and_increment_group_id(&self) -> u64 {
        self.incrementing_group_id_messaging.fetch_add(1, ORDERING)
    }

    pub fn get_and_increment_group_file_transfer(&self) -> u64 {
        self.incrementing_group_id_file_transfer
            .fetch_add(1, ORDERING)
    }

    pub fn get_next_object_id(&self) -> ObjectId {
        Uuid::new_v4().as_u128().into()
    }

    pub fn get_next_constructor(&self) -> Option<R::Constructor> {
        if self.update_in_progress.toggle_on_if_untoggled() == CurrentToggleState::JustToggled {
            self.get_ratchet(None)?.next_alice_constructor()
        } else {
            None
        }
    }

    /// Refreshed the internal state to init state
    pub fn refresh_state(&self) {
        self.update_in_progress.toggle_off();
        self.incrementing_group_id_messaging.store(0, ORDERING);
        self.incrementing_group_id_file_transfer.store(0, ORDERING);
    }

    /// Gets the parameters used at registrations
    pub fn get_default_params(&self) -> CryptoParameters {
        self.toolset
            .read()
            .get_static_auxiliary_ratchet()
            .get_message_pqc_and_entropy_bank_at_layer(None)
            .expect("Expected to get message pqc and entropy bank")
            .0
            .params
    }

    pub fn local_is_initiator(&self) -> bool {
        self.local_is_initiator
    }

    pub fn latest_usable_version(&self) -> u32 {
        self.latest_usable_version.load(ORDERING)
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    pub fn toolset(&self) -> &Arc<RwLock<Toolset<R>>> {
        &self.toolset
    }
}

pub trait AssociatedSecurityLevel {
    fn security_level(&self) -> SecurityLevel;
}

pub trait AssociatedCryptoParams {
    fn crypto_params(&self) -> CryptoParameters;
}

pub trait EndpointRatchetConstructor<R: Ratchet>: Debug + Send + Sync + 'static {
    type AliceToBobWireTransfer: Send
        + Sync
        + Serialize
        + DeserializeOwned
        + AssociatedSecurityLevel
        + AssociatedCryptoParams;
    type BobToAliceWireTransfer: Send
        + Sync
        + Serialize
        + DeserializeOwned
        + AssociatedSecurityLevel;
    fn new_alice(opts: Vec<ConstructorOpts>, cid: u64, new_version: u32) -> Option<Self>
    where
        Self: Sized;
    fn new_bob<T: AsRef<[u8]>>(
        cid: u64,
        opts: Vec<ConstructorOpts>,
        transfer: Self::AliceToBobWireTransfer,
        psks: &[T],
    ) -> Option<Self>
    where
        Self: Sized;
    fn stage0_alice(&self) -> Option<Self::AliceToBobWireTransfer>;
    fn stage0_bob(&mut self) -> Option<Self::BobToAliceWireTransfer>;
    fn stage1_alice<T: AsRef<[u8]>>(
        &mut self,
        transfer: Self::BobToAliceWireTransfer,
        psks: &[T],
    ) -> Result<(), CryptError>;

    fn update_version(&mut self, version: u32) -> Option<()>;
    fn finish_with_custom_cid(self, cid: u64) -> Option<R>;
    fn finish(self) -> Option<R>;
}

#[derive(Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum KemTransferStatus<R: Ratchet> {
    StatusNoTransfer(ToolsetUpdateStatus),
    Empty,
    Contended,
    #[serde(bound = "")]
    Some(
        <R::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
        ToolsetUpdateStatus,
    ),
}

impl<R: Ratchet> Debug for KemTransferStatus<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemTransferStatus::StatusNoTransfer(status) => {
                write!(f, "KemTransferStatus::StatusNoTransfer({:?})", status)
            }
            KemTransferStatus::Empty => write!(f, "KemTransferStatus::Empty"),
            KemTransferStatus::Contended => write!(f, "KemTransferStatus::Contended"),
            KemTransferStatus::Some(_, status) => {
                write!(f, "KemTransferStatus::Some(transfer, {status:?})")
            }
        }
    }
}

impl<R: Ratchet> KemTransferStatus<R> {
    pub fn requires_truncation(&self) -> Option<u32> {
        match self {
            KemTransferStatus::StatusNoTransfer(
                ToolsetUpdateStatus::CommittedNeedsSynchronization {
                    oldest_version: old_version,
                    ..
                },
            )
            | KemTransferStatus::Some(
                _,
                ToolsetUpdateStatus::CommittedNeedsSynchronization {
                    oldest_version: old_version,
                    ..
                },
            ) => Some(*old_version),

            _ => None,
        }
    }

    pub fn omitted(&self) -> bool {
        matches!(self, Self::Contended)
    }

    pub fn has_some(&self) -> bool {
        matches!(self, KemTransferStatus::Some(..))
    }
}
