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
    /// The next version that has been declared/reserved for an in-flight rekey.
    /// This is incremented when a rekey starts (before semaphore release) to ensure
    /// sequential version targeting even with wait_for_completion=false.
    declared_next_version: Arc<AtomicU32>,
}

const ORDERING: Ordering = Ordering::SeqCst;

impl<R: Ratchet> PeerSessionCrypto<R> {
    /// Creates a new [`PeerSessionCrypto`] instance
    ///
    /// `local_is_initiator`: May also be "local_is_server", or any constant designation used to determine
    /// priority in case of concurrent conflicts
    ///
    /// This should only be called by the RatchetConstructor
    pub fn new(toolset: Toolset<R>, local_is_initiator: bool) -> Self {
        let current_version = toolset.get_most_recent_ratchet_version();
        Self {
            cid: toolset.cid,
            toolset: Arc::new(RwLock::new(toolset)),
            update_in_progress: SyncToggle::new(),
            local_is_initiator,
            incrementing_group_id_messaging: Arc::new(AtomicU64::new(0)),
            incrementing_group_id_file_transfer: Arc::new(AtomicU64::new(0)),
            latest_usable_version: Arc::new(AtomicU32::new(current_version)),
            declared_next_version: Arc::new(AtomicU32::new(current_version)),
        }
    }

    /*
    /// Gets a specific entropy_bank version, or, gets the latest version committed
    pub fn get_ratchet(&self, version: Option<u32>) -> Option<R> {
        self.toolset
            .read()
            .get_ratchet(version.unwrap_or_else(|| self.latest_usable_version.load(ORDERING)))
            .cloned()
    }*/

    // Retrieves a ratchet atomically
    pub fn get_ratchet(&self, version: Option<u32>) -> Option<R> {
        let read = self.toolset.read();

        let target_version = version.unwrap_or_else(|| {
            // Use Acquire ordering to ensure we see the latest version
            let latest_version = self.latest_usable_version.load(ORDERING);
            if read.get_ratchet(latest_version).is_none() {
                latest_version.saturating_sub(1)
            } else {
                latest_version
            }
        });

        read.get_ratchet(target_version).cloned()
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    ///
    /// @human-review: Lock windows minimized. Heavy constructor ops (stage0_bob/finish) are computed outside any write lock; only short
    /// update_from commits are performed under a write lock. If calling from an async context on multi-threaded builds, consider offloading
    /// to tokio::task::spawn_blocking before invoking, to avoid blocking the runtime.
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
        log::info!(target: "citadel", "[CBD-CNRV-1] Client {} commit_next_ratchet_version entry, generate_next={}", local_cid, generate_next);
        // Minimize lock scope: read current version under read lock, compute outside, then commit under short write lock
        let cur_vers = self.toolset.read().get_most_recent_ratchet_version();
        let next_vers = cur_vers.wrapping_add(1);
        log::info!(target: "citadel", "[CBD-CNRV-2] Client {} cur_vers={}, next_vers={}", local_cid, cur_vers, next_vers);

        // Update version before any stage operations
        log::info!(target: "citadel", "[CBD-CNRV-2a] Client {} calling update_version({})", local_cid, next_vers);
        newest_version.update_version(next_vers).ok_or_else(|| {
            log::error!(target: "citadel", "[CBD-CNRV-2a-ERR] Client {} update_version({}) returned None!", local_cid, next_vers);
            CryptError::RekeyUpdateError("Unable to progress past update_version".to_string())
        })?;
        log::info!(target: "citadel", "[CBD-CNRV-2b] Client {} update_version({}) complete", local_cid, next_vers);

        if !generate_next {
            // Heavy: finish constructor — synchronous compute outside lock; callers should offload if needed
            log::info!(target: "citadel", "[CBD-CNRV-ALICE-1] Client {} calling finish_with_custom_cid (Alice path)", local_cid);
            let latest_ratchet = newest_version
                .finish_with_custom_cid(local_cid)
                .ok_or_else(|| {
                    log::error!(target: "citadel", "[CBD-CNRV-ALICE-ERR1] Client {} finish_with_custom_cid returned None!", local_cid);
                    CryptError::RekeyUpdateError(
                        "Unable to progress past finish_with_custom_cid for bob-to-alice trigger"
                            .to_string(),
                    )
                })?;
            let ratchet_version = latest_ratchet.version();
            log::info!(target: "citadel", "[CBD-CNRV-ALICE-2] Client {} finish_with_custom_cid complete (ratchet_v={}), acquiring write lock", local_cid, ratchet_version);

            // Commit with short write lock
            let status = {
                let mut toolset = self.toolset.write();
                let current_toolset_version = toolset.get_most_recent_ratchet_version();
                log::info!(target: "citadel", "[CBD-CNRV-ALICE-3] Client {} write lock acquired, toolset_v={}, ratchet_v={}", local_cid, current_toolset_version, ratchet_version);
                toolset.update_from(latest_ratchet).ok_or_else(|| {
                    log::error!(target: "citadel", "[CBD-CNRV-ALICE-ERR2] Client {} update_from returned None! toolset_v={}, expected_v={}", local_cid, current_toolset_version, ratchet_version);
                    CryptError::RekeyUpdateError(
                        "Unable to progress past update_from for bob-to-alice trigger".to_string(),
                    )
                })?
            };
            let final_version = self.toolset.read().get_most_recent_ratchet_version();
            log::info!(target: "citadel", "[CBD-CNRV-ALICE-4] Client {} Alice path complete, toolset_v={}", local_cid, final_version);

            return Ok((None, status));
        }

        // Heavy: stage0_bob + finish — synchronous compute outside lock; callers should offload if needed
        log::info!(target: "citadel", "[CBD-CNRV-3] Client {} calling stage0_bob", local_cid);
        let transfer = newest_version.stage0_bob().ok_or_else(|| {
            CryptError::RekeyUpdateError("Unable to progress past stage0_bob".to_string())
        })?;
        log::info!(target: "citadel", "[CBD-CNRV-4] Client {} stage0_bob complete, calling finish_with_custom_cid", local_cid);

        let next_ratchet = newest_version
            .finish_with_custom_cid(local_cid)
            .ok_or_else(|| {
                CryptError::RekeyUpdateError(
                    "Unable to progress past finish_with_custom_cid".to_string(),
                )
            })?;
        log::info!(target: "citadel", "[CBD-CNRV-5] Client {} finish_with_custom_cid complete, acquiring write lock", local_cid);

        // Short commit under write lock
        let status = {
            let mut toolset = self.toolset.write();
            log::info!(target: "citadel", "[CBD-CNRV-6] Client {} write lock acquired, calling update_from", local_cid);
            toolset.update_from(next_ratchet).ok_or_else(|| {
                CryptError::RekeyUpdateError("Unable to progress past update_from".to_string())
            })?
        };
        log::info!(target: "citadel", "[CBD-CNRV-7] Client {} successfully updated Ratchet from v{cur_vers} to v{next_vers}", local_cid);

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
        log::info!(target: "citadel", "[CBD-USS-1] Client {} update_sync_safe entry, triggered_by_bob={}", local_cid, triggered_by_bob_to_alice_transfer);
        let update_in_progress =
            self.update_in_progress.toggle_on_if_untoggled() == CurrentToggleState::AlreadyToggled;

        log::info!(target: "citadel", "[CBD-USS-2] Client {} update_in_progress={}, local_is_initiator={}", local_cid, update_in_progress, self.local_is_initiator);

        if update_in_progress && !triggered_by_bob_to_alice_transfer {
            // update is in progress. We only update if local is NOT the initiator (this implies the packet triggering this was sent by the initiator, which takes the preference as desired)
            // if local is initiator, then the packet was sent by the non-initiator, and as such, we don't update on local
            if !self.local_is_initiator {
                log::info!(target: "citadel", "[CBD-USS-3] Client {} returning Contended (update in progress, not initiator)", local_cid);
                return Ok(KemTransferStatus::Contended);
            }
        }

        // There is one last special possibility. Let's say the initiator spam sends a bunch of FastMessage packets. Since the initiator's local won't have the appropriate proposed version ID
        // we need to ensure that it gets the right version, The crypt container will take care of that for us
        log::info!(target: "citadel", "[CBD-USS-4] Client {} calling commit_next_ratchet_version", local_cid);
        let result = self.commit_next_ratchet_version(
            constructor,
            local_cid,
            !triggered_by_bob_to_alice_transfer,
        );

        if let Err(err) = &result {
            log::error!(target: "citadel", "[CBD-USS-ERR] Client {} error during update: {err:?}", local_cid);
            self.update_in_progress.toggle_off();
        }
        log::info!(target: "citadel", "[CBD-USS-5] Client {} commit_next_ratchet_version returned", local_cid);

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
        let from = self.latest_usable_version();
        let to = from.wrapping_add(1);

        // Verify the new ratchet is actually available before incrementing version
        let toolset = self.toolset.read();
        if toolset.get_ratchet(to).is_none() {
            log::error!(target: "citadel", "post_alice_stage1_or_post_stage1_bob for {}: Attempted to upgrade from {} to {} but ratchet {} not found in toolset!", 
                self.cid, from, to, to);
            // Don't increment if the ratchet isn't ready
            return;
        }

        log::trace!(target: "citadel", "post_alice_stage1_or_post_stage1_bob for {}: Upgrading from {} to {} (ratchet verified)", self.cid, from, to);
        let _ = self.latest_usable_version.fetch_add(1, Ordering::Release);
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

    /// Gets the declared next version (for determining rekey target).
    pub fn declared_next_version(&self) -> u32 {
        self.declared_next_version.load(ORDERING)
    }

    /// Declares/reserves the next version for an in-flight rekey.
    /// Returns the newly declared version.
    pub fn declare_next_version(&self) -> u32 {
        self.declared_next_version.fetch_add(1, ORDERING) + 1
    }

    /// Syncs declared version with latest usable version.
    /// Call this when rekey completes successfully.
    /// Always resets declared to latest - this handles contention scenarios where
    /// we declared a higher version but then became Loser and the rekey completed
    /// at a lower version than we declared.
    pub fn sync_declared_version(&self) {
        let latest = self.latest_usable_version.load(ORDERING);
        self.declared_next_version.store(latest, ORDERING);
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
                write!(f, "KemTransferStatus::StatusNoTransfer({status:?})")
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
