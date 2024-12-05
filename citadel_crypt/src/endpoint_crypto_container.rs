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
//! use citadel_crypt::stacked_ratchet::StackedRatchet;
//!
//! fn setup_session() -> Result<(), CryptError> {
//!     // Create toolset with default parameters
//!     let toolset = Toolset::new_with_defaults();
//!     
//!     // Initialize peer session (as initiator)
//!     let mut session = PeerSessionCrypto::new(toolset, true);
//!     
//!     // Get constructor for next update
//!     if let Some(constructor) = session.get_next_constructor(false) {
//!         // Perform update
//!         let status = session.update_sync_safe(
//!             constructor,
//!             true,  // is_alice
//!             1234   // local_cid
//!         )?;
//!         
//!         // Handle transfer status
//!         if status.has_some() {
//!             println!("Update requires transfer");
//!         }
//!     }
//!     
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
//! - [`crate::stacked_ratchet::StackedRatchet`] - Ratchet implementation
//! - [`crate::misc::CryptError`] - Error handling
//!

#![allow(missing_docs)]

use crate::misc::CryptError;
use crate::stacked_ratchet::Ratchet;
use crate::sync_toggle::{CurrentToggleState, SyncToggle};
use crate::toolset::{Toolset, ToolsetUpdateStatus};
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::CryptoParameters;
use citadel_types::prelude::{ObjectId, SecurityLevel};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use uuid::Uuid;

/// A container that holds the toolset as well as some boolean flags to ensure validity
/// in tight concurrency situations. It is up to the networking protocol to ensure
/// that the inner functions are called when appropriate
#[derive(Serialize, Deserialize)]
pub struct PeerSessionCrypto<R: Ratchet> {
    #[serde(bound = "")]
    pub toolset: Toolset<R>,
    pub update_in_progress: SyncToggle,
    // if local is initiator, then in the case both nodes send a FastMessage at the same time (causing an update to the keys), the initiator takes preference, and the non-initiator's upgrade attempt gets dropped (if update_in_progress)
    pub local_is_initiator: bool,
    pub rolling_object_id: ObjectId,
    pub rolling_group_id: u64,
    pub lock_set_by_alice: Option<bool>,
    /// Alice sends to Bob, then bob updates internally the toolset. However. Bob can't send packets to Alice quite yet using that newest version. He must first wait from Alice to commit on her end and wait for an ACK.
    /// If alice sends a packet using the latest version, that's okay since we already have that entropy_bank version on Bob's side; it's just that Bob can't send packets using the latest version until AFTER receiving the ACK
    pub latest_usable_version: u32,
}

impl<R: Ratchet> PeerSessionCrypto<R> {
    /// Creates a new [PeerSessionCrypto] instance
    ///
    /// `local_is_initiator`: May also be "local_is_server", or any constant designation used to determine
    /// priority in case of concurrent conflicts
    pub fn new(toolset: Toolset<R>, local_is_initiator: bool) -> Self {
        Self {
            toolset,
            update_in_progress: SyncToggle::new(),
            local_is_initiator,
            rolling_object_id: ObjectId::random(),
            rolling_group_id: 0,
            lock_set_by_alice: None,
            latest_usable_version: 0,
        }
    }

    /// Derives a new version of self safe to be used in the protocol
    /// Changes made to the returned version will not persist
    pub fn new_session(&self) -> Self {
        Self {
            toolset: self.toolset.clone(),
            update_in_progress: self.update_in_progress.clone(),
            local_is_initiator: self.local_is_initiator,
            rolling_object_id: self.rolling_object_id,
            rolling_group_id: self.rolling_group_id,
            lock_set_by_alice: self.lock_set_by_alice,
            latest_usable_version: self.latest_usable_version,
        }
    }

    /// Gets a specific entropy_bank version, or, gets the latest version committed
    pub fn get_ratchet(&self, version: Option<u32>) -> Option<&R> {
        self.toolset
            .get_stacked_ratchet(version.unwrap_or(self.latest_usable_version))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    #[allow(clippy::type_complexity)]
    pub fn commit_next_stacked_ratchet_version(
        &mut self,
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
        let cur_vers = self.toolset.get_most_recent_stacked_ratchet_version();
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
            let status = self.toolset.update_from(latest_ratchet).ok_or_else(|| {
                CryptError::RekeyUpdateError(
                    "Unable to progress past update_from for bob-to-alice trigger".to_string(),
                )
            })?;

            return Ok((None, status));
        }

        /*
        let transfer = if local_is_alice {
            None
        } else {
            // Generate transfer after version update
            let transfer = newest_version.stage0_bob().ok_or_else(|| {
                CryptError::RekeyUpdateError("Unable to progress past stage0_bob".to_string())
            })?;
            Some(transfer)
        };*/

        // Generate transfer after version update
        let transfer = newest_version.stage0_bob().ok_or_else(|| {
            CryptError::RekeyUpdateError("Unable to progress past stage0_bob".to_string())
        })?;

        let next_stacked_ratchet = newest_version
            .finish_with_custom_cid(local_cid)
            .ok_or_else(|| {
                CryptError::RekeyUpdateError(
                    "Unable to progress past finish_with_custom_cid".to_string(),
                )
            })?;
        let status = self
            .toolset
            .update_from(next_stacked_ratchet)
            .ok_or_else(|| {
                CryptError::RekeyUpdateError("Unable to progress past update_from".to_string())
            })?;
        log::trace!(target: "citadel", "[E2E] Successfully updated StackedRatchet from v{cur_vers} to v{next_vers} for {local_cid}");

        Ok((Some(transfer), status))
    }

    /// Deregisters the oldest StackedRatchet version. Requires the version input to ensure program/network consistency for debug purposes
    pub fn deregister_oldest_stacked_ratchet(
        &mut self,
        version: u32,
    ) -> Result<(), CryptError<String>> {
        self.toolset.deregister_oldest_stacked_ratchet(version)
    }

    /// Performs an update internally, only if sync conditions allow
    pub fn update_sync_safe(
        &mut self,
        constructor: R::Constructor,
        local_is_alice: bool,
        local_cid: u64,
        triggered_by_bob_to_alice_transfer: bool,
    ) -> Result<KemTransferStatus<R>, CryptError> {
        let update_in_progress =
            self.update_in_progress.state() == CurrentToggleState::AlreadyToggled;
        log::trace!(target: "citadel", "[E2E] Calling UPDATE (local_is_alice: {}. Update in progress: {})", local_is_alice, update_in_progress);

        // if local is alice (relative), then update_in_progress will be expected to be true. As such, we don't want an update to occur
        // if local_is_alice is true, and we are updating, that means we are in the middle of a protocol resolution, and we don't want to update
        if update_in_progress && local_is_alice {
            // update is in progress. We only update if local is NOT the initiator (this implies the packet triggering this was sent by the initiator, which takes the preference as desired)
            // if local is initiator, then the packet was sent by the non-initiator, and as such, we don't update on local
            if !self.local_is_initiator {
                return Ok(KemTransferStatus::Contended);
            }
        }

        // There is one last special possibility. Let's say the initiator spam sends a bunch of FastMessage packets. Since the initiator's local won't have the appropriate proposed version ID
        // we need to ensure that it gets the right version, The crypt container will take care of that for us
        let result = self.commit_next_stacked_ratchet_version(
            constructor,
            local_cid,
            !triggered_by_bob_to_alice_transfer,
        );
        if let Err(err) = &result {
            log::error!(target: "citadel", "[E2E] Error during update: {:?}", err);
            self.update_in_progress.toggle_off();
        }

        let (transfer, status) = result?;

        let ret = if let Some(transfer) = transfer {
            KemTransferStatus::Some(transfer, status)
        } else {
            // if it returns with None, and local isn't alice, return an error since we expected Some
            if !triggered_by_bob_to_alice_transfer {
                return Err(CryptError::RekeyUpdateError(
                    "This should only be reached if triggered by a bob-to-alice transfer event, yet, conflicting program state".to_string(),
                ));
            }

            KemTransferStatus::StatusNoTransfer(status)
        };

        // if ret has some, we need one more thing. If we are upgrading the ratchet here on bob's end, we need to place a lock to ensure to updates come from this end until after a TRUNCATE packet comes
        // if this is alice's end, we don't unlock quite yet
        if !local_is_alice && ret.has_some() {
            let _ = self.update_in_progress.toggle_on_if_untoggled();
            self.lock_set_by_alice = Some(false);
        }

        Ok(ret)
    }

    /// Unlocks the hold on future updates, then returns the latest stacked_ratchet
    /// Providing "false" will unconditionally unlock the ratchet
    pub fn maybe_unlock(&mut self, requires_locked_by_alice: bool) -> Option<&R> {
        if requires_locked_by_alice {
            if self.lock_set_by_alice.unwrap_or(false) {
                if self.update_in_progress.reset_and_get_previous()
                    != CurrentToggleState::AlreadyToggled
                {
                    log::error!(target: "citadel", "Expected update_in_progress to be true");
                }

                self.lock_set_by_alice = None;
                log::trace!(target: "citadel", "Unlocking for {}", self.toolset.cid);
            }
        } else {
            if self.update_in_progress.reset_and_get_previous()
                != CurrentToggleState::AlreadyToggled
            {
                log::error!(target: "citadel", "Expected update_in_progress to be true. LSBA: {:?} | Cid: {}", self.lock_set_by_alice, self.toolset.cid);
            }

            self.lock_set_by_alice = None;
            log::trace!(target: "citadel", "Unlocking for {}", self.toolset.cid);
        }

        self.get_ratchet(None)
    }

    /// For alice: this should be called ONLY if the update occurred locally. This updates the latest usable version at the endpoint
    /// For bob: this should be called AFTER receiving the TRUNCATE_STATUS/ACK packet
    pub fn post_alice_stage1_or_post_stage1_bob(&mut self) {
        self.latest_usable_version = self.latest_usable_version.wrapping_add(1);
    }

    pub fn get_and_increment_group_id(&mut self) -> u64 {
        self.rolling_group_id = self.rolling_group_id.wrapping_add(1);
        self.rolling_group_id.wrapping_sub(1)
    }

    pub fn get_next_object_id(&mut self) -> ObjectId {
        Uuid::new_v4().as_u128().into()
    }

    /// Returns a new constructor only if a concurrent update isn't occurring
    /// `force`: If the internal boolean was locked prior to calling this in anticipation, force should be true
    pub fn get_next_constructor(&mut self, force: bool) -> Option<R::Constructor> {
        let next_constructor = move |this: &mut Self| {
            // Only set lock_set_by_alice if we successfully get a constructor
            if let Some(constructor) = this.get_ratchet(None)?.next_alice_constructor() {
                this.lock_set_by_alice = Some(true);
                Some(constructor)
            } else {
                None
            }
        };

        if force {
            return next_constructor(self);
        }

        if self.update_in_progress.toggle_on_if_untoggled() == CurrentToggleState::AlreadyToggled {
            None
        } else {
            next_constructor(self)
        }
    }

    /// Refreshed the internal state to init state
    pub fn refresh_state(&mut self) {
        self.update_in_progress.toggle_off();
        self.lock_set_by_alice = None;
        self.rolling_group_id = 0;
        self.rolling_object_id = ObjectId::random();
    }

    /// Gets the parameters used at registrations
    pub fn get_default_params(&self) -> CryptoParameters {
        self.toolset
            .get_static_auxiliary_ratchet()
            .get_message_pqc_and_entropy_bank_at_layer(None)
            .expect("Expected to get message pqc and entropy bank")
            .0
            .params
    }
}

pub trait AssociatedSecurityLevel {
    fn security_level(&self) -> SecurityLevel;
}

pub trait AssociatedCryptoParams {
    fn crypto_params(&self) -> CryptoParameters;
}

// TODO: Use GAT's to have a type AliceToBobConstructor<'a>. Get rid of these enums
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

#[cfg(test)]
pub(crate) mod no_race {
    use crate::endpoint_crypto_container::{KemTransferStatus, PeerSessionCrypto};
    use crate::prelude::{ConstructorOpts, Toolset};
    use crate::stacked_ratchet::constructor::StackedRatchetConstructor;
    use crate::stacked_ratchet::{Ratchet, StackedRatchet};
    use crate::toolset::{ToolsetUpdateStatus, MAX_RATCHETS_IN_MEMORY};
    use citadel_types::prelude::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

    const ALICE_CID: u64 = 10;
    const BOB_CID: u64 = 20;
    pub const TEST_PSKS: &[&[u8]] = &[b"test_psk_1", b"test_psk_2"];

    fn gen<T: AsRef<[u8]>>(
        version: u32,
        opts: Vec<ConstructorOpts>,
        psks: &[T],
    ) -> (StackedRatchet, StackedRatchet) {
        let mut cx_alice =
            StackedRatchetConstructor::new_alice_constructor(opts.clone(), ALICE_CID, version)
                .unwrap();
        let mut cx_bob = StackedRatchetConstructor::new_bob_constructor(
            BOB_CID,
            version,
            opts,
            cx_alice.stage0_alice().unwrap(),
            psks,
        )
        .unwrap();
        cx_alice
            .stage1_alice(cx_bob.stage0_bob().unwrap(), psks)
            .unwrap();

        (cx_alice.finish().unwrap(), cx_bob.finish().unwrap())
    }

    pub(crate) fn setup_endpoint_containers(
        security_level: SecurityLevel,
        enx: EncryptionAlgorithm,
        kem: KemAlgorithm,
    ) -> (
        PeerSessionCrypto<StackedRatchet>,
        PeerSessionCrypto<StackedRatchet>,
    ) {
        let opts = ConstructorOpts::new_vec_init(Some(enx + kem), security_level);
        let (hr_alice, hr_bob) = gen(START_VERSION, opts, TEST_PSKS);
        assert_eq!(hr_alice.version(), START_VERSION);
        assert_eq!(hr_bob.version(), START_VERSION);
        assert_eq!(hr_alice.get_cid(), ALICE_CID);
        assert_eq!(hr_bob.get_cid(), BOB_CID);
        let alice_container = PeerSessionCrypto::new(Toolset::new(ALICE_CID, hr_alice), true);
        let bob_container = PeerSessionCrypto::new(Toolset::new(BOB_CID, hr_bob), false);
        (alice_container, bob_container)
    }

    const START_VERSION: u32 = 0;

    pub(crate) fn pre_round_assertions<R: Ratchet>(
        alice_container: &PeerSessionCrypto<R>,
        alice_cid: u64,
        bob_container: &PeerSessionCrypto<R>,
        bob_cid: u64,
    ) -> (u32, u32) {
        assert_eq!(
            alice_container.get_ratchet(None).unwrap().get_cid(),
            alice_cid
        );
        assert_eq!(bob_container.get_ratchet(None).unwrap().get_cid(), bob_cid);

        let start_version = alice_container
            .toolset
            .get_most_recent_stacked_ratchet_version();
        let new_version = start_version + 1;
        let new_version_bob = bob_container
            .toolset
            .get_most_recent_stacked_ratchet_version()
            + 1;
        assert_eq!(new_version, new_version_bob);
        (start_version, new_version)
    }

    fn expect_truncation_checks<R: Ratchet>(
        expects_truncation: bool,
        container: &PeerSessionCrypto<R>,
        status: ToolsetUpdateStatus,
        requires_truncation: Option<u32>,
    ) -> Option<u32> {
        if expects_truncation {
            if container.toolset.len() >= MAX_RATCHETS_IN_MEMORY {
                let ToolsetUpdateStatus::CommittedNeedsSynchronization {
                    new_version: _,
                    oldest_version,
                } = status
                else {
                    panic!("Expected ToolsetUpdateStatus::CommittedNeedsSynchronization");
                };
                return Some(oldest_version);
            } else {
                assert!(requires_truncation.is_none());
            }
        }

        None
    }

    /// `expect_truncation` should be set to false if the round is expected to complete without truncation, meaning
    /// there are less than MAX_HYPER_RATCHETS_IN_MEMORY HR's in memory and thus no truncation is needed. Otherwise,
    /// set to true if truncation is expected
    fn run_round_no_race(
        container_0: &mut PeerSessionCrypto<StackedRatchet>,
        container_1: &mut PeerSessionCrypto<StackedRatchet>,
        expect_truncation: bool,
    ) {
        let cid_0 = container_0.toolset.cid;
        let cid_1 = container_1.toolset.cid;

        let (start_version, next_version) =
            pre_round_assertions(container_0, cid_0, container_1, cid_1);

        let mut alice_constructor = container_0.get_next_constructor(false).unwrap();
        let alice_to_bob_transfer = alice_constructor.stage0_alice().unwrap();

        // Bob must generate his next opts recursively to continue ratcheting appropriately
        let next_opts = container_1
            .get_ratchet(None)
            .unwrap()
            .get_next_constructor_opts();

        let bob_constructor = StackedRatchetConstructor::new_bob_constructor(
            cid_1,
            next_version,
            next_opts,
            alice_to_bob_transfer,
            TEST_PSKS,
        )
        .unwrap();

        // Perform update on Bob's side, container_1
        let kem_transfer_status_bob = container_1
            .update_sync_safe(bob_constructor, false, cid_1, true)
            .unwrap();

        let requires_truncation_bob = kem_transfer_status_bob.requires_truncation();

        match kem_transfer_status_bob {
            KemTransferStatus::Some(bob_to_alice_transfer, toolset_status_bob) => {
                if !expect_truncation {
                    assert!(requires_truncation_bob.is_none());
                    assert!(
                        matches!(toolset_status_bob, ToolsetUpdateStatus::Committed { new_version } if new_version == next_version)
                    );
                }

                // In this case, bob expects truncation, but, alice will too, in which case we let alice handle the truncation logic
                let _do_nothing = expect_truncation_checks(
                    expect_truncation,
                    container_1,
                    toolset_status_bob,
                    requires_truncation_bob,
                );

                // Flow in the protocol: primary_group_packet.rs:fn attempt_kem_as_alice_finish
                // alice: stage1_alice
                // alice: update
                // alice: if truncation is required, we call deregister_oldest_stacked_ratchet
                // alice: call post_alice_stage1_or_post_stage1_bob
                // alice: if truncation not required, unlock(requires_locked_by_alice=true) and end, else:
                // alice: send TRUNCATE packet to bob
                // bob: call deregister_oldest_stacked_ratchet on that truncated version in the packet
                // bob: call post_alice_stage1_or_post_stage1_bob
                // bob: call unlock(requires_locked_by_alice=false), providing false since bob is not alice
                // bob: send TRUNCATE_ACK packet to alice
                // alice: call unlock(requires_locked_by_alice=true) and end

                alice_constructor
                    .stage1_alice(bob_to_alice_transfer, TEST_PSKS)
                    .unwrap();

                let kem_transfer_status_alice = container_0
                    .update_sync_safe(alice_constructor, true, cid_0, false)
                    .unwrap();

                let requires_truncation_alice = kem_transfer_status_alice.requires_truncation();

                if !expect_truncation {
                    assert!(requires_truncation_alice.is_none());
                    assert!(matches!(kem_transfer_status_alice,
                        KemTransferStatus::StatusNoTransfer(
                            ToolsetUpdateStatus::Committed {
                                new_version
                            }
                        ) if new_version == next_version
                    ));
                }

                assert_eq!(requires_truncation_alice, requires_truncation_bob, "Asymmetry not allowed:requires_truncation_alice: {requires_truncation_alice:?}, requires_truncation_bob: {requires_truncation_bob:?}");

                // Continue to follow protocol flow

                // If no truncation, we runs some tests and short-circuit here
                if requires_truncation_alice.is_none() {
                    // Test message encryption/decryption. Since post_alice_stage1_or_post_stage1_bob has not yet been called,
                    // the latest usable version should still be the start version
                    ratchet_encrypt_decrypt_test(
                        container_0,
                        cid_0,
                        container_1,
                        cid_1,
                        start_version,
                    );
                    simulate_protocol_resolution_no_truncation(container_0, container_1);

                    assert_eq!(start_version + 1, next_version);

                    // Test message encryption/decryption again. Now that post_alice_stage1_or_post_stage1_bob has been called,
                    // the latest usable version should be the new version
                    ratchet_encrypt_decrypt_test(
                        container_0,
                        cid_0,
                        container_1,
                        cid_1,
                        next_version,
                    );
                    return;
                }

                match kem_transfer_status_alice {
                    KemTransferStatus::StatusNoTransfer(toolset_status_alice) => {
                        if let Some(version_to_truncate) = expect_truncation_checks(
                            expect_truncation,
                            container_0,
                            toolset_status_alice,
                            requires_truncation_alice,
                        ) {
                            container_0
                                .deregister_oldest_stacked_ratchet(version_to_truncate)
                                .unwrap();
                            container_0.post_alice_stage1_or_post_stage1_bob();
                            // Assume alice then sends a TRUNCATE packet to bob, telling him to remove this version
                            // send_to_bob(version_to_truncate);
                            container_1
                                .deregister_oldest_stacked_ratchet(version_to_truncate)
                                .unwrap();
                            container_1.post_alice_stage1_or_post_stage1_bob();
                            let ratchet_bob = container_1.maybe_unlock(false).unwrap();
                            // Assume bob then sends a TRUNCATE_ACK packet to alice, telling her to remove her local lock
                            // send_to_alice(version_to_truncate);
                            let ratchet_alice = container_0.maybe_unlock(true).unwrap();
                            assert_eq!(ratchet_alice.version(), ratchet_bob.version());
                            let expected_version = ratchet_alice.version();
                            ratchet_encrypt_decrypt_test(
                                container_0,
                                cid_0,
                                container_1,
                                cid_1,
                                expected_version,
                            );
                        }
                    }
                    status => {
                        log::warn!(target: "citadel", "KemTransferStatus for Alice is not handled in this test: {status:?}");
                    }
                }
            }
            status => {
                log::warn!(target: "citadel", "KemTransferStatus for Bob is not handled in this test: {status:?}")
            }
        }
    }

    pub(crate) fn ratchet_encrypt_decrypt_test<R: Ratchet>(
        container_0: &PeerSessionCrypto<R>,
        cid_0: u64,
        container_1: &PeerSessionCrypto<R>,
        cid_1: u64,
        expected_version: u32,
    ) {
        let test_message = b"Hello, World!";
        let alice_ratchet = container_0.get_ratchet(None).unwrap();
        assert_eq!(alice_ratchet.version(), expected_version);
        assert_eq!(alice_ratchet.get_cid(), cid_0);
        let encrypted = alice_ratchet.encrypt(test_message).unwrap();

        let bob_ratchet = container_1.get_ratchet(None).unwrap();
        assert_eq!(bob_ratchet.version(), expected_version);
        assert_eq!(bob_ratchet.get_cid(), cid_1);
        let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
        assert_eq!(test_message.to_vec(), decrypted);
    }

    fn simulate_protocol_resolution_no_truncation(
        container_0: &mut PeerSessionCrypto<StackedRatchet>,
        container_1: &mut PeerSessionCrypto<StackedRatchet>,
    ) {
        container_0.post_alice_stage1_or_post_stage1_bob();
        container_1.post_alice_stage1_or_post_stage1_bob();
        let _ = container_0.maybe_unlock(false);
        let _ = container_1.maybe_unlock(false);
    }

    fn endpoint_container_test(
        limit: usize,
        expect_truncation: bool,
        fx: impl for<'a> Fn(
            usize,
            &'a mut PeerSessionCrypto<StackedRatchet>,
            &'a mut PeerSessionCrypto<StackedRatchet>,
        ) -> (
            &'a mut PeerSessionCrypto<StackedRatchet>,
            &'a mut PeerSessionCrypto<StackedRatchet>,
        ),
    ) {
        citadel_logging::setup_log();
        let security_level = SecurityLevel::Standard;

        let (mut alice_container, mut bob_container) = setup_endpoint_containers(
            security_level,
            EncryptionAlgorithm::AES_GCM_256,
            KemAlgorithm::Kyber,
        );

        // Start at 1 since we already have 1 HR in memory per node. We go to the limit of
        // MAX_RATCHETS_IN_MEMORY - 1 since we need to account for the SR's already in memory
        for idx in 1..(limit - 1) {
            let (container_0, container_1) = fx(idx, &mut alice_container, &mut bob_container);
            run_round_no_race(container_0, container_1, expect_truncation);
        }
    }

    /// The next three tests focus on either alice, bob, or alternating between the two
    /// updating the state serially and never in parallel. Additionally, the tests expect
    /// no truncation to occur since the number of SR's in memory is never exceeded
    #[test]
    fn test_endpoint_container_no_truncation_only_alice_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            MAX_RATCHETS_IN_MEMORY,
            false,
            |_, alice_container, bob_container| (alice_container, bob_container),
        );
    }

    #[test]
    fn test_endpoint_container_no_truncation_only_bob_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            MAX_RATCHETS_IN_MEMORY,
            false,
            |_, alice_container, bob_container| (bob_container, alice_container),
        );
    }

    #[test]
    fn test_endpoint_container_no_truncation_alternating_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            MAX_RATCHETS_IN_MEMORY,
            false,
            |idx, alice_container, bob_container| {
                if idx % 2 == 0 {
                    (bob_container, alice_container)
                } else {
                    (alice_container, bob_container)
                }
            },
        );
    }

    /// The next three tests focus on either alice, bob, or alternating between the two
    /// updating the state serially and never in parallel. Unlike the previous three tests,
    /// these tests expect truncation to occur since the number of SR's in memory is exceeded
    const TEST_RATCHET_LIMIT: usize = MAX_RATCHETS_IN_MEMORY + 100;

    #[test]
    fn test_endpoint_container_truncation_only_alice_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            TEST_RATCHET_LIMIT,
            true,
            |_, alice_container, bob_container| (alice_container, bob_container),
        );
    }

    #[test]
    fn test_endpoint_container_truncation_only_bob_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            TEST_RATCHET_LIMIT,
            true,
            |_, alice_container, bob_container| (bob_container, alice_container),
        );
    }

    #[test]
    fn test_endpoint_container_truncation_alternating_no_race() {
        citadel_logging::setup_log();
        endpoint_container_test(
            TEST_RATCHET_LIMIT,
            true,
            |idx, alice_container, bob_container| {
                if idx % 2 == 0 {
                    (bob_container, alice_container)
                } else {
                    (alice_container, bob_container)
                }
            },
        );
    }
}
