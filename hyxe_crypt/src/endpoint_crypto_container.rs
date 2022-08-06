#![allow(missing_docs)]

use crate::misc::CryptError;
use crate::prelude::SecurityLevel;
use crate::stacked_ratchet::constructor::{AliceToBobTransferType, BobToAliceTransferType};
use crate::stacked_ratchet::{Ratchet, StackedRatchet};
use crate::toolset::{Toolset, UpdateStatus};
use ez_pqcrypto::algorithm_dictionary::CryptoParameters;
use ez_pqcrypto::constructor_opts::ConstructorOpts;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A container that holds the toolset as well as some boolean flags to ensure validity
/// in tight concurrency situations. It is up to the networking protocol to ensure
/// that the inner functions are called when appropriate
#[derive(Serialize, Deserialize)]
pub struct PeerSessionCrypto<R: Ratchet = StackedRatchet> {
    #[serde(bound = "")]
    pub toolset: Toolset<R>,
    pub update_in_progress: Arc<AtomicBool>,
    // if local is initiator, then in the case both nodes send a FastMessage at the same time (causing an update to the keys), the initiator takes preference, and the non-initiator's upgrade attempt gets dropped (if update_in_progress)
    pub local_is_initiator: bool,
    pub rolling_object_id: u32,
    pub rolling_group_id: u64,
    pub lock_set_by_alice: Option<bool>,
    /// Alice sends to Bob, then bob updates internally the toolset. However. Bob can't send packets to Alice quite yet using that newest version. He must first wait from Alice to commit on her end and wait for an ACK.
    /// If alice sends a packet using the latest version, that's okay since we already have that drill version on Bob's side; it's just that Bob can't send packets using the latest version until AFTER receiving the ACK
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
            update_in_progress: Arc::new(AtomicBool::new(false)),
            local_is_initiator,
            rolling_object_id: 1,
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

    /// Gets a specific drill version, or, gets the latest version comitted
    pub fn get_hyper_ratchet(&self, version: Option<u32>) -> Option<&R> {
        self.toolset
            .get_hyper_ratchet(version.unwrap_or(self.latest_usable_version))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    pub fn commit_next_hyper_ratchet_version(
        &mut self,
        mut newest_version: R::Constructor,
        local_cid: u64,
        local_is_alice: bool,
    ) -> Result<(Option<BobToAliceTransferType>, UpdateStatus), ()> {
        let cur_vers = self.toolset.get_most_recent_hyper_ratchet_version();
        let next_vers = cur_vers.wrapping_add(1);
        newest_version.update_version(next_vers).ok_or(())?;

        let transfer = if local_is_alice {
            None
        } else {
            // we don't want to custom CID here
            Some(newest_version.stage0_bob().ok_or(())?)
        };

        let next_hyper_ratchet = newest_version.finish_with_custom_cid(local_cid).ok_or(())?;
        let status = self.toolset.update_from(next_hyper_ratchet).ok_or(())?;
        log::trace!(target: "lusna", "[E2E] Successfully updated StackedRatchet from v{} to v{}", cur_vers, next_vers);
        //self.latest_hyper_ratchet_version_committed = next_vers;

        Ok((transfer, status))
    }

    /// Deregisters the oldest StackedRatchet version. Requires the version input to ensure program/network consistency for debug purposes
    pub fn deregister_oldest_hyper_ratchet(
        &mut self,
        version: u32,
    ) -> Result<(), CryptError<String>> {
        self.toolset.deregister_oldest_hyper_ratchet(version)
    }

    /// Performs an update internally, only if sync conditions allow
    pub fn update_sync_safe(
        &mut self,
        constructor: R::Constructor,
        local_is_alice: bool,
        local_cid: u64,
    ) -> Result<KemTransferStatus, ()> {
        let update_in_progress = self.update_in_progress.load(Ordering::SeqCst);
        log::trace!(target: "lusna", "[E2E] Calling UPDATE (local_is_alice: {}. Update in progress: {})", local_is_alice, update_in_progress);
        // if local is alice (relative), then update_in_progress will be expected to be true. As such, we don't want this to occur
        if update_in_progress && !local_is_alice {
            // update is in progress. We only update if local is NOT the initiator (this implies the packet triggering this was sent by the initiator, which takes the preference as desired)
            // if local is initiator, then the packet was sent by the non-initiator, and as such, we don't update on local
            if self.local_is_initiator {
                return Ok(KemTransferStatus::Omitted);
            }
        }

        // There is one last special possibility. Let's say the initiator spam sends a bunch of FastMessage packets. Since the initiator's local won't have the appropriate proposed version ID
        // we need to ensure that it gets the right version, The crypt container will take care of that for us
        let (transfer, status) =
            self.commit_next_hyper_ratchet_version(constructor, local_cid, local_is_alice)?;

        let ret = if let Some(transfer) = transfer {
            KemTransferStatus::Some(transfer, status)
        } else {
            // if it returns with None, and local isn't alice, return an error since we expected Some
            if !local_is_alice {
                return Err(());
            }

            KemTransferStatus::StatusNoTransfer(status)
        };

        // if ret has some, we need one more thing. If we are upgrading the ratchet here on bob's end, we need to place a lock to ensure to updates come from this end until after a TRUNCATE packet comes
        // if this is alice's end, we don't unlock quite yet
        if !local_is_alice && ret.has_some() {
            self.update_in_progress.store(true, Ordering::SeqCst);
            self.lock_set_by_alice = Some(false);
        }

        Ok(ret)
    }

    /// Unlocks the hold on future updates, then returns the latest hyper_ratchet
    /// Providing "false" will unconditionally unlock the ratchet
    pub fn maybe_unlock(&mut self, requires_locked_by_alice: bool) -> Option<&R> {
        if requires_locked_by_alice {
            if self.lock_set_by_alice.unwrap_or(false) {
                if !self.update_in_progress.fetch_nand(true, Ordering::SeqCst) {
                    log::error!(target: "lusna", "Expected update_in_progress to be true");
                }

                //self.update_in_progress.store(false, Ordering::SeqCst);
                self.lock_set_by_alice = None;
                log::trace!(target: "lusna", "Unlocking for {}", self.toolset.cid);
            }
        } else {
            if !self.update_in_progress.fetch_nand(true, Ordering::SeqCst) {
                log::error!(target: "lusna", "Expected update_in_progress to be true. LSBA: {:?} | Cid: {}", self.lock_set_by_alice, self.toolset.cid);
                //std::process::exit(-1);
            }

            //self.update_in_progress.store(false, Ordering::SeqCst);
            self.lock_set_by_alice = None;
            log::trace!(target: "lusna", "Unlocking for {}", self.toolset.cid);
        }

        self.get_hyper_ratchet(None)
    }

    /// For alice: this should be called ONLY if the update occurred locally. This updates the latest usable version at the endpoint
    /// For bob: this should be called AFTER receiving the TRUNCATE_STATUS/ACK packet
    pub fn post_alice_stage1_or_post_stage1_bob(&mut self) {
        self.latest_usable_version = self.latest_usable_version.wrapping_add(1);
    }

    ///
    pub fn get_and_increment_group_id(&mut self) -> u64 {
        self.rolling_group_id = self.rolling_group_id.wrapping_add(1);
        self.rolling_group_id.wrapping_sub(1)
    }

    ///
    pub fn get_and_increment_object_id(&mut self) -> u32 {
        self.rolling_object_id = self.rolling_object_id.wrapping_add(1);
        self.rolling_object_id.wrapping_sub(1)
    }

    /// Returns a new constructor only if a concurrent update isn't occurring
    /// `force`: If the internal boolean was locked prior to calling this in anticipation, force should be true
    pub fn get_next_constructor(&mut self, force: bool) -> Option<R::Constructor> {
        let set_lock = move |this: &mut Self| {
            this.update_in_progress.store(true, Ordering::SeqCst);
            this.lock_set_by_alice = Some(true);
            this.get_hyper_ratchet(None)?.next_alice_constructor()
        };

        if force {
            return set_lock(self);
        }

        if self.update_in_progress.load(Ordering::SeqCst) {
            None
        } else {
            set_lock(self)
        }
    }

    /// Refreshed the internal state to init state
    pub fn refresh_state(&mut self) {
        self.update_in_progress = Arc::new(AtomicBool::new(false));
        self.lock_set_by_alice = None;
        self.rolling_group_id = 0;
        self.rolling_object_id = 0;
    }

    /// Gets the parameters used at registrations
    pub fn get_default_params(&self) -> CryptoParameters {
        self.toolset
            .get_static_auxiliary_ratchet()
            .message_pqc_drill(None)
            .0
            .params
    }
}

// TODO: Use GAT's to have a type AliceToBobConstructor<'a>. Get rid of these enums
pub trait EndpointRatchetConstructor<R: Ratchet>: Send + Sync + 'static {
    fn new_alice(
        opts: Vec<ConstructorOpts>,
        cid: u64,
        new_version: u32,
        security_level: Option<SecurityLevel>,
    ) -> Option<Self>
    where
        Self: Sized;
    fn new_bob(
        cid: u64,
        new_drill_vers: u32,
        opts: Vec<ConstructorOpts>,
        transfer: AliceToBobTransferType<'_>,
    ) -> Option<Self>
    where
        Self: Sized;
    fn stage0_alice(&self) -> AliceToBobTransferType<'_>;
    fn stage0_bob(&self) -> Option<BobToAliceTransferType>;
    fn stage1_alice(&mut self, transfer: &BobToAliceTransferType) -> Option<()>;

    fn update_version(&mut self, version: u32) -> Option<()>;
    fn finish_with_custom_cid(self, cid: u64) -> Option<R>;
    fn finish(self) -> Option<R>;
}

#[derive(Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum KemTransferStatus {
    StatusNoTransfer(UpdateStatus),
    Empty,
    Omitted,
    Some(BobToAliceTransferType, UpdateStatus),
}

impl KemTransferStatus {
    pub fn requires_truncation(&self) -> Option<u32> {
        match self {
            KemTransferStatus::StatusNoTransfer(UpdateStatus::CommittedNeedsSynchronization {
                old_version,
                ..
            })
            | KemTransferStatus::Some(
                _,
                UpdateStatus::CommittedNeedsSynchronization { old_version, .. },
            ) => Some(*old_version),

            _ => None,
        }
    }

    pub fn omitted(&self) -> bool {
        match self {
            Self::Omitted => true,
            _ => false,
        }
    }

    pub fn has_some(&self) -> bool {
        match self {
            KemTransferStatus::Some(..) => true,
            _ => false,
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use crate::hyper_ratchet::StackedRatchet;
    use crate::hyper_ratchet::constructor::{StackedRatchetConstructor, BobToAliceTransferType};
    use crate::prelude::{ConstructorOpts, Toolset};
    use ez_pqcrypto::algorithm_dictionary::{EncryptionAlgorithm, KemAlgorithm};
    use crate::drill::SecurityLevel;
    use crate::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus};

    fn gen(enx: EncryptionAlgorithm, kem: KemAlgorithm, security_level: SecurityLevel, version: u32, opts: Option<Vec<ConstructorOpts>>) -> (StackedRatchet, StackedRatchet) {
        let opts = opts.unwrap_or_else(||ConstructorOpts::new_vec_init(Some(enx + kem), (security_level.value() + 1) as usize));
        let mut cx_alice = StackedRatchetConstructor::new_alice(opts.clone(), 0, version, Some(security_level));
        let cx_bob = StackedRatchetConstructor::new_bob(0, version, opts, cx_alice.stage0_alice()).unwrap();
        cx_alice.stage1_alice(&BobToAliceTransferType::Default(cx_bob.stage0_bob().unwrap())).unwrap();

        (cx_alice.finish().unwrap(), cx_bob.finish().unwrap())
    }

    #[test]
    fn upgrades() {
        const NUM_UPDATES: usize = 1;
        lusna_logging::setup_log();
        for level in 0..10u8 {
            let level = SecurityLevel::from(level);
            let (hr_alice, hr_bob) = gen(EncryptionAlgorithm::AES_GCM_256_SIV, KemAlgorithm::Firesaber, level, 0, None);
            let mut endpoint_alice = PeerSessionCrypto::new(Toolset::new(0, hr_alice), true);
            let mut endpoint_bob = PeerSessionCrypto::new(Toolset::new(0, hr_bob), false);

            for vers in 1..=NUM_UPDATES {
                // now, upgrade
                let alice_hr_cons = endpoint_alice.get_next_constructor(false).unwrap();
                let transfer = alice_hr_cons.stage0_alice();

                let bob_constructor = StackedRatchetConstructor::new_bob(0, vers as _, )
                match endpoint_bob.update_sync_safe(next_alice_2_bob, false, 0).unwrap() {
                    KemTransferStatus::Some(transfer, status) => {
                        let
                        endpoint_alice.update_sync_safe(transfer.assume_default().unwrap())
                    }
                    _ => panic!("Did not expect this kem status")
                }
            }
        }
    }
}*/
