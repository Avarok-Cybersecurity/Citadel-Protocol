#![allow(missing_docs)]

use crate::toolset::{Toolset, UpdateStatus};
use crate::hyper_ratchet::{HyperRatchet, Ratchet};
use crate::hyper_ratchet::constructor::{AliceToBobTransferType, BobToAliceTransferType};
use crate::misc::CryptError;
use serde::{Serialize, Deserialize};
use crate::prelude::SecurityLevel;
use crate::fcm::keys::FcmKeys;

/// A container that holds the toolset as well as some boolean flags to ensure validity
/// in tight concurrency situations. It is up to the networking protocol to ensure
/// that the inner functions are called when appropriate
#[derive(Serialize, Deserialize)]
pub struct PeerSessionCrypto<R: Ratchet = HyperRatchet> {
    #[serde(bound = "")]
    pub toolset: Toolset<R>,
    pub fcm_keys: Option<FcmKeys>,
    #[serde(skip)]
    pub update_in_progress: bool,
    // if local is initiator, then in the case both nodes send a FastMessage at the same time (causing an update to the keys), the initiator takes preference, and the non-initiator's upgrade attempt gets dropped (if update_in_progress)
    pub local_is_initiator: bool,
    pub rolling_object_id: u32,
    pub rolling_group_id: u64
}

impl<R: Ratchet> PeerSessionCrypto<R> {
    /// Creates a new [PeerSessionCrypto] instance
    ///
    /// `local_is_initiator`: May also be "local_is_server", or any constant designation used to determine
    /// priority in case of concurrent conflicts
    pub fn new(toolset: Toolset<R>, local_is_initiator: bool) -> Self {
        Self { toolset, update_in_progress: false, local_is_initiator, rolling_object_id: 1, rolling_group_id: 0, fcm_keys: None }
    }

    pub fn new_fcm(toolset: Toolset<R>, local_is_initiator: bool, fcm_keys: FcmKeys) -> Self {
        Self { toolset, update_in_progress: false, local_is_initiator, rolling_object_id: 1, rolling_group_id: 0, fcm_keys: Some(fcm_keys) }
    }

    /// Gets a specific drill version, or, gets the latest version comitted
    pub fn get_hyper_ratchet(&self, version: Option<u32>) -> Option<&R> {
        self.toolset.get_hyper_ratchet(version.unwrap_or(self.toolset.get_most_recent_hyper_ratchet_version()))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    pub fn commit_next_hyper_ratchet_version(&mut self, mut newest_version: R::Constructor, local_cid: u64, local_is_alice: bool) -> Result<(Option<BobToAliceTransferType>, UpdateStatus), ()> {
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
        log::info!("[E2E] Successfully updated HyperRatchet from v{} to v{}", cur_vers, next_vers);
        //self.latest_hyper_ratchet_version_committed = next_vers;

        Ok((transfer, status))
    }

    /// Deregisters the oldest HyperRatchet version. Requires the version input to ensure program/network consistency for debug purposes
    pub fn deregister_oldest_hyper_ratchet(&mut self, version: u32) -> Result<(), CryptError<String>> {
        self.toolset.deregister_oldest_hyper_ratchet(version)
    }

    /// Performs an update internally, only if sync conditions allow
    pub fn update_sync_safe(&mut self, constructor: R::Constructor, local_is_alice: bool, local_cid: u64) -> Result<KemTransferStatus, ()> {
        log::info!("[E2E] Calling UPDATE (local_is_alice: {}. Update in progress: {})", local_is_alice, self.update_in_progress);
        // if local is alice (relative), then update_in_progress will be expected to be true. As such, we don't want this to occur
        if self.update_in_progress && !local_is_alice {
            // update is in progress. We only update if local is NOT the initiator (this implies the packet triggering this was sent by the initiator, which takes the preference as desired)
            // if local is initiator, then the packet was sent by the non-initiator, and as such, we don't update on local
            if self.local_is_initiator {
                return Ok(KemTransferStatus::Omitted);
            }
        }

        // There is one last special possibility. Let's say the initiator spam sends a bunch of FastMessage packets. Since the initiator's local won't have the appropriate proposed version ID
        // we need to ensure that it gets the right version, The crypt container will take care of that for us
        let (transfer, status) = self.commit_next_hyper_ratchet_version(constructor, local_cid, local_is_alice)?;

        let ret = if let Some(transfer) = transfer {
            KemTransferStatus::Some(transfer, status)
        } else {
            // if it returns with None, and local isn't alice, return an error since we expected Some
            if !local_is_alice {
                return Err(());
            }

            KemTransferStatus::StatusNoTransfer(status)
        };

        Ok(ret)
    }

    /// Unlocks the hold on future updates, then returns the latest hyper_ratchet
    pub fn unlock(&mut self) -> Option<&R> {
        self.update_in_progress = false;
        self.get_hyper_ratchet(None)
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

    /// Returns a new constructor only if a concurrent update isn't occuring
    pub fn get_next_constructor(&mut self, algorithm: Option<u8>) -> Option<R::Constructor> {
        if self.update_in_progress {
            None
        } else {
            self.update_in_progress = true;
            Some(self.get_hyper_ratchet(None)?.next_alice_constructor(algorithm))
        }
    }
}

// TODO: Use GAT's to have a type AliceToBobConstructor<'a>. Get rid of these enums
pub trait EndpointRatchetConstructor<R: Ratchet>: Send + Sync + 'static {
    fn new_alice(algorithm: Option<u8>, cid: u64, new_version: u32, security_level: Option<SecurityLevel>) -> Self where Self: Sized;
    fn new_bob(algorithm: u8, cid: u64, new_drill_vers: u32, transfer: AliceToBobTransferType<'_>) -> Option<Self> where Self: Sized;
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
    Some(BobToAliceTransferType, UpdateStatus)
}

impl KemTransferStatus {
    pub fn requires_truncation(&self) -> Option<u32> {
        match self {
            KemTransferStatus::StatusNoTransfer(UpdateStatus::CommittedNeedsSynchronization { old_version, ..}) | KemTransferStatus::Some(_, UpdateStatus::CommittedNeedsSynchronization { old_version, ..}) => {
                Some(*old_version)
            }

            _ =>  None
        }
    }
}