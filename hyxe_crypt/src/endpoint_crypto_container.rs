#![allow(missing_docs)]

use crate::toolset::{Toolset, UpdateStatus};
use crate::hyper_ratchet::HyperRatchet;
use crate::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransfer};
use crate::misc::CryptError;
use serde::{Serialize, Deserialize};

/// A container that holds the toolset as well as some boolean flags to ensure validity
/// in tight concurrency situations. It is up to the networking protocol to ensure
/// that the inner functions are called when appropriate
#[derive(Serialize, Deserialize)]
pub struct PeerSessionCrypto {
    pub toolset: Toolset,
    #[serde(skip)]
    pub update_in_progress: bool,
    // if local is initiator, then in the case both nodes send a FastMessage at the same time (causing an update to the keys), the initiator takes preference, and the non-initiator's upgrade attempt gets dropped (if update_in_progress)
    pub local_is_initiator: bool
}

impl PeerSessionCrypto {
    /// Creates a new [PeerSessionCrypto] instance
    ///
    /// `local_is_initiator`: May also be "local_is_server", or any constant designation used to determine
    /// priority in case of concurrent conflicts
    pub fn new(toolset: Toolset, local_is_initiator: bool) -> Self {
        Self { toolset, update_in_progress: false, local_is_initiator }
    }

    /// Gets a specific drill version, or, gets the latest version comitted
    pub fn get_hyper_ratchet(&self, version: Option<u32>) -> Option<&HyperRatchet> {
        self.toolset.get_hyper_ratchet(version.unwrap_or(self.toolset.get_most_recent_hyper_ratchet_version()))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase (will receive transfer), or, when Alice receives confirmation
    /// that the endpoint updated the ratchet (no transfer received, since none needed)
    pub fn commit_next_hyper_ratchet_version(&mut self, mut newest_version: HyperRatchetConstructor, local_cid: u64, local_is_alice: bool) -> Result<(Option<BobToAliceTransfer>, UpdateStatus), ()> {
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
}