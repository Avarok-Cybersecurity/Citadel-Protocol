//! # Cryptographic Toolset Management
//!
//! This module provides a management layer for cryptographic ratchets, handling version control,
//! synchronization, and lifecycle management of encryption keys. It maintains a rolling window
//! of active ratchets while ensuring secure key evolution.
//!
//! ## Features
//! - Manages multiple versions of cryptographic ratchets
//! - Provides automatic version control and synchronization
//! - Implements memory-bounded storage with configurable limits
//! - Supports static auxiliary ratchet for persistent encryption
//! - Handles secure ratchet updates and deregistration
//! - Ensures thread-safe access to cryptographic primitives
//!
//! ## Usage Example
//! ```rust
//! use citadel_crypt::toolset::{Toolset, UpdateStatus};
//! use citadel_crypt::stacked_ratchet::StackedRatchet;
//!
//! // Create a new toolset with initial ratchet
//! let cid = 12345;
//! let initial_ratchet = StackedRatchet::new(cid, 0);
//! let mut toolset = Toolset::new(cid, initial_ratchet);
//!
//! // Create and add a new ratchet version
//! let new_ratchet = StackedRatchet::new(cid, 1);
//! match toolset.update_from(new_ratchet) {
//!     Some(UpdateStatus::Committed { new_version }) => {
//!         println!("Updated to version {}", new_version);
//!     }
//!     Some(UpdateStatus::CommittedNeedsSynchronization { new_version, old_version }) => {
//!         println!("Updated to {} but need to sync version {}", new_version, old_version);
//!         // Implement synchronization logic
//!         toolset.deregister_oldest_stacked_ratchet(old_version).unwrap();
//!     }
//!     None => println!("Update failed"),
//! }
//!
//! // Access ratchets
//! if let Some(current) = toolset.get_most_recent_stacked_ratchet() {
//!     // Use current ratchet for encryption
//! }
//! ```
//!
//! ## Important Notes
//! - Maximum number of ratchets in memory is configurable and environment-dependent
//! - Static auxiliary ratchet provides persistent encryption for stored data
//! - Version synchronization is required when maximum capacity is reached
//! - Thread-safe operations for concurrent access
//!
//! ## Related Components
//! - [`StackedRatchet`](crate::ratchets::stacked::stacked_ratchet::StackedRatchet): Core ratchet implementation
//! - [`EntropyBank`](crate::entropy_bank::EntropyBank): Entropy source for ratchets
//! - [`CryptError`](crate::misc::CryptError): Error handling for cryptographic operations
//! - [`ClientNetworkAccount`]: High-level account management

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::misc::CryptError;
use crate::ratchets::stacked::stacked_ratchet::StackedRatchet;
use crate::ratchets::Ratchet;
use std::ops::RangeInclusive;

/// The maximum number of ratchets to store in memory. Note that, most of the time, the true number in memory
/// will be the max - 1, since the max is only reached when the most recent ratchet is added and the toolset
/// is in the state of pending synchronization/truncation
#[cfg(debug_assertions)]
pub const MAX_RATCHETS_IN_MEMORY: usize = 6;
#[cfg(not(debug_assertions))]
pub const MAX_RATCHETS_IN_MEMORY: usize = 128;

/// The reserved version for the static aux ratchet
pub const STATIC_AUX_VERSION: u32 = 0;

/// The [Toolset] is the layer of abstraction between a [ClientNetworkAccount] and the
/// inner hyper ratchets.
#[derive(Serialize, Deserialize)]
pub struct Toolset<R: Ratchet> {
    /// the CID of the owner
    pub cid: u64,
    most_recent_stacked_ratchet_version: u32,
    oldest_stacked_ratchet_version: u32,
    #[serde(bound = "")]
    map: VecDeque<R>,
    /// The static auxiliary entropy_bank was made to cover a unique situation that is consequence of dropping-off the back of the VecDeque upon upgrade:
    /// As the back gets dropped, any data encrypted using that version now becomes undecipherable forever. The solution to this is having a static entropy_bank, but this
    /// does indeed compromise safety. This should NEVER be used for network data transmission (except for first packets), and should only
    /// really be used when encrypting data which is stored under the local filesystem via HyxeFiles. Since a HyxeFile, for example, hides revealing data
    /// with a complex file path, any possible hacker wouldn't necessarily be able to correlate the HyxeFile with the correct CID unless additional work was done.
    /// Local filesystems should be encrypted anyways (otherwise voids warranty), but, having the HyxeFile layer is really just a "weak" layer of protection
    /// designed to derail any currently existing or historical viruses that may look for conventional means of breaking-through data
    #[serde(bound = "")]
    static_auxiliary_stacked_ratchet: R,
}

// This clone should only be called in the middle of a session
impl<R: Ratchet> Clone for Toolset<R> {
    fn clone(&self) -> Self {
        Self {
            cid: self.cid,
            most_recent_stacked_ratchet_version: self.most_recent_stacked_ratchet_version,
            oldest_stacked_ratchet_version: self.oldest_stacked_ratchet_version,
            map: self.map.clone(),
            static_auxiliary_stacked_ratchet: self.static_auxiliary_stacked_ratchet.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
pub enum ToolsetUpdateStatus {
    // new version has been committed, and the number of HRs is still less than the total max. No E2E synchronization required
    Committed {
        new_version: u32,
    },
    // The maximum number of acceptable HR's have been stored in memory, but will not be removed until both endpoints can agree
    // to removing the version
    CommittedNeedsSynchronization {
        new_version: u32,
        oldest_version: u32,
    },
}

impl<R: Ratchet> Toolset<R> {
    /// Creates a new [Toolset]. Designates the `stacked_ratchet` as the static auxiliary ratchet
    /// stacked_ratchet should be version 0
    pub fn new(cid: u64, stacked_ratchet: R) -> Self {
        let mut map = VecDeque::with_capacity(MAX_RATCHETS_IN_MEMORY);
        map.push_front(stacked_ratchet.clone());
        Toolset {
            cid,
            most_recent_stacked_ratchet_version: 0,
            oldest_stacked_ratchet_version: 0,
            map,
            static_auxiliary_stacked_ratchet: stacked_ratchet,
        }
    }

    pub fn new_debug(
        cid: u64,
        stacked_ratchet: R,
        most_recent_stacked_ratchet_version: u32,
        oldest_stacked_ratchet_version: u32,
    ) -> Self {
        let mut map = VecDeque::with_capacity(MAX_RATCHETS_IN_MEMORY);
        map.push_front(stacked_ratchet.clone());
        Toolset {
            cid,
            most_recent_stacked_ratchet_version,
            oldest_stacked_ratchet_version,
            map,
            static_auxiliary_stacked_ratchet: stacked_ratchet,
        }
    }

    /// Updates from an inbound DrillUpdateObject. Returns the new Drill
    pub fn update_from(&mut self, new_stacked_ratchet: R) -> Option<ToolsetUpdateStatus> {
        let latest_hr_version = self.get_most_recent_stacked_ratchet_version();

        if new_stacked_ratchet.get_cid() != self.cid {
            log::error!(target: "citadel", "The supplied hyper ratchet does not belong to the expected CID (expected: {}, obtained: {})", self.cid, new_stacked_ratchet.get_cid());
            return None;
        }

        if latest_hr_version != new_stacked_ratchet.version().wrapping_sub(1) {
            log::error!(target: "citadel", "The supplied hyper ratchet is not precedent to the entropy_bank update object (expected: {}, obtained: {})", latest_hr_version + 1, new_stacked_ratchet.version());
            return None;
        }

        let update_status = self.append_stacked_ratchet(new_stacked_ratchet);
        let cur_version = match &update_status {
            ToolsetUpdateStatus::Committed { new_version }
            | ToolsetUpdateStatus::CommittedNeedsSynchronization { new_version, .. } => {
                *new_version
            }
        };

        self.most_recent_stacked_ratchet_version = cur_version;

        let prev_version = self.most_recent_stacked_ratchet_version.wrapping_sub(1);
        log::trace!(target: "citadel", "[{}] Upgraded {} to {} for cid={}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_RATCHETS_IN_MEMORY, prev_version, cur_version, self.cid, self.get_adjusted_index(cur_version), self.get_adjusted_index(prev_version), self.get_oldest_stacked_ratchet_version(), self.map.len());
        Some(update_status)
    }

    #[allow(unused_results)]
    ///Replacing entropy_banks is not allowed, and is why this subroutine returns an error when a collision is detected
    ///
    /// Returns the new hyper ratchet version
    fn append_stacked_ratchet(&mut self, stacked_ratchet: R) -> ToolsetUpdateStatus {
        //debug_assert!(self.map.len() <= MAX_HYPER_RATCHETS_IN_MEMORY);
        let new_version = stacked_ratchet.version();
        //println!("max hypers: {} @ {} bytes ea", MAX_HYPER_RATCHETS_IN_MEMORY, get_approx_bytes_per_stacked_ratchet());
        self.map.push_front(stacked_ratchet);
        if self.map.len() >= MAX_RATCHETS_IN_MEMORY {
            let oldest_version = self.get_oldest_stacked_ratchet_version();
            log::trace!(target: "citadel", "[Toolset Update] Needs Truncation. Oldest version: {}", oldest_version);
            ToolsetUpdateStatus::CommittedNeedsSynchronization {
                new_version,
                oldest_version,
            }
        } else {
            ToolsetUpdateStatus::Committed { new_version }
        }
    }

    /// When append_stacked_ratchet returns CommittedNeedsSynchronization on Bob's side, Bob should first
    /// send a packet to Alice telling her that capacity has been reached and that version V should be dropped.
    /// Alice will then prevent herself from sending any more packets using version V, and will locally run this
    /// function. Next, Alice should alert Bob telling him that it's now safe to remove version V. Bob then runs
    /// this function last. By doing this, Alice no longer sends packets that may be no longer be valid
    #[allow(unused_results)]
    pub fn deregister_oldest_stacked_ratchet(&mut self, version: u32) -> Result<(), CryptError> {
        if self.map.len() < MAX_RATCHETS_IN_MEMORY {
            return Err(CryptError::RekeyUpdateError(
                "Cannot call for deregistration unless the map len is maxed out".to_string(),
            ));
        }

        let oldest = self.get_oldest_stacked_ratchet_version();
        if oldest != version {
            Err(CryptError::RekeyUpdateError(format!(
                "Unable to deregister. Provided version: {version}, expected version: {oldest}",
            )))
        } else {
            self.map.pop_back().ok_or(CryptError::OutOfBoundsError)?;
            self.oldest_stacked_ratchet_version =
                self.oldest_stacked_ratchet_version.wrapping_add(1);
            log::trace!(target: "citadel", "[Toolset] Deregistered version {} for cid={}. New oldest: {} | LEN: {}", version, self.cid, self.oldest_stacked_ratchet_version, self.len());
            Ok(())
        }
    }

    /// Returns the number of StackedRatchets internally
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns the latest entropy_bank version
    pub fn get_most_recent_stacked_ratchet(&self) -> Option<&R> {
        self.map.front()
    }

    /// Returns the oldest entropy_bank in the VecDeque
    pub fn get_oldest_stacked_ratchet(&self) -> Option<&R> {
        self.map.back()
    }

    /// Gets the oldest entropy_bank version
    pub fn get_oldest_stacked_ratchet_version(&self) -> u32 {
        self.oldest_stacked_ratchet_version
    }

    /// Returns the most recent entropy_bank
    pub fn get_most_recent_stacked_ratchet_version(&self) -> u32 {
        self.most_recent_stacked_ratchet_version
    }

    /// Returns the static auxiliary entropy_bank. There is no "set" function, because this really
    /// shouldn't be changing internally as this is depended upon by datasets which require a fixed encryption
    /// version which would otherwise normally get dropped from the VecDeque semi-actively.
    ///
    /// This panics if the internal map is empty
    ///
    /// The static auxilliary entropy_bank is used for RECOVERY MODE. I.e., if the version are out
    /// of sync, then the static auxiliary entropy_bank is used to obtain the nonce for the AES GCM
    /// mode of encryption
    pub fn get_static_auxiliary_ratchet(&self) -> &R {
        &self.static_auxiliary_stacked_ratchet
    }

    /// The index within the vec deque does not necessarily track the entropy_bank versions.
    /// This function adjusts for that
    #[inline]
    fn get_adjusted_index(&self, version: u32) -> usize {
        self.most_recent_stacked_ratchet_version
            .wrapping_sub(version) as usize
    }

    /// Returns a specific entropy_bank version
    pub fn get_stacked_ratchet(&self, version: u32) -> Option<&R> {
        let idx = self.get_adjusted_index(version);

        let res = self.map.get(idx);
        if res.is_none() {
            log::error!(target: "citadel", "Attempted to get ratchet v{} for cid={}, but does not exist! len: {}. Oldest: {}. Newest: {}", version, self.cid, self.map.len(), self.oldest_stacked_ratchet_version, self.most_recent_stacked_ratchet_version);
        }

        res
    }

    /// Returns a range of entropy_banks. Returns None if any entropy_bank in the range is missing
    pub fn get_stacked_ratchets(&self, versions: RangeInclusive<u32>) -> Option<Vec<&R>> {
        let mut ret = Vec::with_capacity((*versions.end() - *versions.start() + 1) as usize);
        for version in versions {
            if let Some(entropy_bank) = self.get_stacked_ratchet(version) {
                ret.push(entropy_bank);
            } else {
                return None;
            }
        }

        Some(ret)
    }

    /// Serializes the toolset to a buffer
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, CryptError<String>> {
        bincode::serialize(self).map_err(|err| CryptError::RekeyUpdateError(err.to_string()))
    }

    /// Deserializes from a slice of bytes
    pub fn deserialize_from_bytes<T: AsRef<[u8]>>(input: T) -> Result<Self, CryptError<String>> {
        bincode::deserialize(input.as_ref())
            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))
    }

    /// Resets the internal state to the default, if necessary. At the beginning of each session, this should be called
    pub fn verify_init_state(&self) -> Option<()> {
        self.static_auxiliary_stacked_ratchet.reset_ara();
        Some(())
    }
}

/// Makes replacing/synchronizing toolsets easier
/// input: (static_aux_ratchet, f(0))
pub type StaticAuxRatchet = StackedRatchet;
impl<R: Ratchet> From<(R, R)> for Toolset<R> {
    fn from(entropy_bank: (R, R)) -> Self {
        let most_recent_stacked_ratchet_version = entropy_bank.1.version();
        let oldest_stacked_ratchet_version = most_recent_stacked_ratchet_version; // for init, just like in the normal constructor
        let mut map = VecDeque::with_capacity(MAX_RATCHETS_IN_MEMORY);
        map.insert(0, entropy_bank.1);
        Self {
            cid: entropy_bank.0.get_cid(),
            oldest_stacked_ratchet_version,
            most_recent_stacked_ratchet_version,
            map,
            static_auxiliary_stacked_ratchet: entropy_bank.0,
        }
    }
}
