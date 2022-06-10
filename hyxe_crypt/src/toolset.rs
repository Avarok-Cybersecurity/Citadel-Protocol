use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::misc::CryptError;
use std::ops::RangeInclusive;
use crate::hyper_ratchet::{Ratchet, HyperRatchet};

/// Returns the max number of drill that can be stored in memory
#[cfg(debug_assertions)]
pub const MAX_HYPER_RATCHETS_IN_MEMORY: usize = 6;
#[cfg(not(debug_assertions))]
pub const MAX_HYPER_RATCHETS_IN_MEMORY: usize = 128;

/// The reserved version for the static aux ratchet
pub const STATIC_AUX_VERSION: u32 = 0;

/// The [Toolset] is the layer of abstraction between a [ClientNetworkAccount] and the
/// inner hyper ratchets.
#[derive(Serialize, Deserialize)]
pub struct Toolset<R: Ratchet> {
    /// the CID of the owner
    pub cid: u64,
    most_recent_hyper_ratchet_version: u32,
    oldest_hyper_ratchet_version: u32,
    #[serde(bound="")]
    map: VecDeque<R>,
    /// The static auxiliary drill was made to cover a unique situation that is consequence of dropping-off the back of the VecDeque upon upgrade:
    /// As the back gets dropped, any data encrypted using that version now becomes undecipherable forever. The solution to this is having a static drill, but this
    /// does indeed compromise safety. This should NEVER be used for network data transmission (except for first packets), and should only
    /// really be used when encrypting data which is stored under the local filesystem via HyxeFiles. Since a HyxeFile, for example, hides revealing data
    /// with a complex file path, any possible hacker wouldn't necessarily be able to correlate the HyxeFile with the correct CID unless additional work was done.
    /// Local filesystems should be encrypted anyways (otherwise voids warranty), but, having the HyxeFile layer is really just a "weak" layer of protection
    /// designed to derail any currently existing or historical viruses that may look for conventional means of breaking-through data
    #[serde(bound="")]
    static_auxiliary_hyper_ratchet: R
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum UpdateStatus {
    // new version has been committed, and the number of HRs is still less than the total max. No E2E synchronization required
    Committed { new_version: u32 },
    // The maximum number of acceptable HR's have been stored in memory, but will not be removed until both endpoints can agree
    // to removing the version
    CommittedNeedsSynchronization { new_version: u32, old_version: u32 }
}

impl<R: Ratchet> Toolset<R> {
    /// Creates a new [Toolset]. Designates the `hyper_ratchet` as the static auxiliary ratchet
    /// hyper_ratchet should be version 0
    pub fn new(cid: u64, hyper_ratchet: R) -> Self {
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.push_front(hyper_ratchet.clone());
        Toolset { cid, most_recent_hyper_ratchet_version: 0, oldest_hyper_ratchet_version: 0, map, static_auxiliary_hyper_ratchet: hyper_ratchet }
    }

    #[cfg(debug_assertions)]
    pub fn new_debug(cid: u64, hyper_ratchet: R, most_recent_hyper_ratchet_version: u32, oldest_hyper_ratchet_version: u32) -> Self {
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.push_front(hyper_ratchet.clone());
        Toolset { cid, most_recent_hyper_ratchet_version, oldest_hyper_ratchet_version, map, static_auxiliary_hyper_ratchet: hyper_ratchet }
    }

    /// Updates from an inbound DrillUpdateObject. Returns the new Drill
    pub fn update_from(&mut self, new_hyper_ratchet: R) -> Option<UpdateStatus> {
        let latest_hr_version = self.get_most_recent_hyper_ratchet_version();

        if new_hyper_ratchet.get_cid() != self.cid {
            log::error!(target: "lusna", "The supplied hyper ratchet does not belong to the expected CID (expected: {}, obtained: {})", self.cid, new_hyper_ratchet.get_cid());
            return None;
        }

        if latest_hr_version != new_hyper_ratchet.version().wrapping_sub(1) {
            log::error!(target: "lusna", "The supplied hyper ratchet is not precedent to the drill update object (expected: {}, obtained: {})", latest_hr_version + 1, new_hyper_ratchet.version());
            return None;
        }

        let update_status = self.append_hyper_ratchet(new_hyper_ratchet);
        let cur_version = match &update_status {
            UpdateStatus::Committed { new_version } | UpdateStatus::CommittedNeedsSynchronization { new_version, .. } => *new_version
        };

        self.most_recent_hyper_ratchet_version = cur_version;

        let prev_version = self.most_recent_hyper_ratchet_version.wrapping_sub(1);
        log::trace!(target: "lusna", "[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_HYPER_RATCHETS_IN_MEMORY, prev_version, cur_version, self.get_adjusted_index(cur_version), self.get_adjusted_index(prev_version), self.get_oldest_hyper_ratchet_version(), self.map.len());
        Some(update_status)
    }

    /*
    // on wrap-around, will hit zero (which is reserved), thus will return 1
    fn get_next_version(base: u32) -> u32 {
        std::cmp::max(1, base.wrapping_add(1))
    }

    const fn get_previous_version(base: u32) -> u32 {
        let vers = base.wrapping_sub(1);
        if vers != STATIC_AUX_VERSION {
            vers
        } else {
            u32::MAX
        }
    }*/


    #[allow(unused_results)]
    ///Replacing drills is not allowed, and is why this subroutine returns an error when a collision is detected
    ///
    /// Returns the new hyper ratchet version
    fn append_hyper_ratchet(&mut self, hyper_ratchet: R) -> UpdateStatus {
        //debug_assert!(self.map.len() <= MAX_HYPER_RATCHETS_IN_MEMORY);
        let new_version = hyper_ratchet.version();
        //println!("max hypers: {} @ {} bytes ea", MAX_HYPER_RATCHETS_IN_MEMORY, get_approx_bytes_per_hyper_ratchet());
        self.map.push_front(hyper_ratchet);
        if self.map.len() > MAX_HYPER_RATCHETS_IN_MEMORY {
            let old_version = self.get_oldest_hyper_ratchet_version();
            log::trace!(target: "lusna", "[Toolset Update] Needs Truncation. Old version: {}", old_version);
            UpdateStatus::CommittedNeedsSynchronization { new_version, old_version }
        } else {
            UpdateStatus::Committed { new_version }
        }
    }

    /// When append_hyper_ratchet returns CommittedNeedsSynchronization on Bob's side, Bob should first
    /// send a packet to Alice telling her that capacity has been reached and that version V should be dropped.
    /// Alice will then prevent herself from sending any more packets using version V, and will locally run this
    /// function. Next, Alice should alert Bob telling him that it's now safe to remove version V. Bob then runs
    /// this function last. By doing this, Alice no longer sends packets that may be no longer be valid
    #[allow(unused_results)]
    pub fn deregister_oldest_hyper_ratchet(&mut self, version: u32) -> Result<(), CryptError> {
        if self.map.len() <= MAX_HYPER_RATCHETS_IN_MEMORY {
            return Err(CryptError::DrillUpdateError("Cannot call for deregistration unless the map len is maxed out".to_string()))
        }

        let oldest = self.get_oldest_hyper_ratchet_version();
        if oldest != version {
            Err(CryptError::DrillUpdateError(format!("Unable to deregister. Provided version: {}, expected version: {}", version, oldest)))
        } else {
            self.map.pop_back().ok_or(CryptError::OutOfBoundsError)?;
            self.oldest_hyper_ratchet_version = self.oldest_hyper_ratchet_version.wrapping_add(1);
            log::trace!(target: "lusna", "[Toolset] Deregistered version {}. New oldest: {} | LEN: {}", version, self.oldest_hyper_ratchet_version, self.len());
            Ok(())
        }
    }

    /// Returns the number of HyperRatchets internally
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns the latest drill version
    pub fn get_most_recent_hyper_ratchet(&self) -> Option<&R> {
        self.map.front()
    }

    /// Returns the oldest drill in the VecDeque
    pub fn get_oldest_hyper_ratchet(&self) -> Option<&R> {
        self.map.back()
    }

    /// Gets the oldest drill version
    pub fn get_oldest_hyper_ratchet_version(&self) -> u32 {
        self.oldest_hyper_ratchet_version
    }

    /// Returns the most recent drill
    pub fn get_most_recent_hyper_ratchet_version(&self) -> u32 {
        self.most_recent_hyper_ratchet_version
    }

    /// Returns the static auxiliary drill. There is no "set" function, because this really
    /// shouldn't be changing internally as this is depended upon by datasets which require a fixed encryption
    /// version which would otherwise normally get dropped from the VecDeque semi-actively.
    ///
    /// This panics if the internal map is empty
    ///
    /// The static auxilliary drill is used for RECOVERY MODE. I.e., if the version are out
    /// of sync, then the static auxiliary drill is used to obtain the nonce for the AES GCM
    /// mode of encryption
    pub fn get_static_auxiliary_ratchet(&self) -> &R {
        &self.static_auxiliary_hyper_ratchet
    }

    /// The index within the vec deque does not necessarily track the drill versions.
    /// This function adjusts for that
    #[inline]
    fn get_adjusted_index(&self, version: u32) -> usize {
        self.most_recent_hyper_ratchet_version.wrapping_sub(version) as usize
    }

    /// Returns a specific drill version
    pub fn get_hyper_ratchet(&self, version: u32) -> Option<&R> {
        let idx = self.get_adjusted_index(version);
        //println!("Getting idx {} which should have v{}", idx, version);

        let res = self.map.get(idx);
        if res.is_none() {
            log::error!(target: "lusna", "Attempted to get ratchet v{}, but does not exist! len: {}. Oldest: {}. Newest: {}", version, &self.map.len(), self.oldest_hyper_ratchet_version, self.most_recent_hyper_ratchet_version);
        }

        res
    }

    /// Returns a range of drills. Returns None if any drill in the range is missing
    pub fn get_hyper_ratchets(&self, versions: RangeInclusive<u32>) -> Option<Vec<&R>> {
        let mut ret = Vec::with_capacity((*versions.end() - *versions.start() + 1) as usize);
        for version in versions {
            if let Some(drill) = self.get_hyper_ratchet(version) {
                ret.push(drill);
            } else {
                return None;
            }
        }

        Some(ret)
    }

    /// Serializes the toolset to a buffer
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, CryptError<String>> {
        bincode2::serialize(self).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// Deserializes from a slice of bytes
    pub fn deserialize_from_bytes<T: AsRef<[u8]>>(input: T) -> Result<Self, CryptError<String>> {
        bincode2::deserialize(input.as_ref()).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// Resets the internal state to the default, if necessary. At the beginning of each session, this should be called
    pub fn verify_init_state(&self) -> Option<()> {
        self.static_auxiliary_hyper_ratchet.reset_ara();
        Some(())
    }
}

/// Makes replacing/synchronizing toolsets easier
/// input: (static_aux_ratchet, f(0))
pub type StaticAuxRatchet = HyperRatchet;
impl From<(StaticAuxRatchet, HyperRatchet)> for Toolset<HyperRatchet> {
    fn from(drill: (StaticAuxRatchet, HyperRatchet)) -> Self {
        let most_recent_hyper_ratchet_version = drill.1.version();
        let oldest_hyper_ratchet_version = most_recent_hyper_ratchet_version; // for init, just like in the normal constructor
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.insert(0, drill.1);
        Self {
            cid: drill.0.get_cid(),
            oldest_hyper_ratchet_version,
            most_recent_hyper_ratchet_version,
            map,
            static_auxiliary_hyper_ratchet: drill.0
        }
    }
}