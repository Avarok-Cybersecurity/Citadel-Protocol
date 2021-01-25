use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::misc::CryptError;
use std::ops::RangeInclusive;
use crate::hyper_ratchet::{get_approx_bytes_per_hyper_ratchet, HyperRatchet};

/// The maximum amount of memory per toolset in RAM is 300kb
pub const MAX_TOOLSET_MEMORY_BYTES: usize = 1024 * 120;
/// Returns the max number of drill that can be stored in memory
pub const MAX_HYPER_RATCHETS_IN_MEMORY: usize = calculate_max_hyper_ratchets();

/// According to [Equation 1] in drill.rs, the formula to calculate the number of bytes
/// in memory from the encryption pairs alone is 31(s*p_r). Thus, to calculate the max
/// number of drills, we need to take the floor of MAX_TOOLSET_MEMORY_BYTES/(31(s*p_r))
/// where 31(s*p_r) == BYTES_PER_3D_ARRAY
const fn calculate_max_hyper_ratchets() -> usize {
    let val = (MAX_TOOLSET_MEMORY_BYTES / get_approx_bytes_per_hyper_ratchet()) as isize - 1;
    if val > 0 {
        val as usize
    } else {
        1
    }
}

/// The [Toolset] is the layer of abstraction between a [ClientNetworkAccount] and the
/// inner hyper ratchets.
#[derive(Serialize, Deserialize)]
pub struct Toolset {
    /// the CID of the owner
    pub cid: u64,
    most_recent_hyper_ratchet_version: u32,
    oldest_hyper_ratchet_version: u32,
    map: VecDeque<HyperRatchet>,
    /// The static auxiliary drill was made to cover a unique situation that is consequence of dropping-off the back of the VecDeque upon upgrade:
    /// As the back gets dropped, any data drilled using that version now becomes undecipherable forever. The solution to this is having a static drill, but this
    /// does indeed compromise safety. This is thus marked as unsafe for use. This should NEVER be used for network data transmission, and should only
    /// really be used when drilling data which is stored under the local filesystem via HyxeFiles. Since a HyxeFile, for example, hides revealing data
    /// with a complex file path, any possible hacker wouldn't necessarily be able to correlate the HyxeFile with the correct CID unless additional work was done.
    /// Local filesystems should be encrypted anyways (otherwise voids warranty), but, having the HyxeFile layer is really just a "weak" layer of protection
    /// designed to derail any currently existing or historical viruses that may look for conventional means of breaking-through data
    static_auxiliary_hyper_ratchet: HyperRatchet
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum UpdateStatus {
    // new version has been committed, and the number of HRs is still less than the total max. No E2E synchronization required
    Committed { new_version: u32 },
    // The maximum number of acceptable HR's have been stored in memory, but will not be removed until both endpoints can agree
    // to removing the version
    CommittedNeedsSynchronization { new_version: u32, old_version: u32 }
}

impl Toolset {
    /// Creates a new [Toolset]. Designates the `hyper_ratchet` as the static auxiliary ratchet
    pub fn new(cid: u64, hyper_ratchet: HyperRatchet) -> Self {
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.push_front(hyper_ratchet.clone());
        Toolset { cid, most_recent_hyper_ratchet_version: 0, oldest_hyper_ratchet_version: 0, map, static_auxiliary_hyper_ratchet: hyper_ratchet }
    }

    #[cfg(debug_assertions)]
    pub fn new_debug(cid: u64, hyper_ratchet: HyperRatchet, most_recent_hyper_ratchet_version: u32, oldest_hyper_ratchet_version: u32) -> Self {
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.push_front(hyper_ratchet.clone());
        Toolset { cid, most_recent_hyper_ratchet_version, oldest_hyper_ratchet_version, map, static_auxiliary_hyper_ratchet: hyper_ratchet }
    }

    /// Updates from an inbound DrillUpdateObject. Returns the new Drill
    pub fn update_from(&mut self, new_hyper_ratchet: HyperRatchet) -> Option<UpdateStatus> {
        let latest_hr_version = self.get_most_recent_hyper_ratchet_version();

        if new_hyper_ratchet.get_cid() != self.cid {
            log::error!("The supplied hyper ratchet does not belong to the expected CID (expected: {}, obtained: {})", self.cid, new_hyper_ratchet.get_cid());
            return None;
        }

        if latest_hr_version != new_hyper_ratchet.version().wrapping_sub(1) {
            log::error!("The supplied hyper ratchet is not precedent to the drill update object (expected: {}, obtained: {})", latest_hr_version + 1, new_hyper_ratchet.version());
            return None;
        }

        let update_status = self.append_hyper_ratchet(new_hyper_ratchet);
        let cur_version = match &update_status {
            UpdateStatus::Committed { new_version } | UpdateStatus::CommittedNeedsSynchronization { new_version, .. } => *new_version
        };

        self.most_recent_hyper_ratchet_version = cur_version;

        let prev_version = self.most_recent_hyper_ratchet_version.wrapping_sub(1);
        log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_HYPER_RATCHETS_IN_MEMORY, prev_version, cur_version, self.get_adjusted_index(cur_version), self.get_adjusted_index(prev_version), self.get_oldest_hyper_ratchet_version(), self.map.len());
        Some(update_status)
    }


    #[allow(unused_results)]
    ///Replacing drills is not allowed, and is why this subroutine returns an error when a collision is detected
    ///
    /// Returns the new hyper ratchet version
    fn append_hyper_ratchet(&mut self, hyper_ratchet: HyperRatchet) -> UpdateStatus {
        //debug_assert!(self.map.len() <= MAX_HYPER_RATCHETS_IN_MEMORY);
        let new_version = hyper_ratchet.version();
        //println!("max hypers: {} @ {} bytes ea", MAX_HYPER_RATCHETS_IN_MEMORY, get_approx_bytes_per_hyper_ratchet());
        self.map.push_front(hyper_ratchet);
        if self.map.len() > MAX_HYPER_RATCHETS_IN_MEMORY {
            let old_version = self.get_oldest_hyper_ratchet_version();
            log::info!("[Toolset Update] Needs Truncation. Old version: {}", old_version);
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
            return Err(CryptError::DrillUpdateError(format!("Cannot call for deregistration unless the map len is maxed out")))
        }

        let oldest = self.get_oldest_hyper_ratchet_version();
        if oldest != version {
            Err(CryptError::DrillUpdateError(format!("Unable to deregister. Provided version: {}, expected version: {}", version, oldest)))
        } else {
            self.map.pop_back().ok_or(CryptError::OutOfBoundsError)?;
            self.oldest_hyper_ratchet_version = self.oldest_hyper_ratchet_version.wrapping_add(1);
            log::info!("[Toolset] Deregistered version {}. New oldest: {} | LEN: {}", version, self.oldest_hyper_ratchet_version, self.len());
            Ok(())
        }
    }

    /// Returns the number of HyperRatchets internally
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns the latest drill version
    pub fn get_most_recent_hyper_ratchet(&self) -> Option<&HyperRatchet> {
        self.map.front()
    }

    /// Returns the oldest drill in the VecDeque
    pub fn get_oldest_hyper_ratchet(&self) -> Option<&HyperRatchet> {
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
    pub fn get_static_auxiliary_ratchet(&self) -> &HyperRatchet {
        &self.static_auxiliary_hyper_ratchet
    }

    /// The index within the vec deque does not necessarily track the drill versions.
    /// This function adjusts for that
    #[inline]
    fn get_adjusted_index(&self, version: u32) -> usize {
        self.most_recent_hyper_ratchet_version.wrapping_sub(version) as usize
    }

    /// Returns a specific drill version
    pub fn get_hyper_ratchet(&self, version: u32) -> Option<&HyperRatchet> {
        let idx = self.get_adjusted_index(version);
        //println!("Getting idx {} which should have v{}", idx, version);
        self.map.get(idx)
    }

    /// Returns a range of drills. Returns None if any drill in the range is missing
    pub fn get_hyper_ratchets(&self, versions: RangeInclusive<u32>) -> Option<Vec<&HyperRatchet>> {
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
    pub fn verify_init_state(&mut self) -> Option<()> {
        if self.static_auxiliary_hyper_ratchet.has_verified_packets() {
            log::info!("Resetting toolset ...");
            let cid = self.cid;
            let serialized_static = bincode2::serialize(&self.static_auxiliary_hyper_ratchet).ok()?;
            let static_aux = bincode2::deserialize(&serialized_static[..]).ok()?;
            *self = Toolset::new(cid, static_aux);
        }

        Some(())
    }
}

/// Makes replacing/synchronizing toolsets easier
/// input: (static_aux_ratchet, f(0))
pub type StaticAuxRatchet = HyperRatchet;
impl From<(StaticAuxRatchet, HyperRatchet)> for Toolset {
    fn from(drill: (HyperRatchet, HyperRatchet)) -> Self {
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