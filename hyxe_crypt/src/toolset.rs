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

impl Toolset {
    /// Creates a new [Toolset]. Designates the `hyper_ratchet` as the static auxilliary ratchet
    pub fn new(cid: u64, hyper_ratchet: HyperRatchet) -> Self {
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.push_front(hyper_ratchet.clone());
        Toolset { cid, most_recent_hyper_ratchet_version: 0, map, static_auxiliary_hyper_ratchet: hyper_ratchet }
    }

    /// Updates from an inbound DrillUpdateObject. Returns the new Drill
    pub fn update_from(&mut self, new_hyper_ratchet: HyperRatchet) -> Option<()> {
        let latest_hr_version = self.get_most_recent_hyper_ratchet_version();

        if latest_hr_version != new_hyper_ratchet.version().saturating_sub(1) {
            log::error!("The supplied hyper ratchet is not precedent to the drill update object");
            return None;
        }

        let cur_version = self.append_hyper_ratchet(new_hyper_ratchet).ok()?;
        self.most_recent_hyper_ratchet_version = cur_version;

        let prev_version = self.most_recent_hyper_ratchet_version.saturating_sub(1);
        log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_HYPER_RATCHETS_IN_MEMORY, prev_version, cur_version, self.get_adjusted_index(cur_version).unwrap(), self.get_adjusted_index(prev_version).unwrap(), self.get_oldest_hyper_ratchet_version(), self.map.len());
        Some(())
    }

    /// store a new drill. Must have the latest version
    pub fn register_new_hyper_ratchet(&mut self, hyper_ratchet: HyperRatchet) -> bool {
        match self.append_hyper_ratchet(hyper_ratchet.clone()) {
            Ok(_) => {
                let proposed_new_hyper_ratchet_version = hyper_ratchet.version();
                let expected_new_hyper_ratchet_version =  self.most_recent_hyper_ratchet_version.wrapping_add(1);

                if proposed_new_hyper_ratchet_version != expected_new_hyper_ratchet_version {
                    log::error!("An invalid new hyper ratchet attempted to be registered, for the versions are not equivalent (Proposed: {} | Expected: {})", proposed_new_hyper_ratchet_version, expected_new_hyper_ratchet_version);
                    // We need to limit the drill version by trimming. There are several scenarios:
                    // 0. The expected new version is BELOW the proposed new version. This means localhost is behind the adjacent node.
                    //
                    // 1. The expected new version is AHEAD the proposed new version. This means localhost is ahead the adjacent node.
                    // Since drill versioning is handled by the system internally, and it uses to latest version, localhost just needs
                    // to trim
                    false
                } else {
                    self.most_recent_hyper_ratchet_version = self.most_recent_hyper_ratchet_version.wrapping_add(1);
                    let _prev_version = self.most_recent_hyper_ratchet_version.wrapping_sub(1);
                    //log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_DRILLS_IN_MEMORY, prev_version, prev_version + 1, self.get_adjusted_index(prev_version + 1).unwrap(), self.get_adjusted_index(prev_version).unwrap(), self.get_oldest_drill_version(), self.map.len());
                    true
                }
            },

            _ => {
                false
            }
        }
    }

    #[allow(unused_results)]
    ///Replacing drills is not allowed, and is why this subroutine returns an error when a collision is detected
    ///
    /// Returns the new hyper ratchet version
    fn append_hyper_ratchet(&mut self, hyper_ratchet: HyperRatchet) -> Result<u32, CryptError<String>> {
        debug_assert!(self.map.len() <= MAX_HYPER_RATCHETS_IN_MEMORY);
        let new_vers = hyper_ratchet.version();
        //println!("max hypers: {} @ {} bytes ea", MAX_HYPER_RATCHETS_IN_MEMORY, get_approx_bytes_per_hyper_ratchet());
        if self.map.len() == MAX_HYPER_RATCHETS_IN_MEMORY {
            if let Some(_old) = self.map.pop_back() {
                self.map.push_front(hyper_ratchet);
                Ok(new_vers)
            } else {
                unreachable!("This shouldn't happen");
            }
        } else {
            self.map.push_front(hyper_ratchet);
            Ok(new_vers)
        }
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
        self.get_oldest_hyper_ratchet().unwrap().version()
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
    /// Returns None if the version is out of bounds
    ///
    /// TODO: Handle the case when wrapping_add goes beyond the max u32
    #[inline]
    fn get_adjusted_index(&self, version: u32) -> Option<usize> {
        let oldest_hyper_ratchet_version = self.get_oldest_hyper_ratchet_version();
        //println!("{} must be greater than {} or less than {} to fail", version, self.most_recent_hyper_ratchet_version, oldest_hyper_ratchet_version);

        if version > self.most_recent_hyper_ratchet_version || version < oldest_hyper_ratchet_version {
            return None;
        }

        Some((self.most_recent_hyper_ratchet_version - version) as usize)
    }

    /// Returns a specific drill version
    pub fn get_hyper_ratchet(&self, version: u32) -> Option<&HyperRatchet> {
        let idx = self.get_adjusted_index(version)?;
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

    /// Returns a range of drill versions
    pub fn get_available_hyper_ratchet_versions(&self) -> RangeInclusive<u32> {
        self.get_oldest_hyper_ratchet_version()..=self.get_most_recent_hyper_ratchet_version()
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
        let mut map = VecDeque::with_capacity(MAX_HYPER_RATCHETS_IN_MEMORY);
        map.insert(0, drill.1);
        Self {
            cid: drill.0.get_cid(),
            most_recent_hyper_ratchet_version,
            map,
            static_auxiliary_hyper_ratchet: drill.0
        }
    }
}