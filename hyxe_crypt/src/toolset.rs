use std::collections::VecDeque;

//use rayon::prelude::{ParallelSlice, IndexedParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use crate::drill::{BYTES_PER_3D_ARRAY, Drill};
use crate::drill_update::DrillUpdateObject;
use crate::misc::CryptError;
use std::ops::RangeInclusive;
use std::sync::Arc;

/// The maximum amount of memory per toolset in RAM is 300kb
pub const MAX_TOOLSET_MEMORY_BYTES: usize = 1024 * 30;
/// Returns the max number of drill that can be stored in memory
pub const MAX_DRILLS_IN_MEMORY: usize = calculate_max_drills();

/// According to [Equation 1] in drill.rs, the formula to calculate the number of bytes
/// in memory from the encryption pairs alone is 31(s*p_r). Thus, to calculate the max
/// number of drills, we need to take the floor of MAX_TOOLSET_MEMORY_BYTES/(31(s*p_r))
/// where 31(s*p_r) == BYTES_PER_3D_ARRAY
const fn calculate_max_drills() -> usize {
    (MAX_TOOLSET_MEMORY_BYTES / BYTES_PER_3D_ARRAY) - 1
}

/// The [Toolset] is the layer of abstraction between a [ClientNetworkAccount] and the
/// inner drills.
#[derive(Serialize, Deserialize)]
pub struct Toolset where Self: Sized {
    /// the CID of the owner
    pub cid: u64,
    most_recent_drill_version: u32,
    map: VecDeque<Drill>,
    /// The static auxiliary drill was made to cover a unique situation that is consequence of dropping-off the back of the VecDeque upon upgrade:
    /// As the back gets dropped, any data drilled using that version now becomes undecipherable forever. The solution to this is having a static drill, but this
    /// does indeed compromise safety. This is thus marked as unsafe for use. This should NEVER be used for network data transmission, and should only
    /// really be used when drilling data which is stored under the local filesystem via HyxeFiles. Since a HyxeFile, for example, hides revealing data
    /// with a complex file path, any possible hacker wouldn't necessarily be able to correlate the HyxeFile with the correct CID unless additional work was done.
    /// Local filesystems should be encrypted anyways (otherwise voids warranty), but, having the HyxeFile layer is really just a "weak" layer of protection
    /// designed to derail any currently existing or historical viruses that may look for conventional means of breaking-through data
    static_auxiliary_drill: Drill
}

impl Toolset {
    /// Creates a new [Toolset]
    pub fn new(cid: u64) -> Result<Self, CryptError<String>> {
        Drill::new(cid, 0).and_then(|drill_0| {
            let mut map = VecDeque::with_capacity(MAX_DRILLS_IN_MEMORY);
            map.insert(0, drill_0.clone());
            Ok(Toolset { cid, most_recent_drill_version: 0, map, static_auxiliary_drill: drill_0.clone() })
        })
    }

    /// Asynchronously updates the toolset, generating the next drill.
    /// Return the DrillUpdateObject
    pub fn update(&mut self) -> Result<DrillUpdateObject, CryptError<String>> {
        self.next_drill().and_then(|(update, next_drill)| {
            assert_eq!(update.drill_version, next_drill.get_version());
            match self.append_drill(next_drill) {
                Ok(_) => {
                    let prev_version = self.most_recent_drill_version.wrapping_sub(1);
                    log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_DRILLS_IN_MEMORY, prev_version, prev_version + 1, self.get_adjusted_index(prev_version + 1).unwrap(), self.get_adjusted_index(prev_version).unwrap(), self.get_oldest_drill_version(), self.map.len());
                    Ok(update)
                },
                Err(err) => Err(err)
            }
        })
    }

    /// Updates from an inbound DrillUpdateObject. Returns the new Drill
    pub fn update_from(&mut self, latest_active_drill: &Drill, drill_update_object: DrillUpdateObject) -> Option<Drill> {
        let latest_drill_version = self.get_most_recent_drill_version();
        if latest_drill_version != latest_active_drill.get_version() {
            log::error!("This node's latest drill version is not compatible with the supplied DOU");
            return None;
        }

        if latest_active_drill.get_version() != drill_update_object.drill_version - 1 {
            log::error!("The supplied drill is not precedent to the drill update object");
            return None;
        }

        let (_, next_drill) = drill_update_object.compute_next_recursion(latest_active_drill, true)?;
        match self.append_drill(next_drill.clone()) {
            Ok(_) => {
                let prev_version = self.most_recent_drill_version.wrapping_sub(1);
                log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_DRILLS_IN_MEMORY, prev_version, prev_version + 1, self.get_adjusted_index(prev_version + 1).unwrap(), self.get_adjusted_index(prev_version).unwrap(), self.get_oldest_drill_version(), self.map.len());
                Some(next_drill)
            },
            Err(_err) => None
        }
    }

    /// store a new drill. Must have the latest version
    pub fn register_new_drill(&mut self, drill: Drill) -> bool {
        match self.append_drill(drill.clone()) {
            Ok(_) => {
                let proposed_new_drill_version = drill.get_version();
                let expected_new_drill_version =  self.most_recent_drill_version.wrapping_add(1);

                if proposed_new_drill_version != expected_new_drill_version {
                    log::error!("An invalid new drill attempted to be registered, for the versions are not equivalent (Proposed: {} | Expected: {})", proposed_new_drill_version, expected_new_drill_version);
                    // We need to limit the drill version by trimming. There are several scenarios:
                    // 0. The expected new version is BELOW the proposed new version. This means localhost is behind the adjacent node.
                    //
                    // 1. The expected new version is AHEAD the proposed new version. This means localhost is ahead the adjacent node.
                    // Since drill versioning is handled by the system internally, and it uses to latest version, localhost just needs
                    // to trim
                    false
                } else {
                    self.most_recent_drill_version = self.most_recent_drill_version.wrapping_add(1);
                    let _prev_version = self.most_recent_drill_version.wrapping_sub(1);
                    //log::info!("[{}] Upgraded {} to {}. Adjusted index of current: {}. Adjusted index of (current - 1): {} || OLDEST: {} || LEN: {}", MAX_DRILLS_IN_MEMORY, prev_version, prev_version + 1, self.get_adjusted_index(prev_version + 1).unwrap(), self.get_adjusted_index(prev_version).unwrap(), self.get_oldest_drill_version(), self.map.len());
                    true
                }
            },

            _ => {
                false
            }
        }
    }

    /// Runs update n times
    #[allow(unused_results)]
    pub fn update_n(&mut self, count: usize) -> Result<(), CryptError<String>> {
        for _ in 0..count {
            self.update()?;
        }

        Ok(())
    }

    fn next_drill(&self) -> Result<(DrillUpdateObject, Drill), CryptError<String>> {
        if let Some(current) = self.get_most_recent_drill() {
            let next_version = self.most_recent_drill_version.wrapping_add(1);
            DrillUpdateObject::generate(self.cid, next_version, current).and_then(|update| {
                update.compute_next_recursion(current, true).ok_or_else(|| CryptError::DrillUpdateError("Unable to compute next recursion. Invalid port combos".to_string()))
            })
        } else {
            Err(CryptError::DrillUpdateError("RECENT_DRILL_NON_EXISTS".to_string()))
        }
    }

    #[allow(unused_results)]
    ///Replacing drills is not allowed, and is why this subroutine returns an error when a collision is detected
    fn append_drill(&mut self, drill: Drill) -> Result<(), CryptError<String>> {
        debug_assert!(self.map.len() <= MAX_DRILLS_IN_MEMORY);
        if self.map.len() == MAX_DRILLS_IN_MEMORY {
            if let Some(_drill_old) = self.map.pop_back() {
                self.map.push_front(drill);
                Ok(())
            } else {
                unreachable!("This shouldn't happen");
            }
        } else {
            self.map.push_front(drill);
            Ok(())
        }
    }

    /// Returns the latest drill version
    pub fn get_most_recent_drill(&self) -> Option<&Drill> {
        self.map.front()
    }

    /// Returns the oldest drill in the VecDeque
    pub fn get_oldest_drill(&self) -> Option<&Drill> {
        self.map.back()
    }

    /// Gets the oldest drill version
    pub fn get_oldest_drill_version(&self) -> u32 {
        self.get_oldest_drill().unwrap().version
    }

    /// Returns the most recent drill
    pub fn get_most_recent_drill_version(&self) -> u32 {
        self.most_recent_drill_version
    }

    /// Returns the static auxiliary drill. There is no "set" function, because this really
    /// shouldn't be changing internally as this is depended upon by datasets which require a fixed encryption
    /// version which would otherwise normally get dropped from the VecDeque semi-actively.
    ///
    /// This panics if the internal map is empty
    ///
    /// The static auxilliary drill is used for RECOVERY MODE. I.e., if the version are out
    /// of sync, then the static auxiliary drill is used to obtain the nonce for the AES GCM
    /// mode of encryption. TODO: Update HYXEFILE subsystem
    pub unsafe fn get_static_auxiliary_drill(&self) -> Drill {
        self.static_auxiliary_drill.clone()
    }

    /// The index within the vec deque does not necessarily track the drill versions.
    /// Returns None if the version is out of bounds
    ///
    /// TODO: Handle the case when wrapping_add goes beyond the max u32
    #[inline]
    fn get_adjusted_index(&self, version: u32) -> Option<usize> {
        let oldest_drill_version = self.get_oldest_drill_version();
        if version > self.most_recent_drill_version || version < oldest_drill_version {
            return None;
        }

        if self.most_recent_drill_version as usize > MAX_DRILLS_IN_MEMORY {
            Some((self.most_recent_drill_version - version) as usize)
        } else {
            Some(self.most_recent_drill_version as usize - version as usize)
        }
    }

    /// Returns a specific drill version
    pub fn get_drill(&self, version: u32) -> Option<&Drill> {
        let idx = self.get_adjusted_index(version)?;
        //println!("Getting idx {} which should have v{}", idx, version);
        self.map.get(idx)
    }

    /// Returns a range of drills. Returns None if any drill in the range is missing
    pub fn get_drills(&self, versions: RangeInclusive<u32>) -> Option<Vec<&Drill>> {
        let mut ret = Vec::with_capacity((*versions.end() - *versions.start() + 1) as usize);
        for version in versions {
            if let Some(drill) = self.get_drill(version) {
                ret.push(drill);
            } else {
                return None;
            }
        }

        Some(ret)
    }

    /// Returns a range of drill versions
    pub fn get_available_drill_versions(&self) -> RangeInclusive<u32> {
        self.get_oldest_drill_version()..=self.get_most_recent_drill_version()
    }

    /// Serializes the toolset to a buffer
    pub fn serialize_to_vec(&mut self) -> Result<Vec<u8>, CryptError<String>> {
        bincode2::serialize(self).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// Deserializes from a slice of bytes
    pub fn deserialize_from_bytes<T: AsRef<[u8]>>(input: T) -> Result<Self, CryptError<String>> {
        bincode2::deserialize(input.as_ref()).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// With endpoint encryption, peer A sends its toolset to peer B.
    /// When this occurs, the data is symmetric; this is good, but we don't want the CID
    /// to remain constant, otherwise the wrong CID will get inscribed in HdpHeaders
    /// This should be called RIGHT AFTER deserializing the toolset. It will PANIC
    /// if any drills are floating around in memory
    pub fn force_update_cid_init_only(mut self, new_cid: u64) -> Self {
        self.cid = new_cid;
        // replace static aux's drill
        let mut drill_bits = Arc::try_unwrap(self.static_auxiliary_drill.inner).unwrap();
        drill_bits.cid = new_cid;
        self.static_auxiliary_drill = Drill::from(drill_bits);
        let drill_0 = self.map.remove(0).unwrap();
        let mut drill_bits = Arc::try_unwrap(drill_0.inner).unwrap();
        drill_bits.cid = new_cid;
        let drill_0 = Drill::from(drill_bits);
        self.map.insert(0, drill_0);
        self
    }
}

/// Makes replacing/synchronizing toolsets easier
/// input: (static_aux_drill, f(0))
pub type StaticAuxDrill = Drill;
impl From<(StaticAuxDrill, Drill)> for Toolset {
    fn from(drill: (StaticAuxDrill, Drill)) -> Self {
        let mut map = VecDeque::with_capacity(MAX_DRILLS_IN_MEMORY);
        map.insert(0, drill.1.clone());
        Self {
            cid: drill.0.get_cid(),
            most_recent_drill_version: drill.1.get_version(),
            map,
            static_auxiliary_drill: drill.0
        }
    }
}