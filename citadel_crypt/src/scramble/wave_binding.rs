//! What a wave's ciphertext is bound to.
//!
//! Under [`WaveBinding::Bound`] a wave's coordinates (its object, group, position and ratchet
//! version) are the wave's associated data, so it opens only in the place it was sealed for.
//! It is the only layout: a node that seals waves without their coordinates is not taken part
//! with (its waves fail to open). The type is where a later layout would be added.

use citadel_types::proto::ObjectId;

/// What waves exchanged with a node carry as associated data. Named by every sender and
/// receiver; there is no default.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaveBinding {
    /// The wave's object, group, index and ratchet version are authenticated with it.
    Bound,
}

/// Distinguishes this associated data from any other the same keys might authenticate.
const DOMAIN: &[u8; 16] = b"citadel-wave-v1\0";
/// DOMAIN, object id, group id, wave index, ratchet version.
const BOUND_LEN: usize = 16 + 16 + 8 + 4 + 4;

/// The associated data one wave is sealed and opened with.
pub struct WaveAad {
    bytes: [u8; BOUND_LEN],
}

impl WaveAad {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl WaveBinding {
    /// The associated data for wave `wave_id` of group `group_id` in object `object_id`, sealed
    /// under ratchet version `ratchet_version`.
    pub fn aad(
        self,
        object_id: ObjectId,
        group_id: u64,
        wave_id: u32,
        ratchet_version: u32,
    ) -> WaveAad {
        let WaveBinding::Bound = self;
        let mut bytes = [0u8; BOUND_LEN];
        let fields: [&[u8]; 5] = [
            DOMAIN,
            &object_id.0.to_be_bytes(),
            &group_id.to_be_bytes(),
            &wave_id.to_be_bytes(),
            &ratchet_version.to_be_bytes(),
        ];
        let mut at = 0;
        for field in fields {
            bytes[at..at + field.len()].copy_from_slice(field);
            at += field.len();
        }
        WaveAad { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_coordinate_changes_the_bound_data() {
        let base = WaveBinding::Bound.aad(ObjectId(1), 2, 3, 4);
        for other in [
            WaveBinding::Bound.aad(ObjectId(9), 2, 3, 4),
            WaveBinding::Bound.aad(ObjectId(1), 9, 3, 4),
            WaveBinding::Bound.aad(ObjectId(1), 2, 9, 4),
            WaveBinding::Bound.aad(ObjectId(1), 2, 3, 9),
        ] {
            assert_ne!(base.as_slice(), other.as_slice());
        }
        assert_eq!(base.as_slice().len(), BOUND_LEN);
    }
}
