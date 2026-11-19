//! What a wave's ciphertext is bound to.
//!
//! Under [`WaveBinding::Bound`] a wave's coordinates (its object, group, position and ratchet
//! version) are the wave's associated data, so it opens only in the place it was sealed for.
//! [`WaveBinding::Unbound`] is the layout of a node that predates the binding, used only with
//! such a node.

use citadel_types::proto::ObjectId;

/// Whether waves exchanged with a node carry their coordinates as associated data. Chosen per
/// group from the peer's protocol version; there is no default.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaveBinding {
    /// The wave's object, group, index and ratchet version are authenticated with it.
    Bound,
    /// The wave authenticates nothing beyond its ciphertext (a node below the binding).
    Unbound,
}

/// Distinguishes this associated data from any other the same keys might authenticate.
const DOMAIN: &[u8; 16] = b"citadel-wave-v1\0";
/// DOMAIN, object id, group id, wave index, ratchet version.
const BOUND_LEN: usize = 16 + 16 + 8 + 4 + 4;

/// The associated data one wave is sealed and opened with.
pub struct WaveAad {
    bytes: [u8; BOUND_LEN],
    len: usize,
}

impl WaveAad {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
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
        let mut bytes = [0u8; BOUND_LEN];
        match self {
            WaveBinding::Unbound => WaveAad { bytes, len: 0 },
            WaveBinding::Bound => {
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
                WaveAad {
                    bytes,
                    len: BOUND_LEN,
                }
            }
        }
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

    #[test]
    fn unbound_waves_authenticate_nothing_extra() {
        assert!(WaveBinding::Unbound
            .aad(ObjectId(1), 2, 3, 4)
            .as_slice()
            .is_empty());
    }
}
