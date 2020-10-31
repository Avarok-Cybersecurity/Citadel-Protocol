use crate::drill::{BYTES_PER_3D_ARRAY, Drill, DrillBits, RawDrillSkeleton};
use serde::{Serialize, Deserialize};
use crate::misc::{CryptError, xor2_forall_between_vec_and_drill, create_port_mapping};
use rand::{thread_rng, RngCore};
use std::sync::Arc;

/// The DrillUpdateObject is the over-the-network data transfer device. If the port range is 20, then its size in bytes
/// is 3,720 bytes or 3.720 kb (notwithstanding Base64 encryption). The DrillUpdateObject must be transmitted over the network,
/// therefore, it *should* be encrypted with low encryption (to ensure there is no increase in size). However, keep in mind
/// that thanks to the nature of update the algorithm, this process is not necessary. However, it is recommended. The DoU,
/// before it's transferred, should use the most recent/synchronized drill version on low-security mode upon the bytes.
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct DrillUpdateObject {
    /// The drill version proposed by this update object
    pub drill_version: u32,
    /// The CID which will have the constants held herein applied to obtain the next drill version
    pub cid: u64,
    /// The constants which will be used to reconstruct a drill
    pub data: Vec<u8>,
    /// Contains the offsets. To find the new port combo, take the old port combos and ADD the offsets
    pub offset_map: Vec<(i16, i16)>
}

impl DrillUpdateObject {
    /// Asynchronously generates a new DrillUpdateObjects. The supplied drill version should be the NEXT
    /// drill version
    pub fn generate(cid: u64, drill_version: u32, prev_drill: &Drill) -> Result<Self, CryptError<String>> {
        let bytes: &mut [u8; BYTES_PER_3D_ARRAY] = &mut [0; BYTES_PER_3D_ARRAY];
        thread_rng().fill_bytes(bytes);
        let bytes = bytes.to_vec();
        let offset_map = generate_offset_map(prev_drill);
        Ok(Self { drill_version, cid, data: bytes, offset_map })
    }

    /// Applies the transform between the current update object and a supplied drill.
    /// Panics if the drill version supplied is not equal to the update object's version
    /// minus one
    ///
    /// `vers_check`: In recovery mode, the static auxiliary drill is used, and as such, the versioning
    /// should not be checked
    #[inline]
    pub fn compute_next_recursion(self, drill: &Drill, vers_check: bool) -> Option<(Self, Drill)> {
        let next_version = self.drill_version;
        if vers_check {
            assert_eq!(drill.get_version(), next_version - 1);
        }
        let skeleton = xor2_forall_between_vec_and_drill(&self, drill);
        let next_drill = construct_drill_from_3d_array(skeleton, next_version, drill.get_cid(), &self.offset_map, drill)?;
        Some((self, next_drill))
    }

    /// Serializes self to a byte vector
    pub fn serialize_to_vector(&self) -> Result<Vec<u8>, CryptError<String>> {
        bincode2::serialize(self).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// Deserializes from a set of bytes
    pub fn deserialize_from_vector<T: AsRef<[u8]>>(input: T) -> Result<Self, CryptError<String>> {
        bincode2::deserialize(input.as_ref()).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }
}

/// Generates the offset map
pub fn generate_offset_map(prev_drill: &Drill) -> Vec<(i16, i16)> {
    let old_port_map = prev_drill.get_port_mapping();
    let next_port_map = create_port_mapping();

    let mut offset_map = Vec::with_capacity(old_port_map.len());

    for ((old_src, old_dst),(new_src, new_dst)) in old_port_map.iter().zip(next_port_map) {
        let src_offset = new_src as i16 - *old_src as i16;
        let dst_offset = new_dst as i16 - *old_dst as i16;
        offset_map.push((src_offset, dst_offset));
    }

    //debug_assert_eq!(next_port_map, get_new_combos_from_offset_map(prev_drill, &offset_map).unwrap());

    offset_map
}

fn get_new_combos_from_offset_map(prev_drill: &Drill, offset_map: &Vec<(i16, i16)>) -> Option<Vec<(u16, u16)>> {
    let old_port_map = prev_drill.get_port_mapping();
    let port_range = prev_drill.get_multiport_width() as i16;
    let mut ret = Vec::with_capacity(offset_map.len());

    for ((old_src, old_dst), (src_offset, dst_offset)) in old_port_map.iter().zip(offset_map) {
        let new_src = *src_offset + *old_src as i16;
        let new_dst = *dst_offset + *old_dst as i16;

        if new_src < 0 || new_dst < 0 || new_src > port_range || new_dst > port_range {
            log::error!("Invalid port offset map! Bad ranges");
            return None;
        }

        ret.push((new_src as u16, new_dst as u16))
    }

    Some(ret)
}

/// constructs a drill out of the constituent bits, using the previous drill to construct the new drill's port mappings
pub fn construct_drill_from_3d_array(skeleton: RawDrillSkeleton, version: u32, cid: u64, offset_map: &Vec<(i16, i16)>, prev_drill: &Drill) -> Option<Drill> {
    let new_port_mappings = get_new_combos_from_offset_map(prev_drill, offset_map)?;
    Some(Drill { inner: Arc::new(DrillBits { version, cid, low: skeleton.0, med: skeleton.1, high: skeleton.2, ultra: skeleton.3, divine: skeleton.4, port_mappings: new_port_mappings }) })
}

/// constructs a drill out of the constituent bits
pub fn construct_first_drill_from_3d_array(skeleton: RawDrillSkeleton, version: u32, cid: u64) -> Drill {
    Drill { inner: Arc::new(DrillBits { version, cid, low: skeleton.0, med: skeleton.1, high: skeleton.2, ultra: skeleton.3, divine: skeleton.4, port_mappings: create_port_mapping() }) }
}