use crate::drill::Drill;

/// The `scrambled_sequence` that is returned by `get_packet_coordinates` is scrambled; the true value of the sequence
/// is NOT given, because it is expected that the values be imprinted upon the packet header and thus are public-facing
#[derive(Debug, Default, Clone)]
pub struct PacketVector {
    /// The group ID of this packet
    pub group_id: u64,
    /// The sequence is the position in the wave ID. Repeating sequences CANNOT exist, and as such,
    /// the drill generator must ensure all values in the port range are non-repeating. TODO: Unique RNG.
    ///
    ///
    /// A wave is a set of packets in scrambled order in respect to the in/out ports. There are a maximum
    /// of multiport_range packets per wave. The wave index starts at 0, and increments to u32::max
    pub wave_id: u32,
    /// The local port from which the packet will leave from, thus implying the sequence
    pub local_port: u16,
    /// The remote port to which the packet will arrive, thus implying the sequence
    pub remote_port: u16,
    /// The original true sequence
    pub true_sequence: usize,
}

use num_integer::Integer;

/// The true sequence should just be the exact order of the data without any consideration of sequence nor wave-ID
pub fn generate_packet_vector(true_sequence: usize,  group_id: u64, drill: &Drill) -> PacketVector {
    // To get the wave_id, we must floor divide the true sequence by the port range. The remainder is the sequence
    let ref port_range = drill.get_multiport_width();
    let (true_wave_id, relative_sequence) = true_sequence.div_mod_floor(port_range);
    // To scramble the true values, we get their corresponding values in the drill
    let (local_port, remote_port) = *drill.scramble_mappings.get(relative_sequence).unwrap();

    PacketVector { group_id, wave_id: true_wave_id as u32, local_port, remote_port, true_sequence }
}

/// This will return None if the values are invalid
#[inline]
pub fn generate_packet_coordinates_inv(wave_id: u32, src_port: u16, local_port: u16, scramble_drill: &Drill) -> Option<usize> {
    for (idx, (in_port, out_port)) in scramble_drill.scramble_mappings.iter().enumerate() {
        if *in_port == src_port && *out_port == local_port {
            let port_range = scramble_drill.scramble_mappings.len();
            let true_position = (wave_id as usize * port_range) + idx;
            return Some(true_position);
        }
    }

    None
}