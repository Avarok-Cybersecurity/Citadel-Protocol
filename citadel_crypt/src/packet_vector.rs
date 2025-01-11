//! Packet Vector: Secure Packet Sequencing and Port Mapping
//!
//! This module provides secure packet sequencing and port mapping functionality
//! through wave-based packet organization and scrambled port assignments. It ensures
//! ordered packet delivery while obscuring true sequence information.
//!
//! # Features
//!
//! - Wave-based packet organization
//! - Scrambled port assignments
//! - Secure sequence tracking
//! - Port mapping coordination
//! - Zero-knowledge sequence hiding
//! - Automatic memory zeroing
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::packet_vector::{PacketVector, generate_packet_vector};
//! use citadel_crypt::ratchets::entropy_bank::EntropyBank;
//! use citadel_crypt::misc::CryptError;
//!
//! fn coordinate_packets() -> Result<(), CryptError> {
//!     // Create entropy bank for port scrambling
//!     let bank = EntropyBank::new(1234, 1, Default::default())?;
//!     
//!     // Generate packet vector for sequence 0
//!     let vector = generate_packet_vector(0, 5678, &bank);
//!     
//!     // Access vector properties
//!     println!("Wave ID: {}", vector.wave_id);
//!     println!("Local Port: {}", vector.local_port);
//!     println!("Remote Port: {}", vector.remote_port);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Port assignments are cryptographically scrambled
//! - True sequence numbers are never transmitted
//! - Memory is automatically zeroed on drop
//! - Wave IDs wrap around at u32::MAX
//! - Port ranges must be non-repeating
//!
//! # Related Components
//!
//! - [`EntropyBank`] - Provides port scrambling
//! - [`crate::secure_buffer::sec_packet`] - Packet buffer implementation
//!

use crate::ratchets::entropy_bank::EntropyBank;
use num_integer::Integer;
use zeroize::ZeroizeOnDrop;

/// The `scrambled_sequence` that is returned by `get_packet_coordinates` is scrambled; the true value of the sequence
/// is NOT given, because it is expected that the values be imprinted upon the packet header and thus are public-facing
#[derive(Debug, Default, Clone, ZeroizeOnDrop)]
/// Represents a packet vector with secure sequencing and port mapping information.
pub struct PacketVector {
    /// The group ID of this packet
    pub group_id: u64,
    /// The sequence is the position in the wave ID. Repeating sequences CANNOT exist, and as such,
    /// the entropy_bank generator must ensure all values in the port range are non-repeating.
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

/// Generates a packet vector with secure sequencing and port mapping information.
///
/// # Parameters
///
/// * `true_sequence`: The original true sequence number.
/// * `group_id`: The group ID of the packet.
/// * `entropy_bank`: The entropy bank used for port scrambling.
///
/// # Returns
///
/// A `PacketVector` instance with secure sequencing and port mapping information.
pub fn generate_packet_vector(
    true_sequence: usize,
    group_id: u64,
    entropy_bank: &EntropyBank,
) -> PacketVector {
    // To get the wave_id, we must floor divide the true sequence by the port range. The remainder is the sequence
    let port_range = &entropy_bank.get_multiport_width();
    let (true_wave_id, relative_sequence) = true_sequence.div_mod_floor(port_range);
    // To scramble the true values, we get their corresponding values in the entropy_bank
    let (local_port, remote_port) = *entropy_bank
        .scramble_mappings
        .get(relative_sequence)
        .unwrap();

    PacketVector {
        group_id,
        wave_id: true_wave_id as u32,
        local_port,
        remote_port,
        true_sequence,
    }
}

/// Generates packet coordinates from wave ID, source port, local port, and scramble entropy_bank.
///
/// # Parameters
///
/// * `wave_id`: The wave ID of the packet.
/// * `src_port`: The source port of the packet.
/// * `local_port`: The local port of the packet.
/// * `scramble_entropy_bank`: The entropy bank used for port scrambling.
///
/// # Returns
///
/// The true sequence number if the values are valid, otherwise `None`.
#[inline]
pub fn generate_packet_coordinates_inv(
    wave_id: u32,
    src_port: u16,
    local_port: u16,
    scramble_entropy_bank: &EntropyBank,
) -> Option<usize> {
    for (idx, (in_port, out_port)) in scramble_entropy_bank.scramble_mappings.iter().enumerate() {
        if *in_port == src_port && *out_port == local_port {
            let port_range = scramble_entropy_bank.scramble_mappings.len();
            let true_position = (wave_id as usize * port_range) + idx;
            return Some(true_position);
        }
    }

    None
}
