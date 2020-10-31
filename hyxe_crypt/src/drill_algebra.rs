use crate::drill::{Drill, E_OF_X_START_INDEX, PORT_RANGE};

/// Allows easy manipulation of the algorithms applied to the inner numbers
pub trait Algorithm {
    /// Encrypts a single a single byte into 1 byte
    fn encrypt_u8_to_u8(
        input: u8,
        low_subdrill: &[[u8; PORT_RANGE]; E_OF_X_START_INDEX],
        j_rand: u8,
        get_idx: usize,
    ) -> u8;

    /// Encrypts a single a single byte into 2 bytes
    fn encrypt_u8_to_u16(
        input: u8,
        med_subdrill: &[[u16; PORT_RANGE]; E_OF_X_START_INDEX],
        j_rand: u16,
        get_idx: usize,
    ) -> u16;

    /// Encrypts a single a single byte into 4 bytes
    fn encrypt_u8_to_u32(
        input: u8,
        high_subdrill: &[[u32; PORT_RANGE]; E_OF_X_START_INDEX],
        j_rand: u32,
        get_idx: usize,
    ) -> u32;

    /// Encrypts a single a single byte into 8 bytes
    fn encrypt_u8_to_u64(
        input: u8,
        ultra_subdrill: &[[u64; PORT_RANGE]; E_OF_X_START_INDEX],
        j_rand: u64,
        get_idx: usize,
    ) -> u64;

    /// Encrypts a single a single byte into 16 bytes
    fn encrypt_u8_to_u128(
        input: u8,
        divine_subdrill: &[[u128; PORT_RANGE]; E_OF_X_START_INDEX],
        j_rand: u128,
        get_idx: usize,
    ) -> u128;

    /// Decrypts a singular low-security block
    fn decrypt_1byte_chunk(
        low_subdrill: &[[u8; PORT_RANGE]; E_OF_X_START_INDEX],
        get_idx: usize,
        j_rand: u8,
        encrypted_bytes: &[u8],
    ) -> u8;

    /// Decrypts a singular medium-security block
    fn decrypt_2byte_chunk(
        med_subdrill: &[[u16; PORT_RANGE]; E_OF_X_START_INDEX],
        get_idx: usize,
        j_rand: u16,
        encrypted_bytes: &[u8],
    ) -> u8;

    /// Decrypts a singular high-security block
    fn decrypt_4byte_chunk(
        high_subdrill: &[[u32; PORT_RANGE]; E_OF_X_START_INDEX],
        get_idx: usize,
        j_rand: u32,
        encrypted_bytes: &[u8],
    ) -> u8;

    /// Decrypts a singular ultra-security block
    fn decrypt_8byte_chunk(
        ultra_subdrill: &[[u64; PORT_RANGE]; E_OF_X_START_INDEX],
        get_idx: usize,
        j_rand: u64,
        encrypted_bytes: &[u8],
    ) -> u8;

    /// Decrypts a singular divine-security block
    fn decrypt_16byte_chunk(
        divine_subdrill: &[[u128; PORT_RANGE]; E_OF_X_START_INDEX],
        get_idx: usize,
        j_rand: u128,
        encrypted_bytes: &[u8],
    ) -> u8;

    /// Each algorithm must be mapped to an ID to allow for runtime identification
    fn get_algorithm_id() -> u8;
}

/// A set of possible algorithms
pub mod algorithms {
    use crate::drill::{DrillEndian, C_RAND_INDEX, DELTA_RAND, K_RAND_INDEX, PORT_RANGE, E_OF_X_START_INDEX};
    use crate::drill_algebra::Algorithm;
    use byteorder::ByteOrder;

    /// contains the mapping from name to byte id
    #[allow(non_upper_case_globals)]
    pub mod dictionary {
        /// The standard
        pub const StandardAlgorithm: u8 = 0;
    }

    /// The basic algorithm
    pub struct StandardAlgorithm;

    impl Algorithm for StandardAlgorithm {
        #[inline]
        fn encrypt_u8_to_u8(
            input: u8,
            low_subdrill: &[[u8; PORT_RANGE]; E_OF_X_START_INDEX],
            j_rand: u8,
            get_idx: usize,
        ) -> u8 {
            input.wrapping_add(
                low_subdrill[DELTA_RAND][get_idx]
                    ^ low_subdrill[C_RAND_INDEX][get_idx]
                    ^ low_subdrill[K_RAND_INDEX][get_idx]
                    ^ j_rand,
            )
        }

        #[inline]
        fn encrypt_u8_to_u16(
            input: u8,
            med_subdrill: &[[u16; PORT_RANGE]; E_OF_X_START_INDEX],
            j_rand: u16,
            get_idx: usize,
        ) -> u16 {
            (input as u16).wrapping_add(
                med_subdrill[DELTA_RAND][get_idx]
                    ^ med_subdrill[C_RAND_INDEX][get_idx]
                    ^ med_subdrill[K_RAND_INDEX][get_idx]
                    ^ j_rand,
            )
        }

        #[inline]
        fn encrypt_u8_to_u32(
            input: u8,
            high_subdrill: &[[u32; PORT_RANGE]; E_OF_X_START_INDEX],
            j_rand: u32,
            get_idx: usize,
        ) -> u32 {
            (input as u32).wrapping_add(
                high_subdrill[DELTA_RAND][get_idx]
                    ^ high_subdrill[C_RAND_INDEX][get_idx]
                    ^ high_subdrill[K_RAND_INDEX][get_idx]
                    ^ j_rand,
            )
        }

        #[inline]
        fn encrypt_u8_to_u64(
            input: u8,
            ultra_subdrill: &[[u64; PORT_RANGE]; E_OF_X_START_INDEX],
            j_rand: u64,
            get_idx: usize,
        ) -> u64 {
            (input as u64).wrapping_add(
                ultra_subdrill[DELTA_RAND][get_idx]
                    ^ ultra_subdrill[C_RAND_INDEX][get_idx]
                    ^ ultra_subdrill[K_RAND_INDEX][get_idx]
                    ^ j_rand,
            )
        }

        #[inline]
        fn encrypt_u8_to_u128(
            input: u8,
            divine_subdrill: &[[u128; PORT_RANGE]; E_OF_X_START_INDEX],
            j_rand: u128,
            get_idx: usize,
        ) -> u128 {
            (input as u128).wrapping_add(
                divine_subdrill[DELTA_RAND][get_idx]
                    ^ divine_subdrill[C_RAND_INDEX][get_idx]
                    ^ divine_subdrill[K_RAND_INDEX][get_idx]
                    ^ j_rand,
            )
        }

        #[inline]
        fn decrypt_1byte_chunk(
            low_subdrill: &[[u8; PORT_RANGE]; E_OF_X_START_INDEX],
            get_idx: usize,
            j_rand: u8,
            encrypted_bytes: &[u8],
        ) -> u8 {
            (encrypted_bytes[0]).wrapping_sub(
                j_rand
                    ^ low_subdrill[DELTA_RAND][get_idx]
                    ^ low_subdrill[C_RAND_INDEX][get_idx]
                    ^ low_subdrill[K_RAND_INDEX][get_idx],
            )
        }

        #[inline]
        fn decrypt_2byte_chunk(
            med_subdrill: &[[u16; PORT_RANGE]; E_OF_X_START_INDEX],
            get_idx: usize,
            j_rand: u16,
            encrypted_bytes: &[u8],
        ) -> u8 {
            let true_value = (DrillEndian::read_u16(encrypted_bytes)).wrapping_sub(
                j_rand
                    ^ med_subdrill[DELTA_RAND][get_idx]
                    ^ med_subdrill[C_RAND_INDEX][get_idx]
                    ^ med_subdrill[K_RAND_INDEX][get_idx],
            );
            debug_assert!(true_value < 256);
            true_value as u8
        }

        #[inline]
        fn decrypt_4byte_chunk(
            high_subdrill: &[[u32; PORT_RANGE]; E_OF_X_START_INDEX],
            get_idx: usize,
            j_rand: u32,
            encrypted_bytes: &[u8],
        ) -> u8 {
            let true_value = (DrillEndian::read_u32(encrypted_bytes)).wrapping_sub(
                j_rand
                    ^ high_subdrill[DELTA_RAND][get_idx]
                    ^ high_subdrill[C_RAND_INDEX][get_idx]
                    ^ high_subdrill[K_RAND_INDEX][get_idx],
            );
            debug_assert!(true_value < 256);
            true_value as u8
        }

        #[inline]
        fn decrypt_8byte_chunk(
            ultra_subdrill: &[[u64; PORT_RANGE]; E_OF_X_START_INDEX],
            get_idx: usize,
            j_rand: u64,
            encrypted_bytes: &[u8],
        ) -> u8 {
            let true_value = (DrillEndian::read_u64(encrypted_bytes)).wrapping_sub(
                j_rand
                    ^ ultra_subdrill[DELTA_RAND][get_idx]
                    ^ ultra_subdrill[C_RAND_INDEX][get_idx]
                    ^ ultra_subdrill[K_RAND_INDEX][get_idx],
            );
            debug_assert!(true_value < 256);
            true_value as u8
        }

        #[inline]
        fn decrypt_16byte_chunk(
            divine_subdrill: &[[u128; PORT_RANGE]; E_OF_X_START_INDEX],
            get_idx: usize,
            j_rand: u128,
            encrypted_bytes: &[u8],
        ) -> u8 {
            //let true_value = (DrillEndian::read_u128(encrypted_bytes)).wrapping_sub(j_rand).wrapping_sub(divine_subdrill[DELTA_RAND][get_idx] ^ divine_subdrill[C_RAND_INDEX][get_idx] ^ divine_subdrill[K_RAND_INDEX][get_idx]);
            let true_value = (DrillEndian::read_u128(encrypted_bytes)).wrapping_sub(
                j_rand
                    ^ divine_subdrill[DELTA_RAND][get_idx]
                    ^ divine_subdrill[C_RAND_INDEX][get_idx]
                    ^ divine_subdrill[K_RAND_INDEX][get_idx],
            );
            debug_assert!(true_value < 256);
            true_value as u8
        }

        #[inline]
        fn get_algorithm_id() -> u8 {
            dictionary::StandardAlgorithm
        }
    }
}

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
    let (local_port, remote_port) = *drill.port_mappings.get(relative_sequence).unwrap();

    PacketVector { group_id, wave_id: true_wave_id as u32, local_port, remote_port, true_sequence }
}

/// This will return None if the values are invalid
pub fn generate_packet_coordinates_inv(wave_id: u32, src_port: u16, local_port: u16, drill: &Drill) -> Option<usize> {
    // 1. find the true sequence by running a binary search on the port mapping, scanning for the index
    //println!("Searching for ({}, {})", src_port, local_port);

    for (idx, (in_port, out_port)) in drill.port_mappings.iter().enumerate() {
        if *in_port == src_port && *out_port == local_port {
            let port_range = drill.port_mappings.len();
            let true_position = (wave_id as usize * port_range) + idx;
            return Some(true_position);
        }
    }

    None
}