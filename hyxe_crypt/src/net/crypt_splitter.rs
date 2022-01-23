use std::collections::HashMap;
use std::ops::Range;
use std::time::{Duration, Instant};

use bitvec::vec::BitVec;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use num_integer::Integer;
use rand::prelude::{SliceRandom, ThreadRng};

use crate::drill::Drill;
use crate::packet_vector::{generate_packet_coordinates_inv, generate_packet_vector, PacketVector};
use crate::prelude::{CryptError, SecurityLevel};
use rayon::prelude::*;
use rayon::iter::IndexedParallelIterator;
use crate::hyper_ratchet::{HyperRatchet, Ratchet};

/// The maximum bytes per group
pub const MAX_BYTES_PER_GROUP: usize = 1024 * 1024 * 10;
///
pub const MAX_WAVEFORM_PACKET_SIZE: usize = 480;

/// The overhead of the GHASH function
pub const AES_GCM_GHASH_OVERHEAD: usize = 16;

/// Returns the max packet size based on security level
pub fn get_max_packet_size(starting_max_packet_size: usize, security_level: SecurityLevel) -> usize {
    const BASE: usize = 2;
    let security_exponent = security_level.value() as u32;
    std::cmp::max(starting_max_packet_size / (BASE.pow(security_exponent)), get_aes_gcm_overhead())
}

pub(crate) const fn get_aes_gcm_overhead() -> usize {
    AES_GCM_GHASH_OVERHEAD
}

/// Calculates the length of the expected ciphertext
pub fn calculate_aes_gcm_output_length(plaintext_length: usize) -> usize {
    get_aes_gcm_overhead() + plaintext_length
}

/// Calculates the expected plaintext length of a ciphertext with ciphertext_length bytes
pub fn calculate_aes_gcm_plaintext_length_from_ciphertext_length(ciphertext_length: usize) -> usize {
    ciphertext_length - get_aes_gcm_overhead()
}

#[inline]
/// The goal of this is to create a unique output for each possible (input1, input2) combo
/// Z x Z = Z, where for all Z in S = {z ...}, all z are unique
///
/// Use Szudzik's function: a >= b ? a * a + a + b : a + b * b;  where a, b >= 0
///
/// a = wave_id, b= group id
pub fn calculate_nonce_version(a: usize, b: u64) -> usize {
    let b = b as usize;
    if a < b {
        a + (b * b)
    } else {
        (a * a) + a + b
    }
}

#[inline]
pub fn generate_scrambler_metadata<T: AsRef<[u8]>>(msg_drill: &Drill, plain_text: T, header_size_bytes: usize, security_level: SecurityLevel, group_id: u64, starting_max_packet_size: usize) -> Result<GroupReceiverConfig, CryptError<String>> {
    let plain_text = plain_text.as_ref();

    if plain_text.len() == 0 {
        return Err(CryptError::Encrypt("Empty input".to_string()))
    }

    let max_packet_payload_size = get_max_packet_size(starting_max_packet_size, security_level);
    let max_packets_per_wave = msg_drill.get_multiport_width();
    let aes_gcm_overhead = get_aes_gcm_overhead();
    // the below accounts for the stretch in size as we map n plaintext bytes to calculate_aes_gcm_output_length(n) bytes
    // Since we run the encryption algorithm once per wave, to get the number of plaintext bytes per wave we need, multiple the above by the max packets per wave and subtract
    let max_plaintext_bytes_per_wave = (max_packet_payload_size * max_packets_per_wave) - aes_gcm_overhead; // We encrypt this many bytes per wave

    // the "number_of_waves" is the number of full waves plus partial waves (max n=1 partial waves)
    let (number_of_full_waves, number_of_partial_waves, bytes_in_last_wave) = if plain_text.len() < max_plaintext_bytes_per_wave {
        let (_, bytes_in_last_wave) = plain_text.len().div_rem(&max_plaintext_bytes_per_wave);
        (0, 1, bytes_in_last_wave)
    } else if plain_text.len() % max_plaintext_bytes_per_wave == 0 {
        // in this case, there will be n full wave, 0 partial waves, thus 1 total wave, and 0 bytes in last wave.
        let number_of_full_waves = plain_text.len() / max_plaintext_bytes_per_wave;
        (number_of_full_waves, 0, max_plaintext_bytes_per_wave)
    } else {
        let (number_of_full_waves, bytes_in_last_wave) = plain_text.len().div_rem(&max_plaintext_bytes_per_wave);
        // since we are not in the == case, and instead are in the > case, there will necessarily be 1 partial wave
        let number_of_partial_waves = 1;
        (number_of_full_waves, number_of_partial_waves, bytes_in_last_wave)
    };

    let number_of_waves = number_of_full_waves + number_of_partial_waves;
    // calculate buffer of last wave. In the case of plain_text.len() == max_plaintext_bytes, we have 1 wave.
    let ciphertext_len_last_wave = if number_of_partial_waves != 0 {
        calculate_aes_gcm_output_length(bytes_in_last_wave)
    } else {
        // this will ensure that the calculation below is adjusted for the equals case
        // Also, adjust the bytes in the last wave. Since there is no partial wave, but n full waves, the last
        // bytes in the last wave is equal to the amount in the full wave. This allows the buffer to be calculated correctly,
        // and at the same time allows the last wave size to be accurate
        0
    };

    let packets_in_last_wave = num_integer::Integer::div_ceil(&ciphertext_len_last_wave, &max_packet_payload_size);

    let (_normal_packets_in_last_wave, mut debug_last_payload_size) = ciphertext_len_last_wave.div_rem(&max_packet_payload_size);
    if debug_last_payload_size == 0 {
        debug_last_payload_size = max_packet_payload_size;
    }

    let packets_needed = if number_of_full_waves != 0 {
        (number_of_full_waves * max_packets_per_wave) + packets_in_last_wave
    } else {
        packets_in_last_wave
    };

    Ok(GroupReceiverConfig::new(group_id as usize, packets_needed, header_size_bytes, plain_text.len(), max_packet_payload_size, debug_last_payload_size, number_of_waves, max_plaintext_bytes_per_wave, bytes_in_last_wave, max_packets_per_wave, packets_in_last_wave))
}

fn get_scramble_encrypt_config<'a, R: Ratchet>(hyper_ratchet: &'a R, plain_text: &'a [u8], header_size_bytes: usize, security_level: SecurityLevel, group_id: u64, starting_max_packet_size: usize) -> Result<(GroupReceiverConfig, &'a Drill, &'a PostQuantumContainer, &'a Drill), CryptError<String>> {
    let (msg_pqc, msg_drill) = hyper_ratchet.message_pqc_drill(None);
    let scramble_drill = hyper_ratchet.get_scramble_drill();
    let cfg = generate_scrambler_metadata(msg_drill, plain_text, header_size_bytes, security_level, group_id, starting_max_packet_size)?;
    Ok((cfg, msg_drill, msg_pqc, scramble_drill))
}

/// Each packet contains an empty array open to inscription of a header coupled with a ciphertext
/// The vector contains the orientation data
#[derive(Clone)]
pub struct PacketCoordinate {
    /// The encrypted packet
    pub packet: BytesMut,
    /// The coordinate data of the packet along the wave
    pub vector: PacketVector,
}

/// header_size_bytes: This size (in bytes) of each packet's header
/// TODO: Handle max_plaintext_bytes_per_wave observed overflow errors. This function is unstable
#[allow(unused_results)]
pub fn scramble_encrypt_group<T: AsRef<[u8]>, R: Ratchet>(plain_text: T, security_level: SecurityLevel, hyper_ratchet: &R, header_size_bytes: usize, target_cid: u64, object_id: u32, group_id: u64, ref header_inscriber: impl Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync) -> Result<GroupSenderDevice<0>, CryptError<String>> {
    let plain_text = plain_text.as_ref();
    let (cfg, msg_drill, msg_pqc, scramble_drill) = get_scramble_encrypt_config(hyper_ratchet, plain_text, header_size_bytes, security_level, group_id, MAX_WAVEFORM_PACKET_SIZE)?;

    let packets = plain_text.chunks(cfg.max_plaintext_wave_length).enumerate().map(|(wave_idx, bytes_to_encrypt_for_this_wave)| {
        scramble_encrypt_wave(wave_idx, bytes_to_encrypt_for_this_wave, &cfg, msg_drill, msg_pqc, scramble_drill, target_cid, object_id, header_size_bytes, header_inscriber)
    }).flatten().collect::<HashMap<usize, PacketCoordinate>>();

    debug_assert_ne!(cfg.last_plaintext_wave_length, 0);
    debug_assert_eq!(cfg.packets_needed, packets.len());
    //let group_receiver_config = GroupReceiverConfig::new(group_id as usize, packets.len(), header_size_bytes, plain_text.len(), max_packet_payload_size, debug_last_payload_size, number_of_waves, max_plaintext_bytes_per_wave, bytes_in_last_wave, max_packets_per_wave, packets_in_last_wave);

    Ok(GroupSenderDevice::<0>::new(cfg, packets))
}

/// header_size_bytes: This size (in bytes) of each packet's header
/// the feed order into the header_inscriber is first the target_cid, and then the object ID
#[allow(unused_results)]
pub fn par_scramble_encrypt_group<T: AsRef<[u8]>, R: Ratchet, F, const N: usize>(plain_text: T, security_level: SecurityLevel, hyper_ratchet: &R, header_size_bytes: usize, target_cid: u64, object_id: u32, group_id: u64, ref header_inscriber: F) -> Result<GroupSenderDevice<N>, CryptError<String>>
    where F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync {
    let plain_text = plain_text.as_ref();
    let (cfg, msg_drill, msg_pqc, scramble_drill) = get_scramble_encrypt_config(hyper_ratchet, plain_text, header_size_bytes, security_level, group_id, 1024*8)?;

    let packets = plain_text.par_chunks(cfg.max_plaintext_wave_length).enumerate().map(|(wave_idx, bytes_to_encrypt_for_this_wave)| {
        scramble_encrypt_wave(wave_idx, bytes_to_encrypt_for_this_wave, &cfg, msg_drill, msg_pqc, scramble_drill, target_cid, object_id, header_size_bytes, header_inscriber)
    }).flatten().collect::<HashMap<usize, PacketCoordinate>>();

    debug_assert_ne!(cfg.last_plaintext_wave_length, 0);
    debug_assert_eq!(cfg.packets_needed, packets.len());
    //let group_receiver_config = GroupReceiverConfig::new(group_id as usize, packets.len(), header_size_bytes, plain_text.len(), max_packet_payload_size, debug_last_payload_size, number_of_waves, max_plaintext_bytes_per_wave, bytes_in_last_wave, max_packets_per_wave, packets_in_last_wave);

    Ok(GroupSenderDevice::new(cfg, packets))
}

#[inline(always)]
fn scramble_encrypt_wave(wave_idx: usize, bytes_to_encrypt_for_this_wave: &[u8], cfg: &GroupReceiverConfig, msg_drill: &Drill, msg_pqc: &PostQuantumContainer, scramble_drill: &Drill, target_cid: u64, object_id: u32, header_size_bytes: usize, header_inscriber: impl Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync) -> Vec<(usize, PacketCoordinate)> {
    let mut packets = msg_drill.aes_gcm_encrypt(calculate_nonce_version(wave_idx, cfg.group_id as u64), msg_pqc, bytes_to_encrypt_for_this_wave).unwrap()
        .chunks(cfg.max_payload_size).enumerate().map(|(relative_packet_idx, ciphertext_packet_bytes)| {
        debug_assert_ne!(ciphertext_packet_bytes.len(), 0);
        let mut packet = BytesMut::with_capacity(ciphertext_packet_bytes.len() + header_size_bytes);
        let true_packet_sequence = (wave_idx * cfg.max_packets_per_wave) + relative_packet_idx;
        let vector = generate_packet_vector(true_packet_sequence, cfg.group_id as u64, scramble_drill);
        header_inscriber(&vector, scramble_drill, object_id, target_cid, &mut packet);
        packet.put(ciphertext_packet_bytes);
        (true_packet_sequence, PacketCoordinate { packet, vector })
    }).collect::<Vec<(usize, PacketCoordinate)>>();
    packets.shuffle(&mut ThreadRng::default());
    packets
}

/// header_size_bytes: This size (in bytes) of each packet's header
/// the feed order into the header_inscriber is first the target_cid, and then the object ID
#[allow(unused_results)]
pub fn encrypt_group_unified<T: AsRef<[u8]>, R: Ratchet>(plain_text: T, hyper_ratchet: &R, header_size_bytes: usize, target_cid: u64, object_id: u32, group_id: u64, header_inscriber: impl Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync) -> Result<GroupSenderDevice<0>, CryptError<String>> {
    let (msg_pqc, msg_drill) = hyper_ratchet.message_pqc_drill(None);
    let scramble_drill = hyper_ratchet.get_scramble_drill();

    let plaintext = plain_text.as_ref();
    let output_len = calculate_aes_gcm_output_length(plaintext.len());
    let mut packet = BytesMut::with_capacity(header_size_bytes + output_len);
    let vector_singleton = generate_packet_vector(0, group_id, scramble_drill);
    header_inscriber(&vector_singleton, scramble_drill, object_id, target_cid, &mut packet);
    let _ = msg_drill.aes_gcm_encrypt_into(calculate_nonce_version(0, group_id), msg_pqc, plaintext, &mut packet)?;
    let coord = PacketCoordinate { vector: vector_singleton, packet };
    let group_receiver_config = GroupReceiverConfig::new(group_id as usize, 1, header_size_bytes, plaintext.len(), output_len, output_len, 1, plaintext.len(), plaintext.len(), 1, 1);
    let mut packets = HashMap::with_capacity(1);
    packets.insert(0, coord);
    Ok(GroupSenderDevice::new(group_receiver_config, packets))
}

/// Used for sending a packet that is expected to already be encrypted
pub fn oneshot_unencrypted_group_unified<const N: usize>(plain_text: SecureMessagePacket<N>, header_size_bytes: usize, group_id: u64) -> Result<GroupSenderDevice<N>, CryptError<String>> {
    let len = plain_text.message_len();
    let group_receiver_config = GroupReceiverConfig::new(group_id as usize, 1, header_size_bytes, len, len, len, 1, len, len, 1, 1);
    Ok(GroupSenderDevice::<N>::new_oneshot(group_receiver_config, plain_text))
}

/// Return statuses for the GroupReceiver
#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum GroupReceiverStatus {
    /// The entirety of the group as been received. Returns the last wave finished to allow sending a WAVE_ACK. Finalize() is ready to call
    GROUP_COMPLETE(u32),
    /// Packet is invalid
    INVALID_PACKET,
    /// already received
    ALREADY_RECEIVED,
    /// Valid packet
    INSERT_SUCCESS,
    /// Corrupt
    CORRUPT_WAVE,
    /// Wave is complete
    WAVE_COMPLETE(u32),
    /// A set of true_sequences that need retransmission
    NEEDS_RETRANSMISSION(u32),
}

/// A device used for reconstructing Groups. It is meant for the receiving end. For receiver ends, the use
/// is as expected: to reconstruct the packet
#[allow(dead_code)]
pub struct GroupReceiver {
    unified_plaintext_slab: Vec<u8>,
    /// Since each wave is differentially encrypted, we must store each wave separately. Once the wave's ciphertext is laid out in order, then we decrypt it into the unified plaintext slab above into the correct position
    temp_wave_store: HashMap<usize, TempWaveStore>,
    packets_received_order: BitVec,
    waves_received: BitVec,
    packets_needed: usize,
    last_packet_recv_time: Instant,
    max_payload_size: usize,
    /// All packets will necessarily be the same size, except for the last packet (although, it is possible for it to be the same size)
    last_payload_size: usize,
    max_packets_per_wave: usize,
    max_plaintext_wave_length: usize,
    last_plaintext_wave_length: usize,
    wave_count: usize,
    lowest_sequential_wave_completed: isize,
    last_complete_wave: isize,
    group_timeout: Duration,
    wave_timeout: Duration,
}

use serde::{Serialize, Deserialize};
use ez_pqcrypto::PostQuantumContainer;
use crate::secure_buffer::sec_packet::SecureMessagePacket;

/// For containing the data needed to receive a corresponding group
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
#[allow(missing_docs)]
pub struct GroupReceiverConfig {
    pub packets_needed: usize,
    pub max_packets_per_wave: usize,
    pub plaintext_length: usize,
    pub max_payload_size: usize,
    pub last_payload_size: usize,
    pub wave_count: usize,
    pub max_plaintext_wave_length: usize,
    pub last_plaintext_wave_length: usize,
    pub packets_in_last_wave: usize,
    // this is NOT inscribed; only for transmission
    pub header_size_bytes: usize,
    pub group_id: usize,
}

/// Used in hyxe_net
pub const GROUP_RECEIVER_INSCRIBE_LEN: usize = 72;

impl GroupReceiverConfig {
    /// Creates a new container for the set of variables
    pub fn new(group_id: usize, packets_needed: usize, header_size_bytes: usize, plaintext_length: usize, max_payload_size: usize, last_payload_size: usize, wave_count: usize, max_plaintext_wave_length: usize, last_plaintext_wave_length: usize, max_packets_per_wave: usize, packets_in_last_wave: usize) -> Self {
        Self { group_id, packets_needed, header_size_bytes, plaintext_length, max_payload_size, last_payload_size, wave_count, max_plaintext_wave_length, last_plaintext_wave_length, max_packets_per_wave, packets_in_last_wave }
    }

    /// Returns None if the input length is not equal to GROUP_RECEIVER_INSCRIBE_LEN
    pub fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Option<Self> {
        let input = input.as_ref();
        if input.len() != GROUP_RECEIVER_INSCRIBE_LEN {
            return None;
        }

        let mut reader = input.reader();

        let packets_needed = reader.read_u64::<BigEndian>().ok()? as usize;
        let max_packets_per_wave = reader.read_u64::<BigEndian>().ok()? as usize;
        let plaintext_length = reader.read_u64::<BigEndian>().ok()? as usize;
        let max_payload_size = reader.read_u64::<BigEndian>().ok()? as usize;
        let last_payload_size = reader.read_u64::<BigEndian>().ok()? as usize;
        let wave_count = reader.read_u64::<BigEndian>().ok()? as usize;
        let max_plaintext_wave_length = reader.read_u64::<BigEndian>().ok()? as usize;
        let last_plaintext_wave_length = reader.read_u64::<BigEndian>().ok()? as usize;
        let packets_in_last_wave = reader.read_u64::<BigEndian>().ok()? as usize;

        Some(Self { packets_in_last_wave, group_id: 0, header_size_bytes: 0, packets_needed, plaintext_length, max_payload_size, last_payload_size, wave_count, max_plaintext_wave_length, last_plaintext_wave_length, max_packets_per_wave })
    }

    /// Inscribes the configuration into a buffer. This should be inscribed into the payload of a group-header
    pub fn inscribe_into<B: BufMut>(&self, mut packet: B) {
        packet.put_u64(self.packets_needed as u64);
        packet.put_u64(self.max_packets_per_wave as u64);
        packet.put_u64(self.plaintext_length as u64);
        packet.put_u64(self.max_payload_size as u64);
        packet.put_u64(self.last_payload_size as u64);
        packet.put_u64(self.wave_count as u64);
        packet.put_u64(self.max_plaintext_wave_length as u64);
        packet.put_u64(self.last_plaintext_wave_length as u64);
        packet.put_u64(self.packets_in_last_wave as u64);
    }

    /// Returns the number of packets in a given wave by id. TODO: Clean this up
    /// this works for edge-cases, and all cases, but shouldn't be used in the future
    /// unless absolutely necessary
    pub fn get_packet_count_in_wave(&self, wave_id: usize) -> usize {
        if wave_id == self.wave_count - 1 {
            self.packets_in_last_wave
            /*if wave_id != 0 {
                //self.packets_in_last_wave
                if self.packets_needed % self.max_packets_per_wave != 0 {
                    self.packets_needed % self.max_packets_per_wave
                } else {
                    self.get_packet_count_in_wave(wave_id - 1)
                }
            } else {
                self.packets_needed
            }*/
        } else {
            self.max_packets_per_wave
        }
    }
}

struct TempWaveStore {
    packets_received: usize,
    packets_in_wave: usize,
    #[allow(dead_code)]
    last_packet_recv_time: Option<Instant>,
    ciphertext_buffer: Vec<u8>,
}

impl GroupReceiver {
    /// Creates a new GroupReconstructor for a receiving end.
    ///
    /// The max_payload_size does not account for the packet's header
    ///
    /// The drill is needed in order to get the multiport width (determines max packets per wave)
    #[allow(unused_results)]
    pub fn new(ref cfg: GroupReceiverConfig, wave_timeout_ms: usize, group_timeout_ms: usize) -> Self {
        log::trace!("Creating new group receiver. Anticipated plaintext slab length: {}", cfg.plaintext_length);
        let unified_plaintext_slab = vec![0u8; cfg.plaintext_length];
        let packets_received_order = bitvec::bitvec![0; cfg.packets_needed];
        let waves_received = bitvec::bitvec![0; cfg.wave_count];
        let mut temp_wave_store = HashMap::with_capacity(cfg.wave_count);
        let last_packet_recv_time = Instant::now();
        let max_packets_per_wave = cfg.max_packets_per_wave;
        let group_timeout = Duration::from_millis(group_timeout_ms as u64);
        let wave_timeout = Duration::from_millis(wave_timeout_ms as u64);
        let last_complete_wave = -1;
        let lowest_sequential_wave_completed = -1;

        for wave_id_cur in 0..cfg.wave_count {
            let (ciphertext_buffer_alloc_size_for_single_wave, packets_in_wave) = if wave_id_cur == cfg.wave_count - 1 {
                // The last wave requires a different buffer size
                //let packets_in_last_wave = cfg.packets_needed % max_packets_per_wave;
                let packets_in_last_wave = cfg.get_packet_count_in_wave(wave_id_cur);
                // if packets in last wave is zero, the only amount in the ciphertext buffer alloc is last_payload_size
                // normal packet count is the count of "normally-sized" packets in the wave. All packets are the same size except the last one,
                // unless the data splits evenly
                let normal_packet_count = packets_in_last_wave.saturating_sub(1);
                ((normal_packet_count * cfg.max_payload_size) + cfg.last_payload_size, packets_in_last_wave)
            } else {
                (cfg.max_payload_size * max_packets_per_wave, max_packets_per_wave)
            };

            let last_packet_recv_time = if wave_id_cur == 0 {
                // the first needs a time
                Some(Instant::now())
            } else {
                None
            };
            let ciphertext_buffer = vec![0u8; ciphertext_buffer_alloc_size_for_single_wave];
            let tmp_wave_store_container = TempWaveStore { packets_received: 0, packets_in_wave, last_packet_recv_time, ciphertext_buffer };
            temp_wave_store.insert(wave_id_cur, tmp_wave_store_container);
        }

        Self { lowest_sequential_wave_completed, waves_received, last_complete_wave, wave_timeout, group_timeout, unified_plaintext_slab, temp_wave_store, packets_received_order, packets_needed: cfg.packets_needed, last_packet_recv_time, max_payload_size: cfg.max_payload_size, last_payload_size: cfg.last_payload_size, max_packets_per_wave, wave_count: cfg.wave_count, max_plaintext_wave_length: cfg.max_plaintext_wave_length, last_plaintext_wave_length: cfg.last_plaintext_wave_length }
    }

    /// If a wave is complete, it gets decrypted and placed into the plaintext buffer
    pub fn on_packet_received<T: AsRef<[u8]>, R: Ratchet>(&mut self, group_id: u64, true_sequence: usize, wave_id: u32, hyper_ratchet: &R, packet: T) -> GroupReceiverStatus {
        let packet = packet.as_ref();
        // The wave_id is also the nonce_version

        // this protects against replay attacks too
        let is_received = if let Some(mut is_received) = self.packets_received_order.get_mut(true_sequence) {
            let is_recv = *is_received;
            if !*is_received {
                *is_received = true;
            }

            is_recv
        } else {
            return GroupReceiverStatus::INVALID_PACKET;
        };

        if !is_received {
            // Now, take the ciphertext and place it into the buffer
            let wave_store = self.temp_wave_store.get_mut(&(wave_id as usize));

            if wave_store.is_none() {
                log::info!("Packet {} (Parent wave: {}) does not have a wave store", true_sequence, wave_id);
                return GroupReceiverStatus::INVALID_PACKET;
            }

            let wave_store = wave_store.unwrap();

            let insert_index = Self::get_ciphertext_insertion_range(true_sequence, self.max_packets_per_wave, self.packets_needed, self.last_payload_size, self.max_payload_size, wave_store);
            let dest_bytes = &mut wave_store.ciphertext_buffer[insert_index.clone()];
            //let packet_bytes = packet.bytes();
            let packet_bytes = packet;

            debug_assert_eq!(packet_bytes.len(), dest_bytes.len());

            for (idx, dest_byte) in dest_bytes.iter_mut().enumerate() {
                *dest_byte = packet_bytes[idx];
            }


            wave_store.packets_received += 1;
            wave_store.last_packet_recv_time = Some(Instant::now());
            self.packets_received_order.set(true_sequence, true);

            if wave_store.packets_received == wave_store.packets_in_wave {
                let ciphertext_bytes_for_this_wave = &wave_store.ciphertext_buffer[..];
                let (msg_pqc, msg_drill) = hyper_ratchet.message_pqc_drill(None);

                match msg_drill.aes_gcm_decrypt(calculate_nonce_version(wave_id as usize, group_id), msg_pqc, ciphertext_bytes_for_this_wave) {
                    Ok(plaintext) => {
                        let plaintext = plaintext.as_slice();

                        let plaintext_insert_index = Self::get_plaintext_buffer_insertion_range_by_wave_id(wave_id, ciphertext_bytes_for_this_wave.len(), self.max_plaintext_wave_length);
                        let dest_bytes = &mut self.unified_plaintext_slab[plaintext_insert_index.clone()];
                        debug_assert_eq!(plaintext_insert_index.end - plaintext_insert_index.start, dest_bytes.len());
                        dest_bytes.copy_from_slice(plaintext);

                        // Free the memory
                        assert!(self.temp_wave_store.remove(&(wave_id as usize)).is_some());

                        if self.temp_wave_store.is_empty() {
                            // We are entirely done! Return the bytes
                            GroupReceiverStatus::GROUP_COMPLETE(wave_id)
                        } else {
                            // Now, set the next wave's timer so that it may potentially time-out
                            if let Some(next_wave) = self.temp_wave_store.get_mut(&(wave_id as usize + 1)) {
                                next_wave.last_packet_recv_time = Some(Instant::now());
                            }

                            if wave_id as isize - 1 == self.lowest_sequential_wave_completed {
                                self.lowest_sequential_wave_completed = wave_id as isize;
                            }

                            self.waves_received.set(wave_id as usize, true);
                            // Should send a WAVE_ACK to send to the transmitter, thatway the transmitter can free memory on its end
                            self.last_complete_wave = wave_id as isize;
                            GroupReceiverStatus::WAVE_COMPLETE(wave_id)
                        }
                    }

                    Err(err) => {
                        log::error!("Unable to decrypt wave {}. Reason: {}", wave_id, err.into_string());
                        GroupReceiverStatus::CORRUPT_WAVE
                    }
                }
            } else {
                self.last_packet_recv_time = Instant::now();
                GroupReceiverStatus::INSERT_SUCCESS
            }
        } else {
            log::info!("Packet {} (Parent Wave: {}) already received", true_sequence, wave_id);
            GroupReceiverStatus::ALREADY_RECEIVED
        }
    }

    /// Sometimes when sending multiple waves, a wave k > n may arrive first. This will return all c < k that have not yet arrived
    pub fn get_missing_waves(&self) -> Option<Vec<u32>> {
        if self.lowest_sequential_wave_completed < 0 {
            return None;
        }
        let range = self.lowest_sequential_wave_completed as usize..self.last_complete_wave as usize;
        let offset = range.start;

        let subset = &self.waves_received.as_bitslice()[range];

        let ret = subset.iter().enumerate().filter_map(|(wave_id, finished)| {
            if !*finished {
                Some((offset + wave_id) as u32)
            } else {
                None
            }
        }).collect::<Vec<u32>>();

        if !ret.is_empty() {
            Some(ret)
        } else {
            None
        }
    }

    #[inline]
    /// Returns the number of missing packets in the given wave
    ///
    /// Note: It is possible that the wave_id searched for no longer exists (if the wave finished, its assembly memory buffer is freed).
    /// Thus, we return an option
    pub fn get_missing_count_in_wave(&self, wave_id: u32) -> Option<usize> {
        debug_assert!(wave_id < self.wave_count as u32);
        let wave_store = self.temp_wave_store.get(&(wave_id as usize))?;
        Some(wave_store.packets_in_wave - wave_store.packets_received)
    }

    /// Returns a set of vectors that need to be retransmitted
    pub fn get_retransmission_vectors_for<R: Ratchet>(&self, wave_id: u32, group_id: u64, hyper_ratchet: &R) -> Option<Vec<PacketVector>> {
        //println!("Getting retransmission vectors for {} ofr group {}", wave_id, group_id);
        let drill = hyper_ratchet.get_scramble_drill();
        let wave_store = self.temp_wave_store.get(&(wave_id as usize))?;
        let packets_missing = wave_store.packets_in_wave - wave_store.packets_received;
        //println!("Packets missing: {}", packets_missing);
        // Are there packets missing?
        if packets_missing != 0 {
            /*
            if wave_store.last_packet_recv_time.is_none() {
                return None;
            }*/
            // Are the packets missing and haven't received one for awhile?
            //if wave_store.last_packet_recv_time.as_ref().unwrap().elapsed() > self.wave_timeout {
            // This means packets are missing and we timed-out...
            let offset = self.max_packets_per_wave * (wave_id as usize);
            let end_idx = offset + wave_store.packets_in_wave;

            let subset = &self.packets_received_order.as_bitslice()[offset..end_idx];
            let packets_missing_vec = subset.iter().enumerate().filter_map(|(relative_idx, val)| {
                if !*val {
                    let true_sequence = offset + relative_idx;
                    Some(generate_packet_vector(true_sequence, group_id, drill))
                } else {
                    None
                }
            }).collect::<Vec<PacketVector>>();

            debug_assert_eq!(packets_missing_vec.len(), packets_missing);

            Some(packets_missing_vec)
            //} else {
            //  None
            //}
        } else {
            None
        }
    }
    /// Consumes self. Do not call this unless you received a valid status from on_receive_packet
    pub fn finalize(self) -> Vec<u8> {
        self.unified_plaintext_slab
    }

    fn get_ciphertext_insertion_range(true_sequence: usize, max_packets_per_wave: usize, packets_needed: usize, last_payload_size: usize, max_payload_size: usize, store: &TempWaveStore) -> Range<usize> {
        let packet_idx_relative_to_wave = true_sequence % max_packets_per_wave;
        if true_sequence == packets_needed - 1 {
            // This packet is the very last one
            let len = store.ciphertext_buffer.capacity();
            let start_idx = len - last_payload_size;
            let end_idx = len;
            //println!("(LAST) Getting {}..{}", start_idx, end_idx);
            start_idx..end_idx
        } else {
            let start_idx = max_payload_size * packet_idx_relative_to_wave;
            let end_idx = max_payload_size + start_idx;
            //println!("Getting {}..{}", start_idx, end_idx);
            start_idx..end_idx
        }
    }

    fn get_plaintext_buffer_insertion_range_by_wave_id(wave_id: u32, ciphertext_wave_length: usize, max_plaintext_wave_length: usize) -> Range<usize> {
        let plaintext_length = calculate_aes_gcm_plaintext_length_from_ciphertext_length(ciphertext_wave_length);
        let start_idx = wave_id as usize * max_plaintext_wave_length;
        let end_idx = start_idx + plaintext_length;
        start_idx..end_idx
    }

    /// Returns the number of waves expected to receive
    pub fn get_wave_count(&self) -> usize {
        self.wave_count
    }

    /// Returns None if the last wave is < 0
    pub fn get_last_complete_wave(&self) -> Option<u32> {
        let last = self.last_complete_wave;
        if last < 0 {
            None
        } else {
            Some(last as u32)
        }
    }

    /// Unlike checking each indvidual wave, this checks to see if the group as a whole expired
    pub fn has_expired(&self, timeout: Duration) -> bool {
        self.last_packet_recv_time.elapsed() > timeout
    }
}

/// The networking protocol should use this container to keep track of when transmitted packets are sent successfully
pub struct GroupSenderDevice<const N: usize> {
    /// the hashmap of packets
    pub packets_in_ram: HashMap<usize, PacketCoordinate>,
    oneshot: Option<SecureMessagePacket<N>>,
    packets_received: usize,
    packets_sent: usize,
    receiver_config: GroupReceiverConfig,
    last_wave_ack_received: Instant,
}

impl<const N: usize> GroupSenderDevice<N> {
    /// Before any packets are sent out, this should be called
    pub fn new(receiver_config: GroupReceiverConfig, packets_in_ram: HashMap<usize, PacketCoordinate>) -> Self {
        Self { packets_in_ram, packets_received: 0, packets_sent: 0, receiver_config, oneshot: None, last_wave_ack_received: Instant::now() }
    }

    /// Intended for unencrypted packets
    pub fn new_oneshot(receiver_config: GroupReceiverConfig, oneshot: SecureMessagePacket<N>) -> Self {
        Self { packets_in_ram: HashMap::with_capacity(0), oneshot: Some(oneshot), packets_received: 0, packets_sent: 0, receiver_config, last_wave_ack_received: Instant::now()}
    }

    /// In the case of file-sending, it is beneficial to know when this group is 50% done sending, that way
    /// the next groups can be enqueued
    ///
    /// old value: 1.2f32 (seemed pretty stable)
    pub fn is_atleast_fifty_percent_done(&self) -> bool {
        self.packets_received as f32 * 1.5f32 >= self.receiver_config.packets_needed as f32
    }

    /// Before a packet is sent, this should be called. Returns None when all the packets were sent.
    ///
    /// This sends wave by wave. It is up to the higher-level caller to send WAVE_TAILS as needed
    pub fn get_next_packet(&mut self) -> Option<PacketCoordinate> {
        if self.packets_sent != self.receiver_config.packets_needed {
            // We clone the packet's Bytes and Coordinate here, but not the bytes of the data itself (performs an Arc clone)
            let next_packet = self.packets_in_ram.get(&self.packets_sent).cloned();
            self.packets_sent += 1;
            next_packet
        } else {
            None
        }
    }

    /// Takes the oneshot packet
    pub fn get_oneshot(&mut self) -> Option<SecureMessagePacket<N>> {
        self.oneshot.take()
    }

    /// Frees the RAM internally. Returns true if the entire group is complete
    #[allow(unused_results)]
    pub fn on_wave_tail_ack_received(&mut self, wave_id: u32) -> bool {
        let offset = self.receiver_config.max_packets_per_wave * (wave_id as usize);
        let packets_in_this_wave = self.get_packets_in_wave(wave_id);

        let end = offset + packets_in_this_wave;

        log::info!("Wave tail received for wave {}. Removing entries from {} to {}", wave_id, offset, end);

        for idx in offset..end {
            self.packets_in_ram.remove(&idx);
        }

        self.last_wave_ack_received = Instant::now();
        self.packets_received += packets_in_this_wave;
        self.packets_received == self.receiver_config.packets_needed
    }

    /// This node is the sender, Alice. Bob timed out for a certain wave, and now is requesting a set of packets
    pub fn on_do_wave_retransmission_received(&self, hyper_ratchet: &HyperRatchet, wave_id: u32, payload: &[u8]) -> Option<Vec<PacketCoordinate>> {
        // use the scramble ordering
        let scramble_drill = hyper_ratchet.get_scramble_drill();

        let (missing_packet_count, rem) = payload.len().div_rem(&4);

        if missing_packet_count == 0 || rem != 0 {
            return None;
        }

        let start_idx = (wave_id as usize) * self.receiver_config.max_packets_per_wave;
        let packets_in_wave = self.get_packets_in_wave(wave_id);
        let end_idx = start_idx + packets_in_wave;

        let mut missing_coords = Vec::with_capacity(missing_packet_count);
        //let payload = drill.decrypt_to_vec(payload, 0, SecurityLevel::LOW).ok()?;

        let mut cursor = std::io::Cursor::new(payload);

        for _ in 0..missing_packet_count {
            let src_port = cursor.read_u16::<BigEndian>().ok()?;
            let remote_port = cursor.read_u16::<BigEndian>().ok()?;
            //log::info!("Obtained src/remote port: {} -> {}", src_port, remote_port);
            // The below line ensures that the provided coordinate is valid
            let _vector = generate_packet_coordinates_inv(wave_id, src_port, remote_port, scramble_drill)?;

            let start_count = missing_coords.len();
            'cur_wave: for idx in start_idx..end_idx {
                let coord = self.packets_in_ram.get(&idx)?;
                if coord.vector.wave_id != wave_id {
                    // Could mean the wave has already been cleared by a WAVE_TAIL received
                    return None;
                }

                if coord.vector.local_port == src_port && coord.vector.remote_port == remote_port {
                    missing_coords.push(coord.clone());
                    // Exit the for loop
                    break 'cur_wave;
                }
            }

            if missing_coords.len() == start_count {
                log::error!("Possibly invalid src/dest port combo listed");
                return None;
            }
        }

        Some(missing_coords)
    }

    /// Gets a range of packets. Returns None if the count obtained is not equal to the count requested
    pub fn get_next_packets(&mut self, count: usize) -> Option<Vec<PacketCoordinate>> {
        let start = self.packets_sent;
        let end = start + count;
        let items = (start..end).into_iter().map(|idx| self.packets_in_ram.get(&idx).cloned())
            .filter_map(|res| res).collect::<Vec<PacketCoordinate>>();
        if items.len() != count {
            None
        } else {
            Some(items)
        }
    }

    /// clones the receiver config
    pub fn get_receiver_config(&self) -> GroupReceiverConfig {
        self.receiver_config.clone()
    }

    /// Inscribes the receiver config into a packet. Treats all the values as if they were u64's
    pub fn inscribe_receiver_config_into<B: BufMut>(&self, packet: B) {
        self.receiver_config.inscribe_into(packet)
    }

    /// Returns the number of packets sent (but NOT necessarily received!)
    pub fn get_packets_sent(&self) -> usize {
        self.packets_sent
    }

    /// Returns the number of packets which were successfully received
    pub fn get_packets_received(&self) -> usize {
        self.packets_received
    }

    /// Gets the proper number of packets in the wave
    pub fn get_packets_in_wave(&self, wave_id: u32) -> usize {
        debug_assert!(wave_id < self.receiver_config.wave_count as u32);
        if wave_id == self.receiver_config.wave_count as u32 - 1 {
            self.receiver_config.packets_in_last_wave
            /*if wave_id != 0 {
                //self.packets_in_last_wave
                if self.receiver_config.packets_needed % self.receiver_config.max_packets_per_wave != 0 {
                    self.receiver_config.packets_needed % self.receiver_config.max_packets_per_wave
                } else {
                    self.get_packets_in_wave(wave_id - 1)
                }
            } else {
                self.receiver_config.packets_needed
            }*/
        } else {
            self.receiver_config.max_packets_per_wave
        }
    }

    /// Since the protocol blasts packets, wave by wave, without waiting for confirmation of wave A before sending wave B,
    /// we need to define a timeout that completely halts the sending of packets if a WAVE_ACK is not received by a certain deadline
    pub fn has_expired(&self, timeout: Duration) -> bool {
        self.last_wave_ack_received.elapsed() > timeout
    }
}