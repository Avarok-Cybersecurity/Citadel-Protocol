/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use crate::packet_vector::{PacketVector, generate_packet_vector, generate_packet_coordinates_inv};
use crate::misc::{bytes_to_3d_array, CryptError, create_port_mapping};
use byteorder::BigEndian;
use rand::distributions::Distribution;
use rand::{thread_rng, RngCore, Rng};
use std::fmt::Error;
use std::fmt::Formatter;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::convert::TryFrom;
use std::ops::Div;

use bytes::BufMut;
use ez_pqcrypto::{PostQuantumContainer, LARGEST_NONCE_LEN};
use rand::prelude::ThreadRng;

/// Index for the set of data that obscures the port-send-order
pub const PORT_COMBOS_INDEX: usize = 0;
/// Index for the set of data corresponding to C values
pub const C_RAND_INDEX: usize = 1;
/// Index for the set of data corresponding to K values
pub const K_RAND_INDEX: usize = 2;
/// Index for the set of data corresponding to the implicit values within waves
pub const AMPLITUDE_DIFFERENTIALS_KEY_INDEX: usize = 3;
/// Unlike C_RAND and K_RAND values, `DELTA_RAND` helps scramble the array of bytes significantly by adding instead of Xor'ing.
/// This is needed as bytes alone have a small range of [0,255]
pub const DELTA_RAND: usize = 4;
/// Index for the set of data corresponding to the virtual temporal index of any given wave
pub const VIRTUAL_TIME_INDEX: usize = 5;
/// Index for the set of data that is used for applying multiple layers of encryption
pub const E_OF_X_START_INDEX: usize = 6;

/// This should be configured by the server admin, but it is HIGHLY ADVISED NOT TO CHANGE THIS due to possible discrepancies when connecting between HyperVPN's
pub const PORT_RANGE: usize = 14;
/// We limit the number of ports in order. See the explanation for this value within the `byte_count` subroutine of Drill's implementation
pub const MAX_PORT_RANGE: usize = 352;

/// 1*(s*p_r)
pub const BYTES_IN_LOW: usize = E_OF_X_START_INDEX * PORT_RANGE;
/// 2*(s*p_r)
pub const BYTES_IN_MEDIUM: usize = 2 * BYTES_IN_LOW;
/// 4*(s*p_r)
pub const BYTES_IN_HIGH: usize = 2 * BYTES_IN_MEDIUM;
/// 8*(s*p_r)
pub const BYTES_IN_ULTRA: usize = 2 * BYTES_IN_HIGH;
/// 16*(s*p_r)
pub const BYTES_IN_DIVINE: usize = 2 * BYTES_IN_ULTRA;
/// 31*(s*p_r)
//pub const BYTES_PER_3D_ARRAY: usize = 31 * E_OF_X_START_INDEX * PORT_RANGE;
pub const BYTES_PER_3D_ARRAY: usize = 256;

/// The default endianness for byte storage
pub type DrillEndian = BigEndian;

impl Drill {
    /// Creates a new drill
    pub fn new(cid: u64, version: u32, algorithm: EncryptionAlgorithm) -> Result<Self, CryptError<String>> {
        if PORT_RANGE > MAX_PORT_RANGE {
            return Err(CryptError::OutOfBoundsError);
        }

        Self::download_raw_3d_array()
            .map(|bytes| {
                let port_mappings = create_port_mapping();
                

                Drill {
                    algorithm,
                    version,
                    cid,
                    entropy: bytes,
                    scramble_mappings: port_mappings
                }
            })
    }

    /// For generating a random nonce, independent to any drill
    pub fn generate_public_nonce(enx_algorithm: EncryptionAlgorithm) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let mut base: ArrayVec<u8, LARGEST_NONCE_LEN> = Default::default();
        let mut rng = ThreadRng::default();
        let amt = enx_algorithm.nonce_len();
        for _ in 0..amt { base.push(rng.gen()) }
        base
    }

    /// The nonce is 96 bits or 12 bytes in size. We assume each nonce version is unique
    pub fn get_aes_gcm_nonce(&self, nonce_version: usize) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let nonce = self.get_nonce(nonce_version);
        log::trace!(target: "lusna", "Generated nonce v{}: {:?}", nonce_version, &nonce);
        nonce
    }

    #[inline]
    fn get_nonce(&self, nonce_version: usize) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let mut base = Default::default();
        let nonce_len = self.algorithm.nonce_len();
        let f64s_needed = num_integer::Integer::div_ceil(&nonce_len, &8);
        let mut outer_idx = 0;

        for x in 0..f64s_needed {
            let val = ((nonce_version + x) as f64).div(std::f64::consts::PI);
            let bytes = val.to_be_bytes();

            for y in 0..8 {
                if outer_idx == nonce_len {
                    return base;
                }

                base.push(bytes[y].wrapping_add(self.entropy[outer_idx % BYTES_PER_3D_ARRAY]).wrapping_add(nonce_version as u8));

                outer_idx += 1;
            }
        }

        base
    }

    /// Returns the length of the plaintext
    pub fn aes_gcm_encrypt_into<T: AsRef<[u8]>, B: BufMut>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T, output: B) -> Result<usize, CryptError<String>>{
        self.aes_gcm_encrypt_into_custom_nonce(&self.get_aes_gcm_nonce(nonce_version), quantum_container, input, output)
    }

    /// Returns the length of the plaintext
    pub fn aes_gcm_decrypt_into<T: AsRef<[u8]>, B: BufMut>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T, output: B) -> Result<usize, CryptError<String>>{
        self.aes_gcm_decrypt_into_custom_nonce(&self.get_aes_gcm_nonce(nonce_version), quantum_container, input, output)
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt_into_custom_nonce<T: AsRef<[u8]>, B: BufMut>(&self, nonce: &[u8], quantum_container: &PostQuantumContainer, input: T, mut output: B) -> Result<usize, CryptError<String>>{
        quantum_container.encrypt(input.as_ref(), nonce)
            .map(|ciphertext| {
                output.put(ciphertext.as_slice());
                ciphertext.len()
            }).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the length of the plaintext
    pub fn aes_gcm_decrypt_into_custom_nonce<T: AsRef<[u8]>, B: BufMut>(&self, nonce: &[u8], quantum_container: &PostQuantumContainer, input: T, mut output: B) -> Result<usize, CryptError<String>>{
        quantum_container.decrypt(input.as_ref(), nonce)
            .map(|plaintext| {
                output.put(plaintext.as_slice());
                plaintext.len()
            }).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        self.aes_gcm_encrypt_custom_nonce(&self.get_aes_gcm_nonce(nonce_version), quantum_container, input)
    }

    /// Returns the plaintext if successful
    pub fn aes_gcm_decrypt<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        self.aes_gcm_decrypt_custom_nonce(&self.get_aes_gcm_nonce(nonce_version), quantum_container, input)
    }

    /// Returns the new length if successful
    pub fn aes_gcm_decrypt_in_place<T: AsMut<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T) -> Result<usize, CryptError<String>>{
        let nonce = self.get_aes_gcm_nonce(nonce_version);
        quantum_container.decrypt_in_place(input, &nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt_custom_nonce<T: AsRef<[u8]>>(&self, nonce: &[u8], quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        quantum_container.encrypt(input.as_ref(), &nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the plaintext if successful
    pub fn aes_gcm_decrypt_custom_nonce<T: AsRef<[u8]>>(&self, nonce: &[u8], quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        quantum_container.decrypt(input.as_ref(), &nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Protects an already constructed packet in-place. This guarantees that replay attacks cannot happen
    /// Ordered delivery of packets is mandatory
    pub fn protect_packet<T: EzBuffer>(&self, quantum_container: &PostQuantumContainer, header_len_bytes: usize, full_packet: &mut T) -> Result<(), CryptError<String>> {
        let nonce = &self.get_aes_gcm_nonce(0);
        quantum_container.protect_packet_in_place(header_len_bytes, full_packet, nonce).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Unlike `protect_packet`, the returned object does NOT contain the header. The returned Bytes only contains the ciphertext
    pub fn validate_packet_in_place_split<H: AsRef<[u8]>, T: EzBuffer>(&self, quantum_container: &PostQuantumContainer, header: H, payload: &mut T) -> Result<(), CryptError<String>> {
        let nonce = &self.get_aes_gcm_nonce(0);
        let header = header.as_ref();
        quantum_container.validate_packet_in_place(header, payload, nonce).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Gets the packet coordinates
    pub fn generate_packet_coordinates(&self, true_sequence: usize, group_id: u64) -> PacketVector {
        generate_packet_vector(true_sequence, group_id, self)
    }

    /// Returns the multiport width
    pub fn get_multiport_width(&self) -> usize {
        self.scramble_mappings.len()
    }

    /// Determines the index of the packet w.r.t the total encrypted/scrambled data
    pub fn get_packet_coordinate_inv(&self, src_port: u16, recv_port: u16, wave_id: u32) -> Option<usize> {
        generate_packet_coordinates_inv(wave_id, src_port, recv_port, self)
    }
    
    /// Gets the client ID
    pub fn get_cid(&self) -> u64 {
        self.cid
    }

    /// Gets the version of the drill
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /// Downloads the data necessary to create a drill
    fn download_raw_3d_array() -> Result<[u8; BYTES_PER_3D_ARRAY], CryptError<String>> {
            let bytes: &mut [u8; BYTES_PER_3D_ARRAY] = &mut [0; BYTES_PER_3D_ARRAY];
            let mut trng = thread_rng();
            let _ = rand::distributions::Bernoulli::new(0.5)
                .unwrap()
                .sample(&mut trng);
            trng.fill_bytes(bytes);
            let bytes = bytes.to_vec();
            Ok(bytes_to_3d_array(bytes))
    }

    /// Gets randmonized port mappings which contain the true information. Other ports may get bogons
    pub fn get_port_mapping(&self) -> &Vec<(u16, u16)> {
        &self.scramble_mappings
    }

    /// Serializes self to a vector
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, CryptError<String>> {
        bincode2::serialize(self).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }

    /// Deserializes self from a set of bytes
    pub fn deserialize_from<T: AsRef<[u8]>>(drill: T) -> Result<Self, CryptError<String>> {
        bincode2::deserialize(drill.as_ref()).map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }
}

/// Provides the enumeration forall security levels
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum SecurityLevel {
    LOW,
    MEDIUM,
    HIGH,
    ULTRA,
    DIVINE,
    CUSTOM(u8)
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::LOW
    }
}

impl SecurityLevel {
    /// Returns byte representation of self
    pub fn value(self) -> u8 {
        match self {
            SecurityLevel::LOW => 0,
            SecurityLevel::MEDIUM => 1,
            SecurityLevel::HIGH => 2,
            SecurityLevel::ULTRA => 3,
            SecurityLevel::DIVINE => 4,
            SecurityLevel::CUSTOM(val) => val
        }
    }

    /// Possibly returns the security_level given an input value
    pub fn for_value(val: usize) -> Option<Self> {
        Some(SecurityLevel::from(u8::try_from(val).ok()?))
    }
}

impl From<u8> for SecurityLevel {
    fn from(val: u8) -> Self {
        match val {
            0 => SecurityLevel::LOW,
            1 => SecurityLevel::MEDIUM,
            2 => SecurityLevel::HIGH,
            3 => SecurityLevel::ULTRA,
            4 => SecurityLevel::DIVINE,
            n => SecurityLevel::CUSTOM(n)
        }
    }
}


use serde_big_array::BigArray;
use ez_pqcrypto::bytes_in_place::EzBuffer;
use ez_pqcrypto::algorithm_dictionary::EncryptionAlgorithm;
use arrayvec::ArrayVec;

/// A drill is a fundamental encryption dataset that continually morphs into new future sets
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct Drill {
    pub(super) algorithm: EncryptionAlgorithm,
    pub(super) version: u32,
    pub(super) cid: u64,
    #[serde(with = "BigArray")]
    pub(super) entropy: [u8; BYTES_PER_3D_ARRAY],
    pub(super) scramble_mappings: Vec<(u16, u16)>,
}

/// Returns the approximate number of bytes needed to serialize a Drill
pub const fn get_approx_serialized_drill_len() -> usize {
    4 + 8 + BYTES_PER_3D_ARRAY + (PORT_RANGE * 16 * 2)
}

impl Debug for Drill {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        writeln!(
            f,
            "Drill Version: {}\nDrill CID:{}",
            self.get_version(),
            self.get_cid()
        )
    }
}