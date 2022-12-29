use crate::misc::{create_port_mapping, CryptError};
use byteorder::BigEndian;
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::ops::Div;

use citadel_pqcrypto::{PostQuantumContainer, LARGEST_NONCE_LEN};
use rand::prelude::ThreadRng;

/// This should be configured by the server admin, but it is HIGHLY ADVISED NOT TO CHANGE THIS due to possible discrepancies when connecting between HyperVPN's
pub const PORT_RANGE: usize = 14;
pub const BYTES_PER_STORE: usize = 256;

/// The default endianness for byte storage
pub type DrillEndian = BigEndian;

impl EntropyBank {
    /// Creates a new drill
    pub fn new(
        cid: u64,
        version: u32,
        algorithm: EncryptionAlgorithm,
    ) -> Result<Self, CryptError<String>> {
        Self::generate_raw_3d_array().map(|bytes| {
            let port_mappings = create_port_mapping();

            EntropyBank {
                algorithm,
                version,
                cid,
                entropy: bytes,
                scramble_mappings: port_mappings,
            }
        })
    }

    /// For generating a random nonce, independent to any drill
    pub fn generate_public_nonce(
        enx_algorithm: EncryptionAlgorithm,
    ) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let mut base: ArrayVec<u8, LARGEST_NONCE_LEN> = Default::default();
        let mut rng = ThreadRng::default();
        let amt = enx_algorithm.nonce_len();
        for _ in 0..amt {
            base.push(rng.gen())
        }
        base
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

            for byte in bytes {
                if outer_idx == nonce_len {
                    return base;
                }

                base.push(
                    byte.wrapping_add(self.entropy[outer_idx % BYTES_PER_STORE])
                        .wrapping_add(nonce_version as u8),
                );

                outer_idx += 1;
            }
        }

        base
    }

    /// Returns the length of the ciphertext
    pub fn encrypt<T: AsRef<[u8]>>(
        &self,
        nonce_version: usize,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt_custom_nonce(&self.get_nonce(nonce_version), quantum_container, input)
    }

    /// Returns the plaintext if successful
    pub fn decrypt<T: AsRef<[u8]>>(
        &self,
        nonce_version: usize,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt_custom_nonce(&self.get_nonce(nonce_version), quantum_container, input)
    }

    /// Returns the length of the ciphertext
    pub fn encrypt_custom_nonce<T: AsRef<[u8]>>(
        &self,
        nonce: &[u8],
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        quantum_container
            .encrypt(input.as_ref(), nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the plaintext if successful
    pub fn decrypt_custom_nonce<T: AsRef<[u8]>>(
        &self,
        nonce: &[u8],
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        quantum_container
            .decrypt(input.as_ref(), nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Protects an already constructed packet in-place. This guarantees that replay attacks cannot happen
    /// Ordered delivery of packets is mandatory
    pub fn protect_packet<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header_len_bytes: usize,
        full_packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let nonce = &self.get_nonce(0);
        quantum_container
            .protect_packet_in_place(header_len_bytes, full_packet, nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Unlike `protect_packet`, the returned object does NOT contain the header. The returned Bytes only contains the ciphertext
    pub fn validate_packet_in_place_split<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header: H,
        payload: &mut T,
    ) -> Result<(), CryptError<String>> {
        let nonce = &self.get_nonce(0);
        let header = header.as_ref();
        quantum_container
            .validate_packet_in_place(header, payload, nonce)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Returns the multiport width
    pub fn get_multiport_width(&self) -> usize {
        self.scramble_mappings.len()
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
    fn generate_raw_3d_array() -> Result<[u8; BYTES_PER_STORE], CryptError<String>> {
        let mut bytes: [u8; BYTES_PER_STORE] = [0u8; BYTES_PER_STORE];
        let mut trng = thread_rng();
        trng.fill_bytes(&mut bytes);

        Ok(bytes)
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
        bincode2::deserialize(drill.as_ref())
            .map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }
}

/// Provides the enumeration for all security levels
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Default)]
pub enum SecurityLevel {
    #[default]
    Standard,
    Reinforced,
    High,
    Ultra,
    Extreme,
    Custom(u8),
}

impl SecurityLevel {
    /// Returns byte representation of self
    pub fn value(self) -> u8 {
        match self {
            SecurityLevel::Standard => 0,
            SecurityLevel::Reinforced => 1,
            SecurityLevel::High => 2,
            SecurityLevel::Ultra => 3,
            SecurityLevel::Extreme => 4,
            SecurityLevel::Custom(val) => val,
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
            0 => SecurityLevel::Standard,
            1 => SecurityLevel::Reinforced,
            2 => SecurityLevel::High,
            3 => SecurityLevel::Ultra,
            4 => SecurityLevel::Extreme,
            n => SecurityLevel::Custom(n),
        }
    }
}

use arrayvec::ArrayVec;
use citadel_pqcrypto::algorithm_dictionary::EncryptionAlgorithm;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use serde_big_array::BigArray;

/// A entropy bank is a fundamental dataset that continually morphs into new future sets
#[derive(Serialize, Deserialize)]
pub struct EntropyBank {
    pub(super) algorithm: EncryptionAlgorithm,
    pub(super) version: u32,
    pub(super) cid: u64,
    #[serde(with = "BigArray")]
    pub(super) entropy: [u8; BYTES_PER_STORE],
    pub(super) scramble_mappings: Vec<(u16, u16)>,
}

/// Returns the approximate number of bytes needed to serialize a Drill
pub const fn get_approx_serialized_drill_len() -> usize {
    4 + 8 + BYTES_PER_STORE + (PORT_RANGE * 16 * 2)
}

impl Debug for EntropyBank {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        writeln!(
            f,
            "Drill Version: {}\nDrill CID:{}",
            self.get_version(),
            self.get_cid()
        )
    }
}
