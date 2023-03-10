use crate::misc::{create_port_mapping, CryptError};
use byteorder::{BigEndian, ByteOrder};
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::sync::atomic::{AtomicU64, Ordering};

use citadel_pqcrypto::{PostQuantumContainer, LARGEST_NONCE_LEN};
use rand::prelude::ThreadRng;

pub const PORT_RANGE: usize = 14;
pub const BYTES_PER_STORE: usize = LARGEST_NONCE_LEN;

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
            let transient_counter = Default::default();
            EntropyBank {
                algorithm,
                version,
                cid,
                entropy: bytes,
                scramble_mappings: port_mappings,
                transient_counter,
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
    // the nonce_version should come from either the transient counter, or,
    // the appended u32 at the end of each packet
    fn get_nonce(&self, nonce_version: u64) -> ArrayVec<u8, LARGEST_NONCE_LEN> {
        let mut symmetric_entropy = Vec::with_capacity(self.entropy.len() + 8);
        symmetric_entropy.extend_from_slice(&self.entropy);
        symmetric_entropy.put_u64(nonce_version);

        let mut hasher = sha3::Sha3_256::default();
        hasher.update(symmetric_entropy);
        let out: [u8; LARGEST_NONCE_LEN] = hasher.finalize().into();
        out.into()
    }

    /// Returns the ciphertext
    pub fn encrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_enx_vec(input, move |input, nonce| {
            quantum_container
                .encrypt(input, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Returns the plaintext if successful
    pub fn decrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        input: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_dex_vec(input, move |input, nonce| {
            quantum_container
                .decrypt(input, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Protects an already constructed packet in-place. This guarantees that replay attacks cannot happen
    /// Ordered delivery of packets is mandatory
    pub fn protect_packet<T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header_len_bytes: usize,
        full_packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.wrap_with_unique_nonce_enx(full_packet, move |full_packet, nonce| {
            quantum_container
                .protect_packet_in_place(header_len_bytes, full_packet, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    /// Unlike `protect_packet`, the returned object does NOT contain the header. The returned Bytes only contains the ciphertext
    pub fn validate_packet_in_place_split<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        quantum_container: &PostQuantumContainer,
        header: H,
        payload: &mut T,
    ) -> Result<(), CryptError<String>> {
        let header = header.as_ref();
        self.wrap_with_unique_nonce_dex(payload, move |payload, nonce| {
            quantum_container
                .validate_packet_in_place(header, payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    fn wrap_with_unique_nonce_enx<T: EzBuffer>(
        &self,
        buf: &mut T,
        function: impl FnOnce(&mut T, &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<(), CryptError>,
    ) -> Result<(), CryptError> {
        let transient_id = self.transient_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = &self.get_nonce(transient_id);
        function(buf, nonce)?;
        buf.extend_from_slice(&transient_id.to_be_bytes())
            .map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    fn wrap_with_unique_nonce_dex<T: EzBuffer>(
        &self,
        buf: &mut T,
        function: impl FnOnce(&mut T, &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<(), CryptError>,
    ) -> Result<(), CryptError> {
        let starting_pos = buf.len().saturating_sub(8);
        let transient_id_bytes = &buf.as_ref()[starting_pos..];
        if transient_id_bytes.len() != 8 {
            return Err(CryptError::Decrypt(format!(
                "Bad input size of {} (transient id)",
                buf.as_ref().len()
            )));
        }

        let transient_id = byteorder::BigEndian::read_u64(transient_id_bytes);
        let nonce = &self.get_nonce(transient_id);
        // trim the last 8 bytes
        buf.truncate(starting_pos);
        function(buf, nonce)
    }

    fn wrap_with_unique_nonce_enx_vec<T: AsRef<[u8]>>(
        &self,
        input: T,
        function: impl FnOnce(&[u8], &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<Vec<u8>, CryptError>,
    ) -> Result<Vec<u8>, CryptError> {
        let transient_id = self.transient_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = &self.get_nonce(transient_id);
        let input = input.as_ref();
        let mut out = function(input, nonce)?;
        out.extend_from_slice(&transient_id.to_be_bytes());
        Ok(out)
    }

    fn wrap_with_unique_nonce_dex_vec<T: AsRef<[u8]>>(
        &self,
        input: T,
        function: impl FnOnce(&[u8], &ArrayVec<u8, LARGEST_NONCE_LEN>) -> Result<Vec<u8>, CryptError>,
    ) -> Result<Vec<u8>, CryptError> {
        let buf = input.as_ref();
        let starting_pos = buf.len().saturating_sub(8);
        let transient_id_bytes = &buf[starting_pos..];
        if transient_id_bytes.len() != 8 {
            return Err(CryptError::Decrypt(format!(
                "Bad input size of {} (transient id)",
                buf.len()
            )));
        }

        let transient_id = byteorder::BigEndian::read_u64(transient_id_bytes);
        let nonce = &self.get_nonce(transient_id);
        // trim the last 8 bytes
        let input = &buf[..starting_pos];
        function(input, nonce)
    }

    pub fn local_encrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        payload: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_enx_vec(payload, move |payload, nonce| {
            quantum_container
                .local_encrypt(payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
    }

    pub fn local_decrypt<T: AsRef<[u8]>>(
        &self,
        quantum_container: &PostQuantumContainer,
        payload: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.wrap_with_unique_nonce_dex_vec(payload, move |payload, nonce| {
            quantum_container
                .local_decrypt(payload, nonce)
                .map_err(|err| CryptError::Encrypt(err.to_string()))
        })
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
use bytes::BufMut;
use citadel_pqcrypto::algorithm_dictionary::EncryptionAlgorithm;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use serde_big_array::BigArray;
use sha3::Digest;

/// A entropy bank is a fundamental dataset that continually morphs into new future sets
#[derive(Serialize, Deserialize)]
pub struct EntropyBank {
    pub(super) algorithm: EncryptionAlgorithm,
    pub(super) version: u32,
    pub(super) cid: u64,
    #[serde(with = "BigArray")]
    pub(super) entropy: [u8; BYTES_PER_STORE],
    pub(super) scramble_mappings: Vec<(u16, u16)>,
    pub(super) transient_counter: AtomicU64,
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
