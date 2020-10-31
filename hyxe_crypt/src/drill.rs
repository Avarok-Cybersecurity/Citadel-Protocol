/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use crate::drill_algebra::{PacketVector, generate_packet_vector, generate_packet_coordinates_inv};
use crate::drill_update::*;
use crate::misc::{bytes_to_3d_array, CryptError};
use crate::prelude::{ByteSlice, ByteSliceMut};
use byteorder::{BigEndian, ByteOrder};
use futures::StreamExt;
use rand::distributions::Distribution;
use rand::{thread_rng, RngCore};
use serde::export::fmt::Error;
use serde::export::Formatter;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::{Deref, Div};
use std::sync::Arc;

use crate::decrypt::async_decryptors::*;
use crate::encrypt::async_encryptors::*;
use bytes::{BufMut, BytesMut};
use ez_pqcrypto::PostQuantumContainer;
use rand::prelude::ThreadRng;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::prelude::{IntoParallelIterator, ParallelSlice, ParallelSliceMut};
use zerocopy::AsBytes;
use crate::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use bigdecimal::{FromPrimitive, BigDecimal};
use num_integer::Integer;

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
/// Future TODO: Handle discrepancies
pub const PORT_RANGE: usize = 14;
/// We limit the number of ports in order. See the explanation for this value within the `byte_count` subroutine of Drill's implementation
pub const MAX_PORT_RANGE: usize = 352;

/// The number of bytes per inner matrix is equal to the `PORT_RANGE`. For each outer matrix,
/// there exists `E_OF_X_START_INDEX` inner matrices. Thus, for low security, there exists
/// `PORT_RANGE` * `E_OF_X_START_INDEX` total bytes. Let p_r = `PORT_RANGE`, and s = `E_OF_X_START_INDEX` (=6).
/// Thus the total is s*p_r (for low security, which has raw u8 bytes)
///
/// For medium security, this formula is a little different. Since we have u16's (2x the size of low's u8's),
/// we must take s*p_r and multiply by two. Thus, we have 2*s*p_r for medium. For High security, we have twice
/// the medium's count of bytes. Thus, we have 4*s*p_r. For ultra, once again we multiply the next lowest security
/// level's byte size by 2 to obtain 8*s*p_r. For divine, we have 16*s*p_r.
///
/// To get the total number of bytes, then, we must add up all the level's. Thus, the total number of bytes is:
/// [equation 1] 1(s*p_r) + 2(s*p_r) + 4(s*p_r) + 8(s*p_r) + 16(s*p_r) = 31(s*p_r) => (2^n -1)(s*p_r) where n is the
/// index of {1, 2, 4, 8, 16, ...} => n = {1, 2, 3, 4, [...]}
///
/// On a side note: We want to limit the port range such that there are no more than u64::max() (65535) bytes or
/// 65.535 kilobytes of data per drill-update. To do this, set [equation 1] to 65535, and knowing s, divide 65535 by
/// 31*s to find that p_r = about 352.3. Therefore, the max port range is the floor thereof: p_r_max = 352 when s = `E_OF_X_START_INDEX`.

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
pub const BYTES_PER_3D_ARRAY: usize = 31 * E_OF_X_START_INDEX * PORT_RANGE;

/// The default endianness for byte storage
pub type DrillEndian = BigEndian;

/// I created a type for this very long expression in order to have cleaner-looking code
pub type RawDrillSkeleton = (
    [[u8; PORT_RANGE]; E_OF_X_START_INDEX],
    [[u16; PORT_RANGE]; E_OF_X_START_INDEX],
    [[u32; PORT_RANGE]; E_OF_X_START_INDEX],
    [[u64; PORT_RANGE]; E_OF_X_START_INDEX],
    [[u128; PORT_RANGE]; E_OF_X_START_INDEX],
);

/// For transfering the data around without need of the DrillType
pub type RawDrillSkeletonRef<'a> = (
    &'a [[u8; PORT_RANGE]; E_OF_X_START_INDEX],
    &'a [[u16; PORT_RANGE]; E_OF_X_START_INDEX],
    &'a [[u32; PORT_RANGE]; E_OF_X_START_INDEX],
    &'a [[u64; PORT_RANGE]; E_OF_X_START_INDEX],
    &'a [[u128; PORT_RANGE]; E_OF_X_START_INDEX],
);

/// The parent thread-safe type for sharing the underlying drill. The drill must only implement DrillType
#[derive(Serialize, Deserialize)]
pub struct Drill {
    /// Immutable access because there's no reason to mutate the inner data.
    /// Whether or not a drill is sync'ed with the central server is determined
    /// by the NetworkAccount.
    pub(crate) inner: Arc<DrillBits>,
}

unsafe impl Send for Drill {}
unsafe impl Sync for Drill {}

impl Drill {
    /// Creates a new drill
    pub fn new(cid: u64, drill_version: u32) -> Result<Self, CryptError<String>> {
        if PORT_RANGE > MAX_PORT_RANGE {
            return CryptError::OutOfBoundsError.throw();
        }

        Self::download_raw_3d_array()
            .and_then(|skeleton| Ok(construct_first_drill_from_3d_array(skeleton, drill_version, cid)))
    }

    /// Used to ensure the post-quantum public key appears different each time the it is transmitted
    pub fn generate_nonce(&self) -> u64 {
        ThreadRng::default().next_u64() ^ self.ultra[0][0]
    }

    /// The nonce is 96 bits or 12 bytes in size. We assume each nonce version is unique
    pub fn get_aes_gcm_nonce(&self, nonce_version: usize) -> [u8; AES_GCM_NONCE_LEN_BYTES] {
        assert!(AES_GCM_NONCE_LEN_BYTES < 25);
        let nonce = self.get_nonce3(nonce_version);
        log::trace!("Generated nonce v{}: {:?}", nonce_version, &nonce);
        nonce
    }

    #[inline]
    fn get_nonce3(&self, nonce_version: usize) -> [u8; AES_GCM_NONCE_LEN_BYTES] {
        let mut base = [0u8; AES_GCM_NONCE_LEN_BYTES];
        let f64s_needed = AES_GCM_NONCE_LEN_BYTES.div_ceil(&8);
        let mut outer_idx = 0;

        for x in 0..f64s_needed {
            let val = ((nonce_version + x) as f64).div(std::f64::consts::PI);
            let bytes = val.to_be_bytes();

            for y in 0..8 {
                if outer_idx == AES_GCM_NONCE_LEN_BYTES {
                    return base;
                }

                base[outer_idx] = bytes[y].wrapping_add(self.low[(nonce_version + x) % E_OF_X_START_INDEX][outer_idx % PORT_RANGE]).wrapping_add(nonce_version as u8);

                outer_idx += 1;
            }
        }

        base
    }

    #[inline]
    #[allow(dead_code)]
    fn get_nonce2(&self, nonce_version: usize) -> [u8; AES_GCM_NONCE_LEN_BYTES] {
        let mut base = [0u8; AES_GCM_NONCE_LEN_BYTES];
        // we need a precision of 8 bits per byte * the nonce len in bytes
        let precision = (AES_GCM_NONCE_LEN_BYTES * 8) as u64;

        let x = BigDecimal::from_usize(nonce_version).unwrap().with_prec(precision);
        let pi = BigDecimal::from_f64( std::f64::consts::PI).unwrap().with_prec(precision);
        let output = x.div(pi).with_prec(precision);

        let out_str = output.to_string();
        let out_bytes = out_str.as_bytes();

        //base.copy_from_slice(&out_bytes[..AES_GCM_NONCE_LEN_BYTES]);
        base.iter_mut().enumerate().for_each(|(idx, ptr)| *ptr = out_bytes[idx].wrapping_add(self.low[nonce_version % E_OF_X_START_INDEX][idx % PORT_RANGE]).wrapping_add(nonce_version as u8));
        base
    }

    /// Creates a random nonce. Unlike get_aes_gcm_nonce, there is no determinism
    /// Useful for the login process
    pub fn get_random_aes_gcm_nonce(&self) -> [u8; AES_GCM_NONCE_LEN_BYTES] {
        let mut rng = ThreadRng::default();
        let mut skeleton = [0u8; AES_GCM_NONCE_LEN_BYTES];
        rng.fill_bytes(&mut skeleton);
        skeleton
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt_into<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T, output: &mut BytesMut) -> Result<usize, CryptError<String>>{
        let nonce = self.get_aes_gcm_nonce(nonce_version);
        match quantum_container.encrypt(input.as_ref(), &nonce) {
            Ok(ciphertext) => {
                output.put(ciphertext.as_slice());
                Ok(ciphertext.len())
            },

            Err(err) => {
                log::error!("Error encrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_decrypt_into<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T, output: &mut BytesMut) -> Result<usize, CryptError<String>>{
        let nonce = self.get_aes_gcm_nonce(nonce_version);
        match quantum_container.decrypt(&nonce, input.as_ref()) {
            Ok(plaintext) => {
                output.put(plaintext.as_slice());
                Ok(plaintext.len())
            },

            Err(err) => {
                log::error!("Error decrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        let nonce = self.get_aes_gcm_nonce(nonce_version);
        match quantum_container.encrypt(input.as_ref(), &nonce) {
            Ok(ciphertext) => {
                Ok(ciphertext)
            },

            Err(err) => {
                log::error!("Error encrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Returns the plaintext if successful
    pub fn aes_gcm_decrypt<T: AsRef<[u8]>>(&self, nonce_version: usize, quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        let nonce = self.get_aes_gcm_nonce(nonce_version);
        match quantum_container.decrypt(input.as_ref(), &nonce) {
            Ok(plaintext) => {
                Ok(plaintext)
            },

            Err(err) => {
                log::error!("Error decrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Returns the length of the ciphertext
    pub fn aes_gcm_encrypt_custom_nonce<T: AsRef<[u8]>>(&self, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        match quantum_container.encrypt(input.as_ref(), &nonce) {
            Ok(ciphertext) => {
                Ok(ciphertext)
            },

            Err(err) => {
                log::error!("Error encrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Returns the plaintext if successful
    pub fn aes_gcm_decrypt_custom_nonce<T: AsRef<[u8]>>(&self, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], quantum_container: &PostQuantumContainer, input: T) -> Result<Vec<u8>, CryptError<String>>{
        match quantum_container.decrypt(input.as_ref(), &nonce) {
            Ok(plaintext) => {
                Ok(plaintext)
            },

            Err(err) => {
                log::error!("Error decrypting: {:?}", err);
                Err(CryptError::Encrypt(err.to_string()))
            }
        }
    }

    /// Protects an already constructed packet in-place. This guarantees that replay attacks cannot happen
    /// Ordered delivery of packets is mandatory
    pub fn protect_packet(&self, quantum_container: &PostQuantumContainer, header_len_bytes: usize, full_packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let ref nonce = self.get_aes_gcm_nonce(0);
        quantum_container.protect_packet_in_place(header_len_bytes, full_packet, nonce).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Unlike `protect_packet`, the returned object does NOT contain the header. The returned Bytes only contains the ciphertext
    pub fn validate_packet_in_place_split<H: AsRef<[u8]>>(&self, quantum_container: &PostQuantumContainer, header: H, payload: &mut BytesMut) -> Result<(), CryptError<String>> {
        let ref nonce = self.get_aes_gcm_nonce(0);
        let header = header.as_ref();
        quantum_container.validate_packet_in_place(header, payload, nonce).map_err(|err| CryptError::Encrypt(err.to_string()))
    }

    /// Applies or de-applies a modified form of the Vigenere cipher
    pub fn apply_nonce<T: AsMut<[u8]>>(&self, nonce: u64, mut input: T) {
        let input = input.as_mut();
        let nonce_be_bytes = &mut [0u8; 8];
        DrillEndian::write_u64(nonce_be_bytes, nonce);
        for (idx, byte) in input.into_iter().enumerate() {
            *byte = *byte ^ nonce_be_bytes[idx % 8];
        }
    }

    /// Gets the packet coordinates
    pub fn generate_packet_coordinates(&self, true_sequence: usize, group_id: u64) -> PacketVector {
        generate_packet_vector(true_sequence, group_id, self)
    }

    /// Returns the multiport width
    pub fn get_multiport_width(&self) -> usize {
        self.port_mappings.len()
    }

    /// Determines the index of the packet w.r.t the total encrypted/scrambled data
    pub fn get_packet_coordinate_inv(&self, src_port: u16, recv_port: u16, wave_id: u32) -> Option<usize> {
        generate_packet_coordinates_inv(wave_id, src_port, recv_port, self)
    }

    /// This is useful for encrypting data right into packets. !! Make sure the cursor is at the right position !!
    pub fn encrypt_into_slice<Input: ByteSlice, B: ByteSliceMut>(
        &self,
        input: Input,
        mut output: B,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        //let output = output.as_bytes_mut();
        let output_len = input.len() * byte_stretch;

        if output.len() != output_len {
            return Err(CryptError::Encrypt("Bad output size".to_string()));
        }

        match security_level {
            SecurityLevel::LOW => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        output[idx] = Self::encrypt_u8_to_u8(
                            *unencrypted_byte,
                            low,
                            j_rand as u8,
                            idx % PORT_RANGE,
                        );
                    });
            }
            SecurityLevel::MEDIUM => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u16(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u16(
                                *unencrypted_byte,
                                med,
                                j_rand as u16,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::HIGH => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u32(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u32(
                                *unencrypted_byte,
                                high,
                                j_rand as u32,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::ULTRA => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u64(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u64(
                                *unencrypted_byte,
                                ultra,
                                j_rand as u64,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::DIVINE => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u128(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u128(
                                *unencrypted_byte,
                                divine,
                                j_rand,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
        }

        Ok(output_len)
    }

    /// Allocates a new vector which this subroutine writes to and then returns
    pub fn encrypt_to_vec<Input: ByteSlice>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        let output_len = input.len() * byte_stretch;

        let mut output0 = vec![0; output_len];
        let output = output0.as_bytes_mut();

        match security_level {
            SecurityLevel::LOW => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        output[idx] = Self::encrypt_u8_to_u8(
                            *unencrypted_byte,
                            low,
                            j_rand as u8,
                            idx % PORT_RANGE,
                        );
                    });
            }
            SecurityLevel::MEDIUM => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u16(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u16(
                                *unencrypted_byte,
                                med,
                                j_rand as u16,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::HIGH => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u32(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u32(
                                *unencrypted_byte,
                                high,
                                j_rand as u32,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::ULTRA => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u64(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u64(
                                *unencrypted_byte,
                                ultra,
                                j_rand as u64,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::DIVINE => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        let output_pos = idx * byte_stretch;
                        DrillEndian::write_u128(
                            &mut output[output_pos..(output_pos + byte_stretch)],
                            Self::encrypt_u8_to_u128(
                                *unencrypted_byte,
                                divine,
                                j_rand,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
        };

        Ok(output0)
    }

    /// Takes a generic buffer and encrypts into it
    pub fn encrypt_to_buf<T: ByteSlice, B: BufMut>(
        &self,
        input: T,
        buf: &mut B,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        let output_len = input.len() * byte_stretch;

        if buf.remaining_mut() < output_len {
            return Err(CryptError::Encrypt("Insufficient buffer size".to_string()));
        }

        match security_level {
            SecurityLevel::LOW => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        buf.put_u8(Self::encrypt_u8_to_u8(
                            *unencrypted_byte,
                            low,
                            j_rand as u8,
                            idx % PORT_RANGE,
                        ));
                    });
            }
            SecurityLevel::MEDIUM => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        buf.put_u16(Self::encrypt_u8_to_u16(
                            *unencrypted_byte,
                            med,
                            j_rand as u16,
                            idx % PORT_RANGE,
                        ));
                    });
            }
            SecurityLevel::HIGH => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        buf.put_u32(Self::encrypt_u8_to_u32(
                            *unencrypted_byte,
                            high,
                            j_rand as u32,
                            idx % PORT_RANGE,
                        ));
                    });
            }
            SecurityLevel::ULTRA => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        buf.put_u64(Self::encrypt_u8_to_u64(
                            *unencrypted_byte,
                            ultra,
                            j_rand as u64,
                            idx % PORT_RANGE,
                        ));
                    });
            }
            SecurityLevel::DIVINE => {
                input
                    .iter()
                    .enumerate()
                    .for_each(|(idx, unencrypted_byte)| {
                        buf.put_u128(Self::encrypt_u8_to_u128(
                            *unencrypted_byte,
                            divine,
                            j_rand,
                            idx % PORT_RANGE,
                        ));
                    });
            }
        }

        Ok(output_len)
    }

    /// Parallel version of `encrypt_to_slice`
    pub fn par_encrypt_into_slice<Input: ByteSlice, B: ByteSliceMut>(
        &self,
        input: Input,
        mut output: B,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        //let output = output.as_bytes_mut();
        let output_len = input.len() * byte_stretch;

        if output.len() != output_len {
            return Err(CryptError::Encrypt("Bad output size".to_string()));
        }

        match security_level {
            SecurityLevel::LOW => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), output_bytes)| {
                        output_bytes[0] = Self::encrypt_u8_to_u8(
                            *unencrypted_byte,
                            low,
                            j_rand as u8,
                            idx % PORT_RANGE,
                        );
                    });
            }
            SecurityLevel::MEDIUM => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), output_bytes)| {
                        DrillEndian::write_u16(
                            output_bytes,
                            Self::encrypt_u8_to_u16(
                                *unencrypted_byte,
                                med,
                                j_rand as u16,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::HIGH => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), output_bytes)| {
                        DrillEndian::write_u32(
                            output_bytes,
                            Self::encrypt_u8_to_u32(
                                *unencrypted_byte,
                                high,
                                j_rand as u32,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::ULTRA => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), output_bytes)| {
                        DrillEndian::write_u64(
                            output_bytes,
                            Self::encrypt_u8_to_u64(
                                *unencrypted_byte,
                                ultra,
                                j_rand as u64,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::DIVINE => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), output_bytes)| {
                        DrillEndian::write_u128(
                            output_bytes,
                            Self::encrypt_u8_to_u128(
                                *unencrypted_byte,
                                divine,
                                j_rand,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
        }

        Ok(output_len)
    }

    /// Allocates a new vector which this subroutine writes to and then returns
    pub fn par_encrypt_to_vec<Input: ByteSlice>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        let output_len = input.len() * byte_stretch;

        let mut output = vec![0; output_len];

        let output_ref = output.as_bytes_mut();

        match security_level {
            SecurityLevel::LOW => {
                input.into_par_iter().enumerate().zip(output_ref).for_each(
                    |((idx, unencrypted_byte), setter)| {
                        *setter = Self::encrypt_u8_to_u8(
                            *unencrypted_byte,
                            low,
                            j_rand as u8,
                            idx % PORT_RANGE,
                        );
                    },
                );
            }
            SecurityLevel::MEDIUM => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output_ref.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), setter)| {
                        DrillEndian::write_u16(
                            setter,
                            Self::encrypt_u8_to_u16(
                                *unencrypted_byte,
                                med,
                                j_rand as u16,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::HIGH => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output_ref.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), setter)| {
                        DrillEndian::write_u32(
                            setter,
                            Self::encrypt_u8_to_u32(
                                *unencrypted_byte,
                                high,
                                j_rand as u32,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::ULTRA => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output_ref.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), setter)| {
                        DrillEndian::write_u64(
                            setter,
                            Self::encrypt_u8_to_u64(
                                *unencrypted_byte,
                                ultra,
                                j_rand as u64,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
            SecurityLevel::DIVINE => {
                input
                    .into_par_iter()
                    .enumerate()
                    .zip(output_ref.par_chunks_mut(byte_stretch))
                    .for_each(|((idx, unencrypted_byte), setter)| {
                        DrillEndian::write_u128(
                            setter,
                            Self::encrypt_u8_to_u128(
                                *unencrypted_byte,
                                divine,
                                j_rand,
                                idx % PORT_RANGE,
                            ),
                        );
                    });
            }
        }

        Ok(output)
    }

    /// Asynchronous version of `encrypt_to_slice`
    pub async fn async_encrypt_into_slice<
        Input: ByteSlice + Send + Sync,
        B: ByteSliceMut + Send + Sync,
    >(
        &self,
        input: Input,
        mut output: B,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        let output = output.as_bytes_mut();
        let output_len = input.len() * byte_stretch;

        if output.len() != output_len {
            return Err(CryptError::Encrypt("Bad output size".to_string()));
        }

        let input = input.as_bytes();

        match security_level {
            SecurityLevel::LOW => {
                let mut stream = DrillStandardAsyncEncryptorLow(input, low, j_rand as u8, 0);
                while let Some((bytes, cursor)) = stream.next().await {
                    output[cursor] = bytes[0];
                }
            }
            SecurityLevel::MEDIUM => {
                let mut stream = DrillStandardAsyncEncryptorMedium(input, med, j_rand as u16, 0);
                while let Some((bytes, cursor)) = stream.next().await {
                    let start_pos = cursor * byte_stretch;
                    output[start_pos..(byte_stretch + start_pos)]
                        .clone_from_slice(&bytes[..byte_stretch])
                }
            }
            SecurityLevel::HIGH => {
                let mut stream = DrillStandardAsyncEncryptorHigh(input, high, j_rand as u32, 0);
                while let Some((bytes, cursor)) = stream.next().await {
                    let start_pos = cursor * byte_stretch;
                    output[start_pos..(byte_stretch + start_pos)]
                        .clone_from_slice(&bytes[..byte_stretch])
                }
            }
            SecurityLevel::ULTRA => {
                let mut stream = DrillStandardAsyncEncryptorUltra(input, ultra, j_rand as u64, 0);
                while let Some((bytes, cursor)) = stream.next().await {
                    let start_pos = cursor * byte_stretch;
                    output[start_pos..(byte_stretch + start_pos)]
                        .clone_from_slice(&bytes[..byte_stretch])
                }
            }
            SecurityLevel::DIVINE => {
                let mut stream = DrillStandardAsyncEncryptorDivine(input, divine, j_rand, 0);
                while let Some((bytes, cursor)) = stream.next().await {
                    let start_pos = cursor * byte_stretch;
                    output[start_pos..(byte_stretch + start_pos)]
                        .clone_from_slice(&bytes[..byte_stretch])
                }
            }
        }

        Ok(output_len)
    }

    /// Asynchronous version of `encrypt_to_vec`
    pub async fn async_encrypt_to_vec<Input: ByteSlice + Send + Sync>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, byte_stretch) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        let output_len = input.len() * byte_stretch;
        let mut output = Vec::with_capacity(output_len);
        let input = input.as_bytes();
        //let output_ref = &mut output;

        match security_level {
            SecurityLevel::LOW => {
                let mut stream = DrillStandardAsyncEncryptorLow(input, low, j_rand as u8, 0);
                while let Some((bytes, _)) = stream.next().await {
                    output.extend_from_slice(&bytes);
                }
            }
            SecurityLevel::MEDIUM => {
                let mut stream = DrillStandardAsyncEncryptorMedium(input, med, j_rand as u16, 0);
                while let Some((bytes, _)) = stream.next().await {
                    output.extend_from_slice(&bytes);
                }
            }
            SecurityLevel::HIGH => {
                let mut stream = DrillStandardAsyncEncryptorHigh(input, high, j_rand as u32, 0);
                while let Some((bytes, _)) = stream.next().await {
                    output.extend_from_slice(&bytes);
                }
            }
            SecurityLevel::ULTRA => {
                let mut stream = DrillStandardAsyncEncryptorUltra(input, ultra, j_rand as u64, 0);
                while let Some((bytes, _)) = stream.next().await {
                    output.extend_from_slice(&bytes);
                }
            }
            SecurityLevel::DIVINE => {
                let mut stream = DrillStandardAsyncEncryptorDivine(input, divine, j_rand, 0);
                while let Some((bytes, _)) = stream.next().await {
                    output.extend_from_slice(&bytes);
                }
            }
        }

        Ok(output)
    }

    /// Decrypts an input into a freshly allocated output vector
    pub fn decrypt_to_vec<Input: ByteSlice>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        Ok(match security_level {
            SecurityLevel::LOW => input
                .chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_1byte_chunk(low, idx % PORT_RANGE, j_rand as u8, arr)
                })
                .collect(),
            SecurityLevel::MEDIUM => input
                .chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_2byte_chunk(med, idx % PORT_RANGE, j_rand as u16, arr)
                })
                .collect(),
            SecurityLevel::HIGH => input
                .chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_4byte_chunk(high, idx % PORT_RANGE, j_rand as u32, arr)
                })
                .collect(),
            SecurityLevel::ULTRA => input
                .chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_8byte_chunk(ultra, idx % PORT_RANGE, j_rand as u64, arr)
                })
                .collect(),
            SecurityLevel::DIVINE => input
                .chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| Self::decrypt_16byte_chunk(divine, idx % PORT_RANGE, j_rand, arr))
                .collect(),
        })
    }

    /// Decrypts data into `output`. Ensure that the output slice contains enough space reserved for writing before calling this method
    pub fn decrypt_into_slice<Input: ByteSlice, Output: ByteSliceMut>(
        &self,
        input: Input,
        mut output: Output,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        let output_len_required = input.len() / block_size;
        if output.len() < output_len_required {
            return Err(CryptError::Decrypt("Bad output size".to_string()));
        }

        match security_level {
            SecurityLevel::LOW => input.chunks(block_size).enumerate().for_each(|(idx, arr)| {
                output[idx] = Self::decrypt_1byte_chunk(low, idx % PORT_RANGE, j_rand as u8, arr);
            }),

            SecurityLevel::MEDIUM => input.chunks(block_size).enumerate().for_each(|(idx, arr)| {
                output[idx] = Self::decrypt_2byte_chunk(med, idx % PORT_RANGE, j_rand as u16, arr);
            }),

            SecurityLevel::HIGH => input.chunks(block_size).enumerate().for_each(|(idx, arr)| {
                output[idx] = Self::decrypt_4byte_chunk(high, idx % PORT_RANGE, j_rand as u32, arr);
            }),

            SecurityLevel::ULTRA => input.chunks(block_size).enumerate().for_each(|(idx, arr)| {
                output[idx] =
                    Self::decrypt_8byte_chunk(ultra, idx % PORT_RANGE, j_rand as u64, arr);
            }),

            SecurityLevel::DIVINE => input.chunks(block_size).enumerate().for_each(|(idx, arr)| {
                output[idx] = Self::decrypt_16byte_chunk(divine, idx % PORT_RANGE, j_rand, arr);
            }),
        }

        Ok(output_len_required)
    }

    /// Decrypts a mutable byte slice using a parallel iterator for concurrency. Use this if the data
    /// is large.
    pub fn par_decrypt_to_vec<Input: ByteSlice>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        Ok(match security_level {
            SecurityLevel::LOW => input
                .par_chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_1byte_chunk(low, idx % PORT_RANGE, j_rand as u8, arr)
                })
                .collect(),
            SecurityLevel::MEDIUM => input
                .par_chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_2byte_chunk(med, idx % PORT_RANGE, j_rand as u16, arr)
                })
                .collect(),
            SecurityLevel::HIGH => input
                .par_chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_4byte_chunk(high, idx % PORT_RANGE, j_rand as u32, arr)
                })
                .collect(),
            SecurityLevel::ULTRA => input
                .par_chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| {
                    Self::decrypt_8byte_chunk(ultra, idx % PORT_RANGE, j_rand as u64, arr)
                })
                .collect(),
            SecurityLevel::DIVINE => input
                .par_chunks(block_size)
                .enumerate()
                .map(|(idx, arr)| Self::decrypt_16byte_chunk(divine, idx % PORT_RANGE, j_rand, arr))
                .collect(),
        })
    }

    /// Decrypts a byte slice into the supplied mutable byte slice using a parallel iterator for concurrency. Use this if the data
    /// is large. Ensure that the output slice contains enough space reserved for writing before calling this method
    pub fn par_decrypt_into_slice<Input: ByteSlice, Output: ByteSliceMut>(
        &self,
        input: Input,
        mut output: Output,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        let output_len_required = input.len() / block_size;
        if output.len() < output_len_required {
            return Err(CryptError::Decrypt("Bad output size".to_string()));
        }

        let output = output.as_bytes_mut();

        match security_level {
            SecurityLevel::LOW => input
                .par_chunks(block_size)
                .enumerate()
                .zip(output.into_par_iter().take(output_len_required))
                .for_each(|((idx, arr), output)| {
                    *output = Self::decrypt_1byte_chunk(low, idx % PORT_RANGE, j_rand as u8, arr);
                }),
            SecurityLevel::MEDIUM => input
                .par_chunks(block_size)
                .enumerate()
                .zip(output.into_par_iter().take(output_len_required))
                .for_each(|((idx, arr), output)| {
                    *output = Self::decrypt_2byte_chunk(med, idx % PORT_RANGE, j_rand as u16, arr);
                }),
            SecurityLevel::HIGH => input
                .par_chunks(block_size)
                .enumerate()
                .zip(output.into_par_iter().take(output_len_required))
                .for_each(|((idx, arr), output)| {
                    *output = Self::decrypt_4byte_chunk(high, idx % PORT_RANGE, j_rand as u32, arr);
                }),
            SecurityLevel::ULTRA => input
                .par_chunks(block_size)
                .enumerate()
                .zip(output.into_par_iter().take(output_len_required))
                .for_each(|((idx, arr), output)| {
                    *output =
                        Self::decrypt_8byte_chunk(ultra, idx % PORT_RANGE, j_rand as u64, arr);
                }),
            SecurityLevel::DIVINE => input
                .par_chunks(block_size)
                .enumerate()
                .zip(output.into_par_iter().take(output_len_required))
                .for_each(|((idx, arr), output)| {
                    *output = Self::decrypt_16byte_chunk(divine, idx % PORT_RANGE, j_rand, arr);
                }),
        }

        Ok(output_len_required)
    }

    /// The asynchronous version of `decrypt_slice_mut`
    pub async fn async_decrypt_to_vec<Input: ByteSlice + Send + Sync>(
        &self,
        input: Input,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        let input = input.as_bytes();

        let mut output = Vec::with_capacity(input.len() / block_size);
        match security_level {
            SecurityLevel::LOW => {
                let mut stream =
                    DrillStandardAsyncDecryptorLow(input, low, block_size, j_rand as u8, 0);
                while let Some(byte) = stream.next().await {
                    output.push(byte);
                }
            }
            SecurityLevel::MEDIUM => {
                let mut stream =
                    DrillStandardAsyncDecryptorMedium(input, med, block_size, j_rand as u16, 0);
                while let Some(byte) = stream.next().await {
                    output.push(byte);
                }
            }
            SecurityLevel::HIGH => {
                let mut stream =
                    DrillStandardAsyncDecryptorHigh(input, high, block_size, j_rand as u32, 0);
                while let Some(byte) = stream.next().await {
                    output.push(byte);
                }
            }
            SecurityLevel::ULTRA => {
                let mut stream =
                    DrillStandardAsyncDecryptorUltra(input, ultra, block_size, j_rand as u64, 0);
                while let Some(byte) = stream.next().await {
                    output.push(byte);
                }
            }
            SecurityLevel::DIVINE => {
                let mut stream =
                    DrillStandardAsyncDecryptorDivine(input, divine, block_size, j_rand, 0);
                while let Some(byte) = stream.next().await {
                    output.push(byte);
                }
            }
        }

        Ok(output)
    }

    /// The asynchronous version of `decrypt_slice_mut`
    pub async fn async_decrypt_into_slice<
        Input: ByteSlice + Send + Sync,
        Output: ByteSliceMut + Send + Sync,
    >(
        &self,
        input: Input,
        mut output: Output,
        amplitudal_sigma: usize,
        security_level: SecurityLevel,
    ) -> Result<usize, CryptError<String>> {
        let (low, med, high, ultra, divine) = self.ref_all();
        let (j_rand, block_size) = get_auxiliary_config(
            &(low, med, high, ultra, divine),
            amplitudal_sigma,
            &security_level,
        );

        if input.len() % block_size != 0 {
            return Err(CryptError::Decrypt("Bad input size".to_string()));
        }

        let output_len_required = input.len() / block_size;
        if output.len() < output_len_required {
            return Err(CryptError::Decrypt("Bad output size".to_string()));
        }

        let input = input.as_bytes();
        let output = output.as_bytes_mut();

        match security_level {
            SecurityLevel::LOW => {
                let stream =
                    DrillStandardAsyncDecryptorLow(input, low, block_size, j_rand as u8, 0);
                let mut stream = stream.enumerate();
                while let Some((idx, byte)) = stream.next().await {
                    output[idx] = byte;
                }
            }
            SecurityLevel::MEDIUM => {
                let stream =
                    DrillStandardAsyncDecryptorMedium(input, med, block_size, j_rand as u16, 0);
                let mut stream = stream.enumerate();
                while let Some((idx, byte)) = stream.next().await {
                    output[idx] = byte;
                }
            }
            SecurityLevel::HIGH => {
                let stream =
                    DrillStandardAsyncDecryptorHigh(input, high, block_size, j_rand as u32, 0);
                let mut stream = stream.enumerate();
                while let Some((idx, byte)) = stream.next().await {
                    output[idx] = byte;
                }
            }
            SecurityLevel::ULTRA => {
                let stream =
                    DrillStandardAsyncDecryptorUltra(input, ultra, block_size, j_rand as u64, 0);
                let mut stream = stream.enumerate();
                while let Some((idx, byte)) = stream.next().await {
                    output[idx] = byte;
                }
            }
            SecurityLevel::DIVINE => {
                let stream =
                    DrillStandardAsyncDecryptorDivine(input, divine, block_size, j_rand, 0);
                let mut stream = stream.enumerate();
                while let Some((idx, byte)) = stream.next().await {
                    output[idx] = byte;
                }
            }
        }

        Ok(output_len_required)
    }

    #[inline]
    /// Decrypts a singular low-security block
    pub(crate) fn decrypt_1byte_chunk(
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
    /// Decrypts a singular medium-security block
    pub(crate) fn decrypt_2byte_chunk(
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
    /// Decrypts a singular high-security block
    pub(crate) fn decrypt_4byte_chunk(
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
    /// Decrypts a singular ultra-security block
    pub(crate) fn decrypt_8byte_chunk(
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
    /// Decrypts a singular divine-security block
    pub(crate) fn decrypt_16byte_chunk(
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
    /// Encrypts a single a single byte into 1 byte
    pub(crate) fn encrypt_u8_to_u8(
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
    /// Encrypts a single a single byte into 2 bytes
    pub(crate) fn encrypt_u8_to_u16(
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
    /// Encrypts a single a single byte into 4 bytes
    pub(crate) fn encrypt_u8_to_u32(
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
    /// Encrypts a single a single byte into 8 bytes
    pub(crate) fn encrypt_u8_to_u64(
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
    /// Encrypts a single a single byte into 16 bytes
    pub(crate) fn encrypt_u8_to_u128(
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
    /// Gets the client ID
    pub fn get_cid(&self) -> u64 {
        self.cid
    }

    /// Gets the version of the drill
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /*
    async fn download_raw_3d_array_async() -> Result<RawDrillSkeleton, CryptError<String>> {
        next_u8s(BYTES_PER_3D_ARRAY)
            .await
            .and_then(|res| Ok(bytes_to_3d_array(&res)))
            .map_err(|err| CryptError::DrillUpdateError(err.to_string()))
    }*/

    /// Downloads the data necessary to create a drill
    fn download_raw_3d_array() -> Result<RawDrillSkeleton, CryptError<String>> {
            let bytes: &mut [u8; BYTES_PER_3D_ARRAY] = &mut [0; BYTES_PER_3D_ARRAY];
            let mut trng = thread_rng();
            let _ = rand::distributions::Bernoulli::new(0.5)
                .unwrap()
                .sample(&mut trng);
            trng.fill_bytes(bytes);
            let bytes = bytes.to_vec();
            Ok(bytes_to_3d_array(bytes))
    }

    /// Gets the low-security bits (u8)
    pub fn get_low(&self) -> &[[u8; PORT_RANGE]; E_OF_X_START_INDEX] {
        &self.low
    }

    /// Gets the medium-security bits (u16)
    pub fn get_med(&self) -> &[[u16; PORT_RANGE]; E_OF_X_START_INDEX] {
        &self.med
    }

    /// Gets the high-security bits (u32)
    pub fn get_high(&self) -> &[[u32; PORT_RANGE]; E_OF_X_START_INDEX] {
        &self.high
    }

    /// Gets the ultra-security bits (u64)
    pub fn get_ultra(&self) -> &[[u64; PORT_RANGE]; E_OF_X_START_INDEX] {
        &self.inner.ultra
    }

    /// Gets the divine-security bits (u128)
    pub fn get_divine(&self) -> &[[u128; PORT_RANGE]; E_OF_X_START_INDEX] {
        &self.divine
    }

    /// Gets randmonized port mappings which contain the true information. Other ports may get bogons
    pub fn get_port_mapping(&self) -> &Vec<(u16, u16)> {
        &self.port_mappings
    }

    /// This should be called by the toolkit. This subroutine returns the the values needed to
    /// transform self at version n to the next self at version (n + 1).

    pub fn download_next_drill(
        &self,
    ) -> Result<(DrillUpdateObject, Drill), CryptError<String>> {
        DrillUpdateObject::generate(self.get_cid(), self.get_version(), self)
            .and_then(|update| update.compute_next_recursion(self, true).ok_or_else(|| CryptError::DrillUpdateError("Unable to compute next recursion".to_string())))
    }

    /// Conveniantly returns a reference of all the items
    pub fn ref_all(&self) -> RawDrillSkeletonRef {
        (&self.low, &self.med, &self.high, &self.ultra, &self.divine)
    }

    /// Returns the strong count of pointers to this object
    pub fn get_strong_count_active(&self) -> usize {
        Arc::strong_count(&self.inner)
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

impl Clone for Drill {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl From<DrillBits> for Drill {
    fn from(inner: DrillBits) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl Deref for Drill {
    type Target = DrillBits;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Provides the enumeration forall security levels
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum SecurityLevel {
    /// Bytes multiplier: 1
    LOW = 0,
    /// Bytes multiplier: 2
    MEDIUM = 1,
    /// Bytes multiplier: 4
    HIGH = 2,
    /// Bytes multiplier: 8
    ULTRA = 3,
    /// Bytes multiplier: 16
    DIVINE = 4,
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
        }
    }

    /// Possibly returns the security_level given an input value
    pub fn for_value(val: usize) -> Option<Self> {
        match val {
            0 => Some(SecurityLevel::LOW),
            1 => Some(SecurityLevel::MEDIUM),
            2 => Some(SecurityLevel::HIGH),
            3 => Some(SecurityLevel::ULTRA),
            4 => Some(SecurityLevel::DIVINE),
            _ => None,
        }
    }

    /// Result version of for_value
    pub fn for_value_ok(val: usize) -> Result<Self, CryptError<String>> {
        match val {
            0 => Ok(SecurityLevel::LOW),
            1 => Ok(SecurityLevel::MEDIUM),
            2 => Ok(SecurityLevel::HIGH),
            3 => Ok(SecurityLevel::ULTRA),
            4 => Ok(SecurityLevel::DIVINE),
            _ => Err(CryptError::BadSecuritySetting),
        }
    }

    /// Returns the byte augmentation value
    pub fn get_augmentation(self) -> usize {
        match self {
            SecurityLevel::LOW => 1,
            SecurityLevel::MEDIUM => 2,
            SecurityLevel::HIGH => 4,
            SecurityLevel::ULTRA => 8,
            SecurityLevel::DIVINE => 16,
        }
    }

    /// Returns the number of bytes expected upon encryption
    pub fn get_expected_encrypted_len(self, len: usize) -> usize {
        len * self.get_augmentation()
    }

    /// Returns the number of bytes expected upon decryption
    pub fn get_expected_decrypted_len(self, len: usize) -> usize {
        len / self.get_augmentation()
    }
}

/// A drill is a fundamental encryption dataset that continually morphs into new future sets
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct DrillBits {
    pub(super) version: u32,
    pub(super) cid: u64,
    pub(super) low: [[u8; PORT_RANGE]; E_OF_X_START_INDEX],
    pub(super) med: [[u16; PORT_RANGE]; E_OF_X_START_INDEX],
    pub(super) high: [[u32; PORT_RANGE]; E_OF_X_START_INDEX],
    pub(super) ultra: [[u64; PORT_RANGE]; E_OF_X_START_INDEX],
    pub(super) divine: [[u128; PORT_RANGE]; E_OF_X_START_INDEX],
    pub(super) port_mappings: Vec<(u16, u16)>,
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

#[inline]
fn get_auxiliary_config(
    drill: &RawDrillSkeletonRef,
    amplitudal_sigma: usize,
    security_level: &SecurityLevel,
) -> (u128, usize) {
    match security_level {
        SecurityLevel::LOW => (
            drill.0[AMPLITUDE_DIFFERENTIALS_KEY_INDEX][amplitudal_sigma % PORT_RANGE] as u128,
            1,
        ),
        SecurityLevel::MEDIUM => (
            drill.1[AMPLITUDE_DIFFERENTIALS_KEY_INDEX][amplitudal_sigma % PORT_RANGE] as u128,
            2,
        ),
        SecurityLevel::HIGH => (
            drill.2[AMPLITUDE_DIFFERENTIALS_KEY_INDEX][amplitudal_sigma % PORT_RANGE] as u128,
            4,
        ),
        SecurityLevel::ULTRA => (
            drill.3[AMPLITUDE_DIFFERENTIALS_KEY_INDEX][amplitudal_sigma % PORT_RANGE] as u128,
            8,
        ),
        SecurityLevel::DIVINE => (
            drill.4[AMPLITUDE_DIFFERENTIALS_KEY_INDEX][amplitudal_sigma % PORT_RANGE],
            16,
        ),
    }
}
