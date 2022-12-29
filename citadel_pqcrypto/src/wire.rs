use crate::{Error, KemAlgorithm, SigAlgorithm};
use aes_gcm_siv::aead::Buffer;
use rand::prelude::SliceRandom;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub enum AliceToBobTransferParameters {
    MixedAsymmetric {
        alice_pk: Arc<Vec<u8>>,
        alice_pk_sig: Arc<pqcrypto_falcon_wasi::falcon1024::PublicKey>,
        alice_signed_public_key: pqcrypto_falcon_wasi::falcon1024::SignedMessage,
        sig_scheme: SigAlgorithm,
        kem_scheme: KemAlgorithm,
    },
    PureSymmetric {
        alice_pk: Arc<Vec<u8>>,
        kem_scheme: KemAlgorithm,
    },
}

#[derive(Serialize, Deserialize, Clone)]
pub enum BobToAliceTransferParameters {
    MixedAsymmetric {
        bob_signed_ciphertext: Arc<pqcrypto_falcon_wasi::falcon1024::SignedMessage>,
        bob_pk_sig: Arc<pqcrypto_falcon_wasi::falcon1024::PublicKey>,
        bob_pk: Arc<Vec<u8>>,
    },
    PureSymmetric {
        bob_ciphertext: Arc<Vec<u8>>,
        bob_pk: Arc<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct ScramCryptDictionary<const BLOCK_SIZE: usize> {
    #[serde(with = "serde_big_array::BigArray")]
    pub mapping: [u8; BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize> ScramCryptDictionary<BLOCK_SIZE> {
    pub fn new() -> Option<Self> {
        assert!(BLOCK_SIZE <= 256);
        assert_eq!(BLOCK_SIZE % 2, 0);

        let mut rng = rand::thread_rng();
        let mut mapping: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        for (idx, val) in mapping.iter_mut().enumerate() {
            *val = idx as u8;
        }

        mapping.shuffle(&mut rng);

        Some(Self { mapping })
    }

    pub fn scramble_in_place<T: Buffer + ?Sized>(&self, buf: &mut T) -> Result<(), Error> {
        if buf.as_mut().len() % BLOCK_SIZE != 0 || buf.as_mut().is_empty() {
            // pad with random bytes
            let diff = BLOCK_SIZE - (buf.as_mut().len() % BLOCK_SIZE);
            let mut rand = rand::thread_rng();
            let mut zeroed_buffer = vec![0u8; diff];
            rand.fill_bytes(zeroed_buffer.as_mut_slice());
            buf.extend_from_slice(zeroed_buffer.as_slice()).unwrap();
        }

        for chunk in buf.as_mut().chunks_exact_mut(BLOCK_SIZE) {
            self.swap_in_place(chunk)?
        }

        Ok(())
    }

    pub fn descramble_in_place<T: AsMut<[u8]> + ?Sized>(&self, buf: &mut T) -> Result<(), Error> {
        let chunk_len = BLOCK_SIZE;
        let buf = buf.as_mut();

        if buf.len() % chunk_len != 0 {
            return Err(Error::Other(format!(
                "Invalid input len for scrambler: {}",
                buf.len()
            )));
        }

        for chunk in buf.chunks_exact_mut(chunk_len) {
            self.swap_in_place(chunk)?
        }

        Ok(())
    }

    fn swap_in_place<T: AsMut<[u8]>>(&self, mut buf: T) -> Result<(), Error> {
        let buf = buf.as_mut();
        if buf.len() != BLOCK_SIZE {
            return Err(Error::Generic("Bad input buffer length"));
        }

        let mut has_swapped = HashSet::new();

        for (lhs_idx, rhs_idx) in self.mapping.iter().map(|r| *r as usize).enumerate() {
            if !has_swapped.contains(&lhs_idx) && !has_swapped.contains(&rhs_idx) {
                if rhs_idx > BLOCK_SIZE || lhs_idx > BLOCK_SIZE {
                    return Err(Error::Generic(
                        "RHS_IDX | LHS_IDX is greater than the block size. Bad deserialization?",
                    ));
                }

                // move the rhs into the lhs and vice versa
                let rhs_val = buf[rhs_idx];
                let lhs_val = buf[lhs_idx];
                buf[lhs_idx] = rhs_val;
                buf[rhs_idx] = lhs_val;
                has_swapped.insert(lhs_idx);
                has_swapped.insert(rhs_idx);
            }
        }

        Ok(())
    }
}

/*
impl<const N: usize> TryFrom<Vec<u8>> for ScramCryptDictionary<N> {
    type Error = EzError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes = value.as_slice();
        if bytes.len() != N {
            return Err(EzError::Other(format!(
                "The input bytes (len={}) for the ScramCrypt Dictionary is not {}",
                bytes.len(),
                N
            )));
        }

        let mut mapping = [0u8; N];
        mapping.copy_from_slice(bytes);

        Ok(Self { mapping })
    }
}
*/

#[cfg(test)]
mod tests {
    use crate::wire::ScramCryptDictionary;
    use rand::random;

    #[test]
    fn test_scrambling() {
        let dict = ScramCryptDictionary::<256>::new().unwrap();
        let mut buf: Vec<u8> = Vec::new();
        for x in 0..257 {
            // test zero-sized inputs too
            if x != 0 {
                buf.push(random());
            }

            let before = buf.clone();

            dict.scramble_in_place(&mut buf).unwrap();
            dict.descramble_in_place(&mut buf).unwrap();

            // NOTE: the protocol will need to the pre-scramble length encoded
            buf.truncate(before.len());

            assert_eq!(before, buf);
        }
    }
}
