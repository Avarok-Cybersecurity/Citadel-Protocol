use crate::EzError;
use aes_gcm_siv::aead::Buffer;
use rand::prelude::SliceRandom;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AliceToBobTransferParameters {
    MixedAsymmetric {
        alice_pk: Arc<oqs::kem::PublicKey>,
        alice_pk_sig: Arc<oqs::sig::PublicKey>,
        alice_sig: oqs::sig::Signature,
        sig_scheme: oqs::sig::Algorithm,
        kem_scheme: oqs::kem::Algorithm,
    },
    PureSymmetric {
        alice_pk: Arc<oqs::kem::PublicKey>,
        kem_scheme: oqs::kem::Algorithm,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum BobToAliceTransferParameters {
    MixedAsymmetric {
        bob_ciphertext: Arc<oqs::kem::Ciphertext>,
        bob_signature: oqs::sig::Signature,
        bob_pk_sig: Arc<oqs::sig::PublicKey>,
        bob_pk: Arc<oqs::kem::PublicKey>,
    },
    PureSymmetric {
        bob_ciphertext: Arc<oqs::kem::Ciphertext>,
        bob_pk: Arc<oqs::kem::PublicKey>,
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
        for x in 0..BLOCK_SIZE {
            mapping[x] = (x % BLOCK_SIZE) as u8;
        }

        mapping.shuffle(&mut rng);

        Some(Self { mapping })
    }

    pub fn scramble_in_place<T: Buffer + ?Sized>(&self, buf: &mut T) {
        if buf.as_mut().len() % BLOCK_SIZE != 0 || buf.as_mut().len() == 0 {
            // pad with random bytes
            let diff = BLOCK_SIZE - (buf.as_mut().len() % BLOCK_SIZE);
            let mut rand = rand::thread_rng();
            let mut zeroed_buffer = vec![0u8; diff];
            rand.fill_bytes(zeroed_buffer.as_mut_slice());
            buf.extend_from_slice(zeroed_buffer.as_slice()).unwrap();
        }

        for chunk in buf.as_mut().chunks_exact_mut(BLOCK_SIZE) {
            self.swap_in_place(chunk)
        }
    }

    pub fn descramble_in_place<T: AsMut<[u8]> + ?Sized>(&self, buf: &mut T) -> Result<(), EzError> {
        let chunk_len = BLOCK_SIZE;
        let buf = buf.as_mut();

        if buf.len() % chunk_len != 0 {
            return Err(EzError::Other(format!(
                "Invalid input len for scrambler: {}",
                buf.len()
            )));
        }

        for chunk in buf.chunks_exact_mut(chunk_len) {
            self.swap_in_place(chunk)
        }

        Ok(())
    }

    fn swap_in_place<T: AsMut<[u8]>>(&self, mut buf: T) {
        let buf = buf.as_mut();
        assert_eq!(buf.len(), BLOCK_SIZE);

        let mut has_swapped = HashSet::new();

        for (lhs_idx, rhs_idx) in self.mapping.iter().map(|r| *r as usize).enumerate() {
            if !has_swapped.contains(&lhs_idx) && !has_swapped.contains(&rhs_idx) {
                // move the rhs into the lhs and vice versa
                let rhs_val = buf[rhs_idx];
                let lhs_val = buf[lhs_idx];
                buf[lhs_idx] = rhs_val;
                buf[rhs_idx] = lhs_val;
                has_swapped.insert(lhs_idx);
                has_swapped.insert(rhs_idx);
            }
        }
    }
}

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

            dict.scramble_in_place(&mut buf);
            dict.descramble_in_place(&mut buf).unwrap();

            // NOTE: the protocol will need to the pre-scramble length encoded
            buf.truncate(before.len());

            assert_eq!(before, buf);
        }
    }
}
