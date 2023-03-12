use crate::{Error, KemAlgorithm, SigAlgorithm};
use aes_gcm::aead::Buffer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Clone)]
pub enum AliceToBobTransferParameters {
    MixedAsymmetric {
        alice_pk: Arc<Zeroizing<Vec<u8>>>,
        alice_pk_sig: Arc<crate::functions::PublicKeyType>,
        alice_public_key_signature: Zeroizing<Vec<u8>>,
        sig_scheme: SigAlgorithm,
        kem_scheme: KemAlgorithm,
    },
    PureSymmetric {
        alice_pk: Arc<Zeroizing<Vec<u8>>>,
        kem_scheme: KemAlgorithm,
    },
}

#[derive(Serialize, Deserialize, Clone)]
pub enum BobToAliceTransferParameters {
    MixedAsymmetric {
        bob_ciphertext_signature: Arc<Zeroizing<Vec<u8>>>,
        bob_ciphertext: Arc<Zeroizing<Vec<u8>>>,
        bob_pk_sig: Arc<crate::functions::PublicKeyType>,
        bob_pk: Arc<Zeroizing<Vec<u8>>>,
    },
    PureSymmetric {
        bob_ciphertext: Arc<Zeroizing<Vec<u8>>>,
        bob_pk: Arc<Zeroizing<Vec<u8>>>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ScramCryptDictionary<const BLOCK_SIZE: usize> {
    #[serde(with = "serde_big_array::BigArray")]
    pub mapping: [u8; BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize> ScramCryptDictionary<BLOCK_SIZE> {
    pub fn new() -> Option<Self> {
        if BLOCK_SIZE > 256 || BLOCK_SIZE % 2 != 0 {
            return None;
        }

        let mut rng = rand::thread_rng();
        let mut mapping: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut mapping);

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
            self.swap_in_place(chunk, false)?
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
            self.swap_in_place(chunk, true)?
        }

        Ok(())
    }

    fn swap_in_place<T: AsMut<[u8]>>(&self, mut buf: T, reverse: bool) -> Result<(), Error> {
        let buf = buf.as_mut();
        if buf.len() != BLOCK_SIZE {
            return Err(Error::Generic("Bad input buffer length"));
        }

        for (shift, buf) in self.mapping.iter().zip(buf.iter_mut()) {
            if reverse {
                *buf = buf.wrapping_sub(*shift)
            } else {
                *buf = buf.wrapping_add(*shift)
            }
        }

        Ok(())
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

            dict.scramble_in_place(&mut buf).unwrap();
            dict.descramble_in_place(&mut buf).unwrap();

            // NOTE: the protocol will need to the pre-scramble length encoded
            buf.truncate(before.len());

            assert_eq!(before, buf);
        }
    }
}
