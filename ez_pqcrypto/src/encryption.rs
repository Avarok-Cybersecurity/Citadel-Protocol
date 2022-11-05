use crate::ez_error::EzError;
use aes_gcm_siv::aead::Buffer;

pub trait AeadModule: Send + Sync {
    fn encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
        let mut ret = Vec::from(input);
        self.encrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), EzError>;
    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), EzError>;
    fn decrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
        let mut ret = Vec::from(input);
        self.decrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }
}

pub(crate) mod aes_impl {
    use crate::encryption::AeadModule;
    use crate::ez_error::EzError;
    use aes_gcm_siv::aead::generic_array::GenericArray;
    use aes_gcm_siv::aead::{AeadInPlace, Buffer};
    use aes_gcm_siv::Aes256GcmSiv;

    impl AeadModule for Aes256GcmSiv {
        fn encrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            <Self as AeadInPlace>::encrypt_in_place(
                self,
                GenericArray::from_slice(nonce),
                ad,
                input,
            )
            .map_err(|_| EzError::EncryptionFailure)
        }

        fn decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            <Self as AeadInPlace>::decrypt_in_place(
                self,
                GenericArray::from_slice(nonce),
                ad,
                input,
            )
            .map_err(|_| EzError::EncryptionFailure)
        }
    }
}

pub(crate) mod chacha_impl {
    use crate::encryption::AeadModule;
    use crate::ez_error::EzError;
    use aes_gcm_siv::aead::Buffer;
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::XChaCha20Poly1305;

    impl AeadModule for XChaCha20Poly1305 {
        fn encrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            <Self as AeadInPlace>::encrypt_in_place(
                self,
                GenericArray::from_slice(nonce),
                ad,
                input,
            )
            .map_err(|_| EzError::EncryptionFailure)
        }

        fn decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            <Self as AeadInPlace>::decrypt_in_place(
                self,
                GenericArray::from_slice(nonce),
                ad,
                input,
            )
            .map_err(|_| EzError::EncryptionFailure)
        }
    }
}

pub(crate) mod kyber_module {
    use crate::{AeadModule, EzError, KemAlgorithm, SigAlgorithm, AES_GCM_NONCE_LENGTH_BYTES};
    use aes_gcm_siv::aead::Buffer;
    use byteorder::{ByteOrder, NetworkEndian};
    use std::sync::Arc;

    pub struct KyberModule {
        pub kem_alg: KemAlgorithm,
        pub sig_alg: SigAlgorithm,
        pub pk_kem_remote: Arc<oqs::kem::PublicKey>,
        pub pk_kem_local: Arc<oqs::kem::PublicKey>,
        pub sk_kem_local: Arc<oqs::kem::SecretKey>,
        pub pk_sig_remote: Arc<oqs::sig::PublicKey>,
        pub sk_sig_local: Arc<oqs::sig::SecretKey>,
        pub pk_sig_local: Arc<oqs::sig::PublicKey>,
        pub symmetric_key_local: Box<dyn AeadModule>,
        pub symmetric_key_remote: Box<dyn AeadModule>,
    }

    impl AeadModule for KyberModule {
        fn encrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            // sign the header only, append, then encrypt
            // signing the header ensures header does not change
            // encrypting the input ciphertext + the signature ensures ciphertext works
            let sig = oqs::sig::Sig::new(self.sig_alg.into())
                .map_err(|err| EzError::Other(err.to_string()))?;

            // include ratcheted symmetric key into equation by encrypting null input
            let aes_nonce = &nonce[..AES_GCM_NONCE_LENGTH_BYTES];
            let x_key = self.symmetric_key_local.encrypt(aes_nonce, &[])?;
            // append the x-key, that way the post-quantum signature includes it
            input
                .extend_from_slice(&x_key)
                .map_err(|err| EzError::Other(err.to_string()))?;

            let signature = sig
                .sign(ad, self.sk_sig_local.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;
            // append the signature of the header onto the plaintext
            input
                .extend_from_slice(signature.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;
            let len_bytes = &(signature.len() as u64).to_be_bytes();
            input.extend_from_slice(len_bytes).unwrap();

            let remote_public_key = &*self.pk_kem_remote;

            // now, encrypt the input
            let output = encrypt_pke(self.kem_alg, remote_public_key, input.as_ref(), &nonce)?;
            input.truncate(0);
            input
                .extend_from_slice(output.as_slice())
                .map_err(|err| EzError::Other(err.to_string()))?;

            Ok(())
        }

        fn decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            let sig = oqs::sig::Sig::new(self.sig_alg.into())
                .map_err(|err| EzError::Other(err.to_string()))?;
            let local_sk = self.sk_kem_local.as_ref();
            // decrypt
            let mut plaintext_and_signature = decrypt_pke(self.kem_alg, local_sk, &input)?;
            let total_len = plaintext_and_signature.len();
            let sig_size_bytes = &plaintext_and_signature[total_len.saturating_sub(8)..];
            // TODO: bounds checks
            let sig_len = NetworkEndian::read_u64(sig_size_bytes) as usize;

            if sig_len > sig.length_signature() {
                return Err(EzError::Generic(
                    "The inscribed signature length is too large",
                ));
            }

            plaintext_and_signature.truncate(total_len.saturating_sub(8));
            // the plaintext is the normal plaintext + signature of the header. Extract the signature
            let signature_start = plaintext_and_signature.len().saturating_sub(sig_len);
            let signature = &plaintext_and_signature[signature_start..];
            let plaintext = &plaintext_and_signature[..signature_start];

            let pk_sig_remote = &*self.pk_sig_remote;

            let signature = sig
                .signature_from_bytes(signature)
                .ok_or(EzError::Generic("Bad signature length"))?;

            // verify the signature of the header. If header was changed in transit, this step
            // will fail
            sig.verify(ad, &signature, pk_sig_remote)
                .map_err(|_| EzError::DecryptionFailure)?;

            // additionally, verify the x-key
            let split_pt = plaintext.len() - 16; // 128-bit block size gcm
            let (plaintext, x_key) = plaintext.split_at(split_pt);
            let aes_nonce = &nonce[..AES_GCM_NONCE_LENGTH_BYTES];
            let _ = self.symmetric_key_remote.decrypt(aes_nonce, x_key)?;

            // HACK. Insert the plaintext
            input.truncate(0);
            input
                .extend_from_slice(plaintext)
                .map_err(|err| EzError::Other(err.to_string()))?;

            Ok(())
        }
    }

    pub fn encrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        _: KemAlgorithm,
        local_pk: T,
        plaintext: R,
        nonce: V,
    ) -> Result<Vec<u8>, EzError> {
        kyber_pke::encrypt(local_pk, plaintext, nonce).map_err(|_| EzError::EncryptionFailure)
    }

    pub fn decrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        _: KemAlgorithm,
        local_sk: T,
        ciphertext: R,
    ) -> Result<Vec<u8>, EzError> {
        kyber_pke::decrypt(local_sk, ciphertext).map_err(|_| EzError::DecryptionFailure)
    }
}

#[cfg(test)]
mod tests {
    use crate::KemAlgorithm;
    use oqs::kem::Algorithm;

    #[test]
    fn test_kyber_with_oqs() {
        let kem = oqs::kem::Kem::new(Algorithm::Kyber1024).unwrap();
        let (pk_alice, sk_alice) = kem.keypair().unwrap();
        let (pk_bob, sk_bob) = kem.keypair().unwrap();
        let (ct, ss_bob) = kem.encapsulate(&pk_alice).unwrap();
        let ss_alice = kem.decapsulate(&sk_alice, &ct).unwrap();
        assert_eq!(ss_alice, ss_bob);
        let message = b"Hello, world!" as &[u8];
        // TODO: the problem is that local_sk is not mathematically tethered to bob/alice pair.
        // THIS test proves this works, we just need to make sure in lib.rs implementation, it works
        let nonce = (0..32).into_iter().map(|r| r as u8).collect::<Vec<u8>>();
        // alice uses bob's public key to encrypt
        let ciphertext =
            super::kyber_module::encrypt_pke(KemAlgorithm::Kyber1024, &pk_bob, message, &nonce)
                .unwrap();
        // bob uses his secret key to decrypt
        let recovered =
            super::kyber_module::decrypt_pke(KemAlgorithm::Kyber1024, sk_bob, ciphertext).unwrap();
        assert_eq!(message, recovered);

        // bob uses alice's public key to encrypt
        let ciphertext =
            super::kyber_module::encrypt_pke(KemAlgorithm::Kyber1024, &pk_alice, message, &nonce)
                .unwrap();
        // alice uses her secret key to decrypt
        let recovered =
            super::kyber_module::decrypt_pke(KemAlgorithm::Kyber1024, sk_alice, ciphertext)
                .unwrap();
        assert_eq!(message, recovered);
    }
}
