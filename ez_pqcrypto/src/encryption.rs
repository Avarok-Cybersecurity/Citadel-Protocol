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
    use crate::wire::ScramCryptDictionary;
    use crate::{
        AeadModule, EzError, KemAlgorithm, PostQuantumMetaKex, PostQuantumMetaSig, SigAlgorithm,
        AES_GCM_NONCE_LENGTH_BYTES,
    };
    use aes_gcm_siv::aead::Buffer;

    pub struct KyberModule {
        pub kem_alg: KemAlgorithm,
        pub sig_alg: SigAlgorithm,
        pub kex: PostQuantumMetaKex,
        pub sig: PostQuantumMetaSig,
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
            let sig_alg = self.sig.sig_alg;

            let sig = oqs::sig::Sig::new(sig_alg).map_err(|err| EzError::Other(err.to_string()))?;

            let aes_nonce = &nonce[..AES_GCM_NONCE_LENGTH_BYTES];
            let signature = sig
                .sign(ad, self.sig.sig_private_key.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;
            // append the signature of the header onto the plaintext
            input
                .extend_from_slice(signature.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;
            encode_length_be_bytes(signature.len(), input)?;

            // encrypt everything so far with AES GCM
            self.symmetric_key_local
                .encrypt_in_place(aes_nonce, ad, input)?;

            let pre_scramble_len = input.len();
            // scramble the AES GCM encrypted ciphertext
            // use N=32 bytes to ensure that we get only a single output ciphertext block from kyber (~1100 bytes)
            let scram_crypt_dict = ScramCryptDictionary::<32>::new().unwrap();
            scram_crypt_dict.scramble_in_place(input)?;
            // encode the pre-scramble length
            encode_length_be_bytes(pre_scramble_len, input)?;
            // encrypt the 32-byte scramble dict using post-quantum pke
            let remote_public_key = &*self.kex.remote_public_key.as_ref().unwrap();

            let scram_crypt_ser = bincode2::serialize(&scram_crypt_dict)
                .map_err(|err| EzError::Other(err.to_string()))?;

            let encrypted_scramble_dict =
                encrypt_pke(self.kem_alg, &**remote_public_key, &scram_crypt_ser, &nonce)?;
            input
                .extend_from_slice(encrypted_scramble_dict.as_slice())
                .map_err(|err| EzError::Other(err.to_string()))?;
            encode_length_be_bytes(encrypted_scramble_dict.len(), input)?;

            let sha = sha3_256(input.as_ref());
            input
                .extend_from_slice(&sha)
                .map_err(|err| EzError::Other(err.to_string()))?;
            log::error!(target: "lusna", "output: {:?}", input.as_ref());
            Ok(())
        }

        fn decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            log::error!(target: "lusna", "input: {:?}", input.as_ref());
            let sig_alg = self.sig.sig_alg;
            let sig = oqs::sig::Sig::new(sig_alg).map_err(|err| EzError::Other(err.to_string()))?;
            let local_sk = self.kex.secret_key.as_deref().unwrap();
            let sig_remote_pk = self.sig.remote_sig_public_key.as_ref().unwrap();

            let (ciphertext, sha_required) =
                input.as_ref().split_at(input.len().saturating_sub(32));
            let sha_ciphertext = sha3_256(ciphertext);
            if sha_ciphertext != sha_required {
                return Err(EzError::Other(format!(
                    "Invalid ciphertext checksum. {:?} != {:?}",
                    sha_ciphertext, sha_required
                )));
            }

            input.truncate(input.len().saturating_sub(32));

            let encrypted_scramble_dict_len = decode_length(input)?;
            let split_pt = input.len().saturating_sub(encrypted_scramble_dict_len);
            let (_, encrypted_scramble_dict) = input.as_ref().split_at(split_pt);
            let decrypted_scramble_dict =
                decrypt_pke(self.kem_alg, local_sk, encrypted_scramble_dict)?;
            //let scram_crypt_dict = ScramCryptDictionary::<32>::try_from(decrypted_scramble_dict)?;
            let scram_crypt_dict: ScramCryptDictionary<32> =
                bincode2::deserialize(&decrypted_scramble_dict)
                    .map_err(|err| EzError::Other(err.to_string()))?;
            // remove the encrypted scramble data from the input buf
            let truncate_point = input.len().saturating_sub(encrypted_scramble_dict_len);
            input.truncate(truncate_point);
            // get the pre-scramble length
            let pre_scramble_length = decode_length(input)?;
            // descramble
            scram_crypt_dict.descramble_in_place(input)?;
            // truncate
            input.truncate(pre_scramble_length);
            // with the AES-GCM encrypted ciphertext descrambled, now, decrypt it
            let aes_nonce = &nonce[..AES_GCM_NONCE_LENGTH_BYTES];
            self.symmetric_key_remote
                .decrypt_in_place(aes_nonce, ad, input)?;
            // get the signature
            let signature_len = decode_length(input)?;
            let split_pt = input.len().saturating_sub(signature_len);
            let (_, signature_bytes) = input.as_ref().split_at(split_pt);
            let signature = sig
                .signature_from_bytes(signature_bytes)
                .ok_or(EzError::Generic("Invalid signature len bytes"))?;
            sig.verify(ad, signature, &**sig_remote_pk).map_err(|err| {
                EzError::Other(format!("Signature verification failed: {:?}", err))
            })?;

            // remove the signature from the buffer
            input.truncate(split_pt);

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
        kyber_pke::decrypt(local_sk, ciphertext).map_err(|err| EzError::Other(format!("{:?}", err)))
    }

    fn encode_length_be_bytes(len: usize, buf: &mut dyn Buffer) -> Result<(), EzError> {
        let bytes_be = (len as u64).to_be_bytes();
        buf.extend_from_slice(&bytes_be as &[u8])
            .map_err(|err| EzError::Other(err.to_string()))?;
        Ok(())
    }

    fn decode_length(input: &mut dyn Buffer) -> Result<usize, EzError> {
        let total_len = input.len();
        let starting_pos = total_len.saturating_sub(8);
        let len_be_bytes = &input.as_ref()[starting_pos..];

        if len_be_bytes.len() != 8 {
            return Err(EzError::Generic("Bad sig_size_bytes length"));
        }

        let mut len_buf = [0u8; 8];
        len_buf.copy_from_slice(len_be_bytes);

        let object_len = u64::from_be_bytes(len_buf) as usize;

        if object_len > total_len {
            return Err(EzError::Other(format!(
                "Decoded length = {}, yet, input buffer's len is only {}",
                object_len, total_len
            )));
        }

        // now, truncate
        input.truncate(starting_pos);

        Ok(object_len)
    }

    fn sha3_256(input: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        let mut digest = sha3::Sha3_256::default();
        digest.update(input);
        digest.finalize().into()
    }
}
