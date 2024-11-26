use aes_gcm::aead::Buffer;
use citadel_types::errors::Error;

pub trait AeadModule: Send + Sync {
    fn encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ret = Vec::from(input);
        self.encrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error>;
    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error>;
    fn decrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ret = Vec::from(input);
        self.decrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }
    /// Encrypts data such that it ensures only the local user may
    /// see the contents, not even the endpoints
    fn local_user_encrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error>;
    fn local_user_decrypt_in_place(
        &self,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error>;

    fn local_user_decrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ret = Vec::from(input);
        self.local_user_decrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }

    fn local_user_encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ret = Vec::from(input);
        self.local_user_encrypt_in_place(nonce, &[], &mut ret)?;
        Ok(ret)
    }
}

pub(crate) mod aes_impl {
    use crate::encryption::AeadModule;
    use crate::PostQuantumMetaKex;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{AeadInPlace, Buffer};
    use aes_gcm::Aes256Gcm;
    use citadel_types::errors::Error;

    pub struct AesModule {
        pub aead: Aes256Gcm,
        pub kex: PostQuantumMetaKex,
    }

    crate::impl_basic_aead_module!(AesModule, citadel_types::crypto::AES_GCM_NONCE_LENGTH_BYTES);
}

pub(crate) mod chacha_impl {
    use crate::encryption::AeadModule;
    use crate::PostQuantumMetaKex;
    use aes_gcm::aead::Buffer;
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::ChaCha20Poly1305;
    use citadel_types::errors::Error;

    pub struct ChaChaModule {
        pub aead: ChaCha20Poly1305,
        pub kex: PostQuantumMetaKex,
    }

    crate::impl_basic_aead_module!(
        ChaChaModule,
        citadel_types::crypto::CHA_CHA_NONCE_LENGTH_BYTES
    );
}

pub(crate) mod ascon_impl {
    use crate::encryption::AeadModule;
    use crate::PostQuantumMetaKex;
    use aes_gcm::aead::Buffer;
    use ascon_aead::Ascon80pq;
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::AeadInPlace;
    use citadel_types::errors::Error;

    pub struct AsconModule {
        pub aead: Ascon80pq,
        pub kex: PostQuantumMetaKex,
    }

    crate::impl_basic_aead_module!(AsconModule, citadel_types::crypto::ASCON_NONCE_LENGTH_BYTES);
}

pub(crate) mod kyber_module {
    #[cfg(target_family = "wasm")]
    use crate::functions::AsSlice;
    use crate::wire::ScramCryptDictionary;
    use crate::{AeadModule, PostQuantumMetaKex, PostQuantumMetaSig};
    use aes_gcm::aead::Buffer;
    use citadel_types::crypto::{KemAlgorithm, SigAlgorithm};
    use citadel_types::errors::Error;

    #[allow(dead_code)]
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
        ) -> Result<(), Error> {
            // sign the header only, append, then encrypt
            // signing the header ensures header does not change
            // encrypting the input ciphertext + the signature ensures ciphertext works

            //let aes_nonce = &nonce[..AES_GCM_NONCE_LENGTH_BYTES];
            let signature = crate::functions::signature_sign(
                sha3_256_with_ad(ad, input.as_ref()),
                self.sig.sig_private_key.as_slice(),
            )?;
            // append the signature of the header onto the plaintext
            input
                .extend_from_slice(signature.as_slice())
                .map_err(|err| Error::Other(err.to_string()))?;
            encode_length_be_bytes(signature.as_slice().len(), input)?;

            // encrypt the data using the remote's public key
            let remote_public_key = self.kex.remote_public_key.as_deref().unwrap();

            core_kyber_otp_encrypt(
                &*self.symmetric_key_local,
                remote_public_key,
                self.kem_alg,
                nonce,
                ad,
                input,
            )
        }

        fn decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), Error> {
            let sig_remote_pk = self.sig.remote_sig_public_key.as_ref().unwrap();
            let secret_key = self.kex.secret_key.as_deref().unwrap();
            core_kyber_otp_decrypt(
                &*self.symmetric_key_remote,
                secret_key,
                self.kem_alg,
                nonce,
                ad,
                input,
            )?;
            // get the signature
            let signature_len = decode_length(input)?;
            let split_pt = input.len().saturating_sub(signature_len);
            let (_, signature_bytes) = input.as_ref().split_at(split_pt);
            let sig_verify_input = sha3_256_with_ad(ad, &input.as_ref()[..split_pt]);
            crate::functions::signature_verify(
                sig_verify_input,
                signature_bytes,
                sig_remote_pk.as_slice(),
            )?;
            // remove the signature from the buffer
            input.truncate(split_pt);

            Ok(())
        }

        fn local_user_encrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), Error> {
            self.symmetric_key_local
                .local_user_encrypt_in_place(nonce, ad, input)
        }

        fn local_user_decrypt_in_place(
            &self,
            nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), Error> {
            self.symmetric_key_local
                .local_user_decrypt_in_place(nonce, ad, input)
        }
    }

    pub fn encrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        kem_alg: KemAlgorithm,
        local_pk: T,
        plaintext: R,
        nonce: V,
    ) -> Result<Vec<u8>, Error> {
        match kem_alg {
            KemAlgorithm::Kyber => kyber_pke::encrypt(local_pk, plaintext, nonce)
                .map_err(|err| Error::Other(format!("{err:?}"))),
        }
    }

    pub fn decrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        kem_alg: KemAlgorithm,
        local_sk: T,
        ciphertext: R,
    ) -> Result<Vec<u8>, Error> {
        match kem_alg {
            KemAlgorithm::Kyber => kyber_pke::decrypt(local_sk, ciphertext)
                .map_err(|err| Error::Other(format!("{err:?}"))),
        }
    }

    fn encode_length_be_bytes(len: usize, buf: &mut dyn Buffer) -> Result<(), Error> {
        let bytes_be = (len as u64).to_be_bytes();
        buf.extend_from_slice(&bytes_be as &[u8])
            .map_err(|err| Error::Other(err.to_string()))?;
        Ok(())
    }

    fn decode_length(input: &mut dyn Buffer) -> Result<usize, Error> {
        let total_len = input.len();
        let starting_pos = total_len.saturating_sub(8);
        let len_be_bytes = &input.as_ref()[starting_pos..];

        if len_be_bytes.len() != 8 {
            return Err(Error::Generic("Bad sig_size_bytes length"));
        }

        let mut len_buf = [0u8; 8];
        len_buf.copy_from_slice(len_be_bytes);

        let object_len = u64::from_be_bytes(len_buf) as usize;

        if object_len > total_len {
            return Err(Error::Other(format!(
                "Decoded length = {object_len}, yet, input buffer's len is only {total_len}",
            )));
        }

        // now, truncate
        input.truncate(starting_pos);

        Ok(object_len)
    }

    pub fn core_kyber_otp_encrypt(
        symmetric_cipher: &dyn AeadModule,
        public_key: impl AsRef<[u8]>,
        kem_alg: KemAlgorithm,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error> {
        // encrypt everything so far with AES GCM
        symmetric_cipher.encrypt_in_place(nonce, ad, input)?;

        let pre_scramble_len = input.len();
        // scramble the AES GCM encrypted ciphertext
        // use N=32 bytes to ensure that we get only a single output ciphertext block from kyber (~1100 bytes)
        let scram_crypt_dict = ScramCryptDictionary::<32>::new().unwrap();
        scram_crypt_dict.scramble_in_place(input)?;
        // encode the pre-scramble length
        encode_length_be_bytes(pre_scramble_len, input)?;
        // encrypt the 32-byte scramble dict using post-quantum pke

        let scram_crypt_ser =
            bincode::serialize(&scram_crypt_dict).map_err(|err| Error::Other(err.to_string()))?;

        let encrypted_scramble_dict = encrypt_pke(kem_alg, public_key, scram_crypt_ser, nonce)?;
        input
            .extend_from_slice(encrypted_scramble_dict.as_slice())
            .map_err(|err| Error::Other(err.to_string()))?;
        encode_length_be_bytes(encrypted_scramble_dict.len(), input)?;

        let sha = sha3_256(input.as_ref());
        input
            .extend_from_slice(&sha)
            .map_err(|err| Error::Other(err.to_string()))?;
        Ok(())
    }

    pub fn core_kyber_otp_decrypt(
        symmetric_cipher: &dyn AeadModule,
        local_sk: impl AsRef<[u8]>,
        kem_alg: KemAlgorithm,
        nonce: &[u8],
        ad: &[u8],
        input: &mut dyn Buffer,
    ) -> Result<(), Error> {
        let (ciphertext, sha_required) = input.as_ref().split_at(input.len().saturating_sub(32));
        let sha_ciphertext = sha3_256(ciphertext);
        if sha_ciphertext != sha_required {
            return Err(Error::Other(format!(
                "Invalid ciphertext checksum. {sha_ciphertext:?} != {sha_required:?}",
            )));
        }

        input.truncate(input.len().saturating_sub(32));

        let encrypted_scramble_dict_len = decode_length(input)?;
        let split_pt = input.len().saturating_sub(encrypted_scramble_dict_len);
        let (_, encrypted_scramble_dict) = input.as_ref().split_at(split_pt);
        let decrypted_scramble_dict = decrypt_pke(kem_alg, local_sk, encrypted_scramble_dict)?;
        let scram_crypt_dict: ScramCryptDictionary<32> =
            bincode::deserialize(&decrypted_scramble_dict)
                .map_err(|err| Error::Other(err.to_string()))?;
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
        symmetric_cipher.decrypt_in_place(nonce, ad, input)?;

        Ok(())
    }

    fn sha3_256(input: &[u8]) -> [u8; 32] {
        sha3_256_with_ad(&[], input)
    }

    fn sha3_256_with_ad(ad: &[u8], input: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        let mut digest = sha3::Sha3_256::default();

        if !ad.is_empty() {
            digest.update(ad);
        }

        digest.update(input);
        digest.finalize().into()
    }
}

#[macro_export]
macro_rules! impl_basic_aead_module {
    ($val:ty, $nonce_len:expr) => {
        impl AeadModule for $val {
            fn encrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                self.aead
                    .encrypt_in_place(GenericArray::from_slice(&nonce[..$nonce_len]), ad, input)
                    .map_err(|_| Error::EncryptionFailure)
            }

            fn decrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                self.aead
                    .decrypt_in_place(GenericArray::from_slice(&nonce[..$nonce_len]), ad, input)
                    .map_err(|_| Error::EncryptionFailure)
            }

            fn local_user_encrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                let public_key = &*self.kex.public_key;
                super::kyber_module::core_kyber_otp_encrypt(
                    self,
                    public_key,
                    self.kex.kem_alg,
                    nonce,
                    ad,
                    input,
                )
            }

            fn local_user_decrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                let private_key = self.kex.secret_key.as_deref().unwrap();
                super::kyber_module::core_kyber_otp_decrypt(
                    self,
                    private_key,
                    self.kex.kem_alg,
                    nonce,
                    ad,
                    input,
                )
            }
        }
    };
}
