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
    use crate::{AeadModule, EzError, KemAlgorithm, SigAlgorithm};
    use aes_gcm_siv::aead::Buffer;
    use oqs::sig::Signature;
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
            let signature = sig
                .sign(ad, self.sk_sig_local.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;
            // append the signature of the header onto the plaintext
            log::error!(target: "lusna", "sig len = {} || {}", signature.len(), sig.length_signature());
            input
                .extend_from_slice(signature.as_ref())
                .map_err(|err| EzError::Other(err.to_string()))?;

            let pk_kem_local = self.pk_kem_local.as_ref();

            // now, encrypt the input
            let output = encrypt_pke(self.kem_alg, pk_kem_local, input.as_ref(), &nonce)?;
            input.truncate(0);
            input
                .extend_from_slice(output.as_slice())
                .map_err(|err| EzError::Other(err.to_string()))?;

            log::error!(target: "lusna", "output len = {}", input.len());

            Ok(())
        }

        fn decrypt_in_place(
            &self,
            _nonce: &[u8],
            ad: &[u8],
            input: &mut dyn Buffer,
        ) -> Result<(), EzError> {
            let sig = oqs::sig::Sig::new(self.sig_alg.into())
                .map_err(|err| EzError::Other(err.to_string()))?;
            let local_sk = self.sk_kem_local.as_ref();
            // decrypt
            let plaintext_and_signature = decrypt_pke(self.kem_alg, local_sk, &input)?;
            // the plaintext is the normal plaintext + signature of the header. Extract the signature
            let signature_len = sig.length_signature();
            // TODO: Why is length_signature() different than actual signature length?
            log::error!(target: "lusna", "pt len = {} | sig len = {}", plaintext_and_signature.len(), signature_len);
            let signature_start = plaintext_and_signature.len() - signature_len;
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

            // HACK. Insert the plaintext
            input.truncate(0);
            input
                .extend_from_slice(plaintext)
                .map_err(|err| EzError::Other(err.to_string()))?;

            Ok(())
        }
    }

    fn encrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        _: KemAlgorithm,
        local_pk: T,
        plaintext: R,
        nonce: V,
    ) -> Result<Vec<u8>, EzError> {
        kyber_pke::encrypt(local_pk, plaintext, nonce).map_err(|_| EzError::EncryptionFailure)
    }

    fn decrypt_pke<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        _: KemAlgorithm,
        local_sk: T,
        ciphertext: R,
    ) -> Result<Vec<u8>, EzError> {
        kyber_pke::decrypt(local_sk, ciphertext).map_err(|_| EzError::DecryptionFailure)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_aead_module_aes() {}
}
