use crate::ez_error::EzError;
use aes_gcm_siv::aead::Buffer;

pub trait AeadModule: Send + Sync {
    fn encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError>;
    fn encrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError>;
    fn decrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError>;
    fn decrypt(&self, nonce: &[u8], input:&[u8]) -> Result<Vec<u8>, EzError>;
}

pub(crate) mod aes_impl {
    use aes_gcm_siv::aead::generic_array::GenericArray;
    use aes_gcm_siv::aead::{Aead, Buffer, AeadInPlace};
    use crate::encryption::AeadModule;
    use aes_gcm_siv::Aes256GcmSiv;
    use crate::ez_error::EzError;

    impl AeadModule for Aes256GcmSiv {

        fn encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
            <Self as Aead>::encrypt(self, GenericArray::from_slice(nonce), input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn encrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError> {
            <Self as AeadInPlace>::encrypt_in_place(self, GenericArray::from_slice(nonce), ad, input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn decrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError> {
            <Self as AeadInPlace>::decrypt_in_place(self, GenericArray::from_slice(nonce), ad, input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn decrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
            <Self as Aead>::decrypt(self, GenericArray::from_slice(nonce), input).map_err(|_| EzError::AesGcmDecryptionFailure)
        }
    }
}

pub(crate) mod chacha_impl {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::{Aead, AeadInPlace};
    use crate::encryption::AeadModule;
    use crate::ez_error::EzError;
    use chacha20poly1305::XChaCha20Poly1305;
    use aes_gcm_siv::aead::Buffer;

    impl AeadModule for XChaCha20Poly1305 {

        fn encrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
            <Self as Aead>::encrypt(self, GenericArray::from_slice(nonce), input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn encrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError> {
            <Self as AeadInPlace>::encrypt_in_place(self, GenericArray::from_slice(nonce), ad, input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn decrypt_in_place(&self, nonce: &[u8], ad: &[u8], input: &mut dyn Buffer) -> Result<(), EzError> {
            <Self as AeadInPlace>::decrypt_in_place(self, GenericArray::from_slice(nonce), ad, input).map_err(|_| EzError::AesGcmEncryptionFailure)
        }

        fn decrypt(&self, nonce: &[u8], input: &[u8]) -> Result<Vec<u8>, EzError> {
            <Self as Aead>::decrypt(self, GenericArray::from_slice(nonce), input).map_err(|_| EzError::AesGcmDecryptionFailure)
        }
    }
}