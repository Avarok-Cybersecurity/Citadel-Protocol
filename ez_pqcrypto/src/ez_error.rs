/// The default error type for this crate
#[derive(Debug)]
pub enum EzError {
    /// The shared secret is not loaded
    SharedSecretNotLoaded,
    /// Failed to encrypt the data
    AesGcmEncryptionFailure,
    /// Failed to decrypt the data
    AesGcmDecryptionFailure,
    /// For all other error types
    Generic(&'static str)
}

impl ToString for EzError {
    fn to_string(&self) -> String {
        match *self {
            EzError::SharedSecretNotLoaded => "Shared secret not loaded".to_string(),
            EzError::AesGcmEncryptionFailure => "AES-GCM Encryption Failure".to_string(),
            EzError::AesGcmDecryptionFailure => "AES-GCM Decryption Failure".to_string(),
            EzError::Generic(val) => val.to_string()
        }
    }
}