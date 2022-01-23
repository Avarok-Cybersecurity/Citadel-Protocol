use std::fmt::{Display, Formatter};

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


impl Display for EzError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let val = match *self {
            EzError::SharedSecretNotLoaded => "Shared secret not loaded",
            EzError::AesGcmEncryptionFailure => "AES-GCM Encryption Failure",
            EzError::AesGcmDecryptionFailure => "AES-GCM Decryption Failure",
            EzError::Generic(val) => val
        };

        write!(f, "{}", val)
    }
}

impl std::error::Error for EzError {}