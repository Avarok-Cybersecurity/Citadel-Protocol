use std::fmt::{Display, Formatter};

/// The default error type for this crate
#[derive(Debug)]
pub enum EzError {
    /// The shared secret is not loaded
    SharedSecretNotLoaded,
    /// Failed to encrypt the data
    EncryptionFailure,
    /// Failed to decrypt the data
    DecryptionFailure,
    /// For generic error types
    Generic(&'static str),
    /// For message types requiring heap
    Other(String),
}

impl Display for EzError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let val = match self {
            EzError::SharedSecretNotLoaded => "Shared secret not loaded",
            EzError::EncryptionFailure => "AES-GCM Encryption Failure",
            EzError::DecryptionFailure => "AES-GCM Decryption Failure",
            EzError::Generic(val) => val,
            EzError::Other(val) => val.as_str(),
        };

        write!(f, "{}", val)
    }
}

impl std::error::Error for EzError {}
