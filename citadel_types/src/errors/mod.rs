use std::fmt::{Debug, Display, Formatter};
#[cfg(feature = "typescript")]
use ts_rs::TS;

/// The default error type for this crate
#[derive(Debug)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum Error {
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
    /// Bad length
    InvalidLength,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}
