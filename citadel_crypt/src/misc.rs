//! Cryptographic Utility Functions and Error Types
//!
//! This module provides common utility functions and error types used throughout
//! the cryptographic operations. It includes port mapping generation and a
//! flexible error handling system for cryptographic operations.
//!
//! # Features
//!
//! - Generic cryptographic error type
//! - Error conversion utilities
//! - Random port mapping generation
//! - Security level validation
//! - Debug and Display implementations
//! - Type-safe error conversions
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::misc::{CryptError, create_port_mapping};
//!
//! fn handle_crypto_error() {
//!     // Create and convert error
//!     let error = CryptError::Encrypt("Failed to encrypt data");
//!     let error_string = error.into_string();
//!     
//!     // Generate random port mappings
//!     let port_pairs = create_port_mapping();
//!     for (src, dst) in port_pairs {
//!         println!("Mapping port {} to {}", src, dst);
//!     }
//! }
//! ```
//!
//! # Important Notes
//!
//! - Error types are generic over the error message type
//! - Port mappings are cryptographically random
//! - Error messages are safely convertible
//! - Debug and Display implementations are provided
//! - Port range is configurable via constants
//!
//! # Related Components
//!
//! - [`crate::entropy_bank`] - Uses port mappings
//! - [`citadel_types::crypto::SecurityLevel`] - Security settings

use crate::entropy_bank::DRILL_RANGE;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use std::fmt::{Display, Formatter};

/// Default Error type for this crate
#[derive(Clone)]
pub enum CryptError<T = String> {
    /// Encrypt Error
    Encrypt(T),
    /// Decrypt Error
    Decrypt(T),
    /// Drill update error
    RekeyUpdateError(T),
    /// Out of bounds
    OutOfBoundsError,
    /// This occurs if the byte-valued security level desired does not correspond to an actual [SecurityLevel]
    BadSecuritySetting,
}

impl<T> CryptError<T> {
    /// Use for converting to different types
    pub fn into_string(self) -> String
    where
        T: Into<String>,
    {
        match self {
            CryptError::Encrypt(s) => s.into(),
            CryptError::Decrypt(s) => s.into(),
            CryptError::RekeyUpdateError(s) => s.into(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception".to_string(),
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting".to_string(),
        }
    }

    pub fn as_str(&self) -> &str
    where
        T: AsRef<str>,
    {
        match self {
            CryptError::Encrypt(s) => s.as_ref(),
            CryptError::Decrypt(s) => s.as_ref(),
            CryptError::RekeyUpdateError(s) => s.as_ref(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception",
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting",
        }
    }
}

impl<T: AsRef<str>> std::fmt::Debug for CryptError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

impl<T: AsRef<str>> Display for CryptError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Creates a port pair mapping at random
pub fn create_port_mapping() -> Vec<(u16, u16)> {
    let mut input_ports = Vec::with_capacity(DRILL_RANGE);
    let mut output_ports = Vec::with_capacity(DRILL_RANGE);

    for i in 0..DRILL_RANGE {
        input_ports.push(i);
        output_ports.push(i);
    }

    let mut rng = thread_rng();
    input_ports.as_mut_slice().shuffle(&mut rng);
    output_ports.as_mut_slice().shuffle(&mut rng);

    let mut output_vec = Vec::with_capacity(DRILL_RANGE);
    for i in 0..DRILL_RANGE {
        output_vec.push((input_ports[i] as u16, output_ports[i] as u16));
    }

    output_vec
}
