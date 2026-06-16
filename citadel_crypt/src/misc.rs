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
//!     let error = CryptError::encrypt("Failed to encrypt data");
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
//! - [`crate::ratchets::entropy_bank`] - Uses port mappings
//! - [`citadel_types::crypto::SecurityLevel`] - Security settings

use crate::ratchets::entropy_bank::DRILL_RANGE;
use rand::prelude::SliceRandom;
use rand::thread_rng;

/// Backwards-compatible alias for this crate's error type.
///
/// As part of the workspace-wide error consolidation, `CryptError` is now the canonical
/// [`citadel_io::NetworkError`]. Construct values via the typed helpers (`CryptError::encrypt(msg)`,
/// `CryptError::out_of_bounds()`, …). The former generic parameter has been dropped (the underlying
/// error always carries an owned, boxed message).
pub type CryptError = citadel_io::NetworkError;

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
