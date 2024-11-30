//! WebAssembly-compatible random number generation.
//!
//! This module provides a cryptographically secure random number generator
//! that works in WebAssembly environments. It uses the Web Crypto API through
//! the `getrandom` crate to generate random numbers.

use rand::{CryptoRng, Error, RngCore};

/// A WebAssembly-compatible random number generator that provides
/// cryptographically secure random numbers using the Web Crypto API.
///
/// This type implements both `RngCore` and `CryptoRng` traits, making it
/// suitable for both general-purpose and cryptographic use cases.
///
/// # Example
///
/// ```rust
/// use citadel_io::WasmRng;
/// use rand::RngCore;
///
/// let mut rng = WasmRng::default();
/// let random_number = rng.next_u32();
/// let mut buffer = [0u8; 32];
/// rng.fill_bytes(&mut buffer);
/// ```
#[derive(Default)]
pub struct WasmRng;

impl RngCore for WasmRng {
    /// Generates a random 32-bit unsigned integer.
    fn next_u32(&mut self) -> u32 {
        u32::from_be_bytes(random_array::<4>())
    }

    /// Generates a random 64-bit unsigned integer.
    fn next_u64(&mut self) -> u64 {
        u64::from_be_bytes(random_array::<8>())
    }

    /// Fills the provided buffer with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).unwrap();
    }

    /// Attempts to fill the provided buffer with random bytes.
    /// Returns an error if the operation fails.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(dest).map_err(|err| Error::from(err.code()))
    }
}

// Implement CryptoRng to indicate this is a cryptographically secure RNG
impl CryptoRng for WasmRng {}

/// Helper function to generate a fixed-size array of random bytes.
///
/// # Panics
///
/// This function will panic if the underlying random number generator fails.
/// This should never happen in practice when using the Web Crypto API.
fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}
