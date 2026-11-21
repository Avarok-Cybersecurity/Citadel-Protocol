//! Secure Configuration Exchange for NAT Traversal
//!
//! This module provides secure packet encryption and decryption for hole punching
//! configuration exchange. It ensures that sensitive network configuration data
//! remains confidential during the NAT traversal process. The STUN servers a punch uses are
//! not part of it: they are required configuration, passed to
//! [`EndpointHolePunchExt::begin_udp_hole_punch`](crate::udp_traversal::udp_hole_puncher::EndpointHolePunchExt::begin_udp_hole_punch).
//!
//! # Features
//!
//! - Secure packet encryption/decryption
//! - Zero-copy packet handling
//! - Thread-safe design
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
//! use bytes::BytesMut;
//!
//! // Create encryption functions
//! let encrypt = |data: &[u8]| BytesMut::from(data);
//! let decrypt = |data: &[u8]| Some(BytesMut::from(data));
//!
//! let container = HolePunchConfigContainer::new(encrypt, decrypt);
//!
//! // Use container for secure packet exchange
//! let packet = container.generate_packet(b"config");
//! let decrypted = container.decrypt_packet(&packet);
//! ```
//!
//! # Important Notes
//!
//! - The provided functions are used in every build, `localhost-testing` included
//! - Functions must be Send + Sync for thread safety
//! - Packet encryption is zero-copy optimized
//! - Custom encryption schemes can be injected
//! - There is no default: an identity cipher would punch in the clear, so every caller names
//!   its functions (PCND):
//!
//! ```compile_fail,E0599
//! use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
//! let _ = HolePunchConfigContainer::default();
//! ```
//!
//! # Related Components
//!
//! - [`crate::udp_traversal::linear::method3`] - NAT traversal method
//! - [`crate::standard::tls`] - TLS configuration
//! - [`crate::standard::quic`] - QUIC protocol support
//!

use bytes::BytesMut;
use std::sync::Arc;

/// Stores the functions relevant to encrypting and decrypting hole-punch related packets
#[derive(Clone)]
pub struct HolePunchConfigContainer {
    // the input into the function is the local port, which is expected to be inscribed inside the payload in an identifiable way
    generate_packet: CryptFunction<BytesMut>,
    // the input into the function are the encrypted bytes
    decrypt_packet: CryptFunction<Option<BytesMut>>,
}

type CryptFunction<T> = Arc<dyn for<'a> Fn(&'a [u8]) -> T + Send + Sync + 'static>;

impl HolePunchConfigContainer {
    /// Wraps the provided functions into a portable abstraction. Every build uses them:
    /// a test build that swapped in identity functions would never run the sealed punch
    /// that production runs.
    pub fn new(
        generate_packet: impl Fn(&[u8]) -> BytesMut + Send + Sync + 'static,
        decrypt_packet: impl Fn(&[u8]) -> Option<BytesMut> + Send + Sync + 'static,
    ) -> Self {
        Self {
            generate_packet: Arc::new(generate_packet),
            decrypt_packet: Arc::new(decrypt_packet),
        }
    }

    /// Generates a packet
    pub fn generate_packet(&self, plaintext: &[u8]) -> BytesMut {
        (self.generate_packet)(plaintext)
    }

    /// Decrypts the payload, returning Some if success
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Option<BytesMut> {
        (self.decrypt_packet)(ciphertext)
    }
}

/// The identity cipher, for this crate's unit tests only: production always passes the
/// session's AEAD, so no build can fall back to it (the type has no `Default`).
#[cfg(test)]
pub(crate) fn identity_for_tests() -> HolePunchConfigContainer {
    HolePunchConfigContainer::new(|p| BytesMut::from(p), |p| Some(BytesMut::from(p)))
}
