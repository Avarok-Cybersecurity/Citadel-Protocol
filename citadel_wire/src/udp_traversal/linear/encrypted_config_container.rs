//! Secure Configuration Exchange for NAT Traversal
//!
//! This module provides secure packet encryption and decryption for hole punching
//! configuration exchange. It ensures that sensitive network configuration data
//! remains confidential during the NAT traversal process, while supporting custom
//! STUN server configurations.
//!
//! # Features
//!
//! - Secure packet encryption/decryption
//! - Custom STUN server support
//! - Zero-copy packet handling
//! - Localhost testing mode
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
//! // Create container with custom STUN servers
//! let stun_servers = vec!["stun.example.com:3478".to_string()];
//! let container = HolePunchConfigContainer::new(
//!     encrypt,
//!     decrypt,
//!     Some(stun_servers)
//! );
//!
//! // Use container for secure packet exchange
//! let packet = container.generate_packet(b"config");
//! let decrypted = container.decrypt_packet(&packet);
//! ```
//!
//! # Important Notes
//!
//! - Encryption is disabled in localhost testing mode
//! - Functions must be Send + Sync for thread safety
//! - Packet encryption is zero-copy optimized
//! - STUN servers can be configured at runtime
//! - Custom encryption schemes can be injected
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
    // custom STUN servers
    stun_servers: Option<Vec<String>>,
}

type CryptFunction<T> = Arc<dyn for<'a> Fn(&'a [u8]) -> T + Send + Sync + 'static>;

impl HolePunchConfigContainer {
    /// Wraps the provided functions into a portable abstraction
    #[cfg(not(feature = "localhost-testing"))]
    pub fn new(
        _generate_packet: impl Fn(&[u8]) -> BytesMut + Send + Sync + 'static,
        _decrypt_packet: impl Fn(&[u8]) -> Option<BytesMut> + Send + Sync + 'static,
        stun_servers: Option<Vec<String>>,
    ) -> Self {
        Self {
            generate_packet: Arc::new(_generate_packet),
            decrypt_packet: Arc::new(_decrypt_packet),
            stun_servers,
        }
    }

    // disable encryption
    #[cfg(feature = "localhost-testing")]
    pub fn new(
        _generate_packet: impl Fn(&[u8]) -> BytesMut + Send + Sync + 'static,
        _decrypt_packet: impl Fn(&[u8]) -> Option<BytesMut> + Send + Sync + 'static,
        stun_servers: Option<Vec<String>>,
    ) -> Self {
        Self {
            stun_servers,
            ..Default::default()
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

    pub fn take_stun_servers(&mut self) -> Option<Vec<String>> {
        self.stun_servers.take()
    }
}

impl Default for HolePunchConfigContainer {
    // identity transformation
    fn default() -> Self {
        Self {
            generate_packet: Arc::new(|input| BytesMut::from(input)),
            decrypt_packet: Arc::new(|input| Some(BytesMut::from(input))),
            stun_servers: None,
        }
    }
}
