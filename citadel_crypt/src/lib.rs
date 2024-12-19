//! # Citadel Cryptographic Core (citadel_crypt)
//!
//! A comprehensive cryptographic framework providing secure communication primitives for the Citadel Protocol.
//! This crate serves as the cryptographic backbone, implementing various security mechanisms including
//! post-quantum cryptography, perfect forward secrecy, and anti-replay protection.
//!
//! ## Features
//!
//! * **Post-Quantum Security**: Integration with quantum-resistant cryptographic algorithms
//! * **Perfect Forward Secrecy**: Implemented through stacked ratchet mechanisms
//! * **Secure Memory Management**: Zero-copy secure buffer implementations for sensitive data
//! * **Entropy Management**: Sophisticated entropy banking system for secure key derivation
//! * **Network Security**: Packet vectorization and port scrambling for enhanced communication security
//! * **FCM (Forward Chain Messaging)**: Cryptographic primitives for secure message forwarding
//! * **Argon2 Integration**: Memory-hard key derivation with auto-tuning capabilities
//!
//! ## Important Notes
//!
//! * All cryptographic operations are designed to be thread-safe and memory-efficient
//! * The crate implements defense-in-depth with multiple layers of security
//! * Zero-copy operations are used where possible to minimize exposure of sensitive data
//! * Automatic memory zeroing is implemented for sensitive data structures
//!
//! ## Related Components
//!
//! * `citadel_pqcrypto`: Post-quantum cryptographic primitives
//! * `citadel_types`: Common type definitions used across the Citadel Protocol
//! * `citadel_wire`: Network protocol implementation
//!

#![deny(
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    unused_results
)]

/// Convenient imports for external use
pub mod prelude {
    pub use ::async_trait::async_trait;

    pub use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    pub use citadel_pqcrypto::{bytes_in_place::EzBuffer, PostQuantumContainer};

    pub use crate::entropy_bank::EntropyBank;
    pub use crate::misc::CryptError;
    pub use crate::packet_vector::PacketVector;
    pub use crate::streaming_crypt_scrambler::FixedSizedSource;
    pub use crate::toolset::Toolset;
    pub use citadel_types::crypto::SecBuffer;
    pub use citadel_types::crypto::SecurityLevel;
}

/// For argon-related functionality
pub mod argon;
/// An abstraction binding the entropy_bank and the PQC
pub mod endpoint_crypto_container;
/// Organizes the different types of entropy_banks that can be used. Currently, there is only one: The Standard Drill
pub mod entropy_bank;
/// Error type
pub mod misc;
/// For endowing packets with coordinates
pub mod packet_vector;
/// Contains the cryptographic primitives for handling FCM interactions on the network
pub mod ratchets;
/// Contains the subroutines for network-related functionality
pub mod scramble;
/// For secure byte handling
pub mod secure_buffer;
/// Allows thread-pooled asynchronous and parallel file processing
pub mod streaming_crypt_scrambler;

///
pub mod ratchet_manager;
pub mod sync_toggle;
/// Provides entropy_bank management, update, and versioning. This is what's exposed to the citadel_user api. The entropy_banks themselves are abstracted beneath
pub mod toolset;
