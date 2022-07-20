//! Hyxe Cryptography is a crypto crate designed for use in the Lusna Protocol
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

    pub use ez_pqcrypto::constructor_opts::ConstructorOpts;
    pub use ez_pqcrypto::{algorithm_dictionary, bytes_in_place::EzBuffer, PostQuantumContainer};

    pub use crate::drill::{Drill, SecurityLevel};
    pub use crate::misc::CryptError;
    pub use crate::packet_vector::PacketVector;
    pub use crate::secure_buffer::sec_bytes::SecBuffer;
    pub use crate::secure_buffer::sec_string::SecString;
    pub use crate::toolset::Toolset;
}

/// For argon-related functionality
pub mod argon;
/// Organizes the different types of drills that can be used. Currently, there is only one: The Standard Drill
pub mod drill;
/// An abstraction binding the drill and the PQC
pub mod endpoint_crypto_container;
/// Contains the cryptographic primitives for handling FCM interactions on the network
pub mod fcm;
/// Error type
pub mod misc;
/// Contains the subroutines for network-related functionality
pub mod net;
/// For endowing packets with coordinates
pub mod packet_vector;
/// Cryptographic container for handling routes
pub mod relay_chain;
/// For secure byte handling
pub mod secure_buffer;
/// This is a container for holding the drill and PQC, and is intended to replace the seperate use of the drill/PQC
pub mod stacked_ratchet;
/// Allows thread-pooled asynchronous and parallel file processing
pub mod streaming_crypt_scrambler;
///
pub mod sync_toggle;
/// Provides drill management, update, and versioning. This is what's exposed to the hyxe_user api. The drills themselves are abstracted beneath
pub mod toolset;
