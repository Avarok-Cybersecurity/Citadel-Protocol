#![feature(asm, fundamental, generators, generator_trait, arbitrary_self_types, ptr_internals, allocator_api, alloc_layout_extra, stdsimd)]
#![feature(in_band_lifetimes, core_intrinsics, exclusive_range_pattern, nll)]
//! Hyxe Cryptography is a crypto crate designed to asynchronously obscure data, re-assemble, etc

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
    pub use zerocopy::{ByteSlice, ByteSliceMut};

    pub use ez_pqcrypto::{algorithm_dictionary, bytes_in_place::EzBuffer, PostQuantumContainer};

    pub use crate::drill::{Drill, SecurityLevel};
    pub use crate::packet_vector::PacketVector;
    pub use crate::misc::CryptError;
    pub use crate::sec_bytes::SecBuffer;
    pub use crate::sec_string::SecString;
    pub use crate::toolset::Toolset;
    pub use ez_pqcrypto::constructor_opts::ConstructorOpts;
}

/// This serves as a lock-free method of retrieving specific
///pub mod GlobalToolset;

/// Provides drill management, update, and versioning. This is what's exposed to the hyxe_user api. The drills themselves are abstracted beneath
pub mod toolset;

/// Organizes the different types of drills that can be used. Currently, there is only one: The Standard Drill
pub mod drill;

/// For endowing packets with coordinates
pub mod packet_vector;

/// Contains the subroutines for network-related functionality
pub mod net;

/// Contains future-oriented subroutines for encrypting data
pub mod aes_gcm;

/// Error type
pub mod misc;
/// A secure mutable string type
pub mod sec_string;
///
pub mod sec_bytes;
/// Cryptographic container for handling routes
pub mod relay_chain;
/// An abstraction binding the drill and the PQC
pub mod endpoint_crypto_container;
/// This is a container for holding the drill and PQC, and is intended to replace the seperate use of the drill/PQC
pub mod hyper_ratchet;
/// Contains the cryptographic primitives for handling FCM interactions on the network
pub mod fcm;
/// For argon-related functionality
pub mod argon;