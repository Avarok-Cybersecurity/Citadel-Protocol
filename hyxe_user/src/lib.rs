#![forbid(unsafe_code)]
//! This crate is meant for containing the user-related libraries for HyperNode accounts. Both NetworkAccount and ClientAccount's are a subset of HyperNode accounts.
//! Every node/device necessarily contains a singular NetworkAccount; for each connection leading into and out of the node, a ClientAccount exists.

#![deny(
    missing_docs,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    unused_results,
    warnings
)]
#![allow(rustdoc::broken_intra_doc_links)]

/// Standard imports for this library
pub mod prelude {
    pub use crate::client_account::*;
    pub use crate::hypernode_account::*;
    pub use crate::network_account::*;
    #[cfg(not(feature = "filesystem"))]
    pub use hyxe_crypt::net::crypt_splitter::MAX_BYTES_PER_GROUP;
    #[cfg(feature = "filesystem")]
    pub use hyxe_crypt::streaming_crypt_scrambler::MAX_BYTES_PER_GROUP;
}

/// Serde and others
pub mod re_imports {
    #[cfg(feature = "filesystem")]
    pub use crate::directory_store::DirectoryStore;
    pub use firebase_rtdb::FirebaseRTDB;
    pub use serde::*;
}

/// The general trait for creating account types
pub mod hypernode_account;

/// Each node must necessarily have a NetworkAccount that is invariant to any ClientAccounts.
/// See the description for [client_account] below for more information.
pub mod network_account;

/// Each client within a HyperVPN has a unique ClientAccount. Multiple CAC's are possible per node.
///
/// Structural design notes: In production mode, it is necessary that a [ClientNetworkAccount] be
/// created by virtue of the subroutines within the [NetworkAccount]. In other words, a NAC is not
/// only needed, but also the means for creating a CNAC. NAC -> CNAC. It terms of abstraction, we
/// now ascend a level: Let the node at any point along the network, independent of central server,
/// be called a NAC. A NAC is necessary to connect and create mutually-trusted connections within
/// the WAN (Wide-area network).
///
/// evoc_null(web 3.0) => void && let void alloc finite && set network evoc_null(!HyperWAN)
pub mod client_account;

#[cfg(feature = "filesystem")]
/// This provides methods to load all locally-stored files
pub mod account_loader;
/// The server in legacy_hyxe_net requires a means of handling the user database. This module contains the means of achieving this
pub mod account_manager;
/// For authentication
pub mod auth;
/// For handling different I/O operations
pub mod backend;
#[cfg(feature = "filesystem")]
/// Environmental constants and subroutines for pre-checking the system
pub mod directory_store;
/// For services
pub mod external_services;
/// For errors
pub mod misc;
/// Contains basic subroutines for serialization
pub mod serialization;
///
pub mod server_misc_settings;
