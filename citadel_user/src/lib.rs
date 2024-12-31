//! # Citadel User Management System
//!
//! A comprehensive user and account management system for the Citadel Protocol, handling both
//! network nodes and client accounts within the VPN architecture. This crate provides
//! the foundational user management layer for the entire Citadel Protocol ecosystem.
//!
//! ## Features
//!
//! * **Account System**:
//!   - Network Accounts: Core network identity
//!   - Client Accounts: Per-connection user accounts
//!
//! * **Backend Support**:
//!   - File System Storage: Persistent local storage
//!   - Redis Database: High-performance caching
//!   - SQL Database: Relational data storage
//!   - In-Memory Storage: Fast temporary storage
//!
//! * **Authentication**:
//!   - Secure Credential Management: Password and key handling
//!   - Google Authentication: OAuth and service account support
//!   - Custom Authentication: Extensible provider system
//!
//! * **External Services**:
//!   - Google Services: Cloud service integration
//!   - Firebase RTDB: Real-time data synchronization
//!   - Service Interface: Common communication layer
//!
//! * **Account Management**:
//!   - Account Creation: Secure account initialization
//!   - Credential Updates: Safe password and key rotation
//!   - State Management: Account lifecycle handling
//!   - Account Recovery: Backup and restore features
//!
//! ## Architecture
//!
//! The system is built on a network-client account structure:
//!
//! ```text
//! Network Account (NAC)
//! └── Client Account (CNAC)
//!     ├── Connection Metadata
//!     ├── Credentials
//!     └── External Services
//! ```
//!
//! ## Security Features
//!
//! * Zero-trust architecture
//! * Post-quantum cryptography support
//! * Secure credential storage
//! * Safe account recovery
//! * Encrypted data transmission
//!
//! ## Important Notes
//!
//! * Multiple ClientAccounts can exist per node
//! * All operations are safe and secure by default
//! * File system operations are feature-gated, enabled by default
//! * External services require appropriate feature flags
//!
//! ## Related Components
//!
//! * [`citadel_crypt`]: Cryptographic operations
//! * [`citadel_wire`]: Network communication
//! * [`citadel_types`]: Common type definitions
//! * [`citadel_pqcrypto`]: Post-quantum cryptography
//!
//! ## Feature Flags
//!
//! * `filesystem`: Enable file system storage
//! * `google-services`: Enable Google service integration
//! * `redis`: Enable Redis database support
//! * `sql`: Enable SQL database support
//!
#![forbid(unsafe_code)]
#![deny(
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    unused_results
)]
#![allow(rustdoc::broken_intra_doc_links)]

/// Standard imports for this library
pub mod prelude {
    pub use crate::client_account::*;
    pub use crate::connection_metadata::*;
    pub use crate::hypernode_account::*;
    pub use citadel_crypt::scramble::streaming_crypt_scrambler::MAX_BYTES_PER_GROUP;
}

/// Serde and others
pub mod re_exports {
    #[cfg(all(feature = "filesystem", not(target_family = "wasm")))]
    pub use crate::directory_store::DirectoryStore;
    #[cfg(feature = "google-services")]
    pub use firebase_rtdb::FirebaseRTDB;
    pub use serde::*;
}

/// The general trait for creating account types
pub mod hypernode_account;

/// Each node must necessarily have a NetworkAccount that is invariant to any ClientAccounts.
/// See the description for [client_account] below for more information.
pub mod connection_metadata;

/// Each client within a VPN has a unique ClientAccount. Multiple CAC's are possible per node.
///
/// Structural design notes: In production mode, it is necessary that a [ClientNetworkAccount] be
/// created by virtue of the subroutines within the [NetworkAccount]. In other words, a NAC is not
/// only needed, but also the means for creating a CNAC. NAC -> CNAC. It terms of abstraction, we
/// now ascend a level: Let the node at any point along the network, independent of central server,
/// be called a NAC. A NAC is necessary to connect and create mutually-trusted connections within
/// the WAN (Wide-area network).
///
/// evoc_null(web 3.0) => void && let void alloc finite && set network evoc_null(!VPN)
pub mod client_account;

#[cfg(feature = "filesystem")]
/// This provides methods to load all locally-stored files
pub mod account_loader;
/// The server in legacy_citadel_proto requires a means of handling the user database. This module contains the means of achieving this
pub mod account_manager;
/// For authentication
pub mod auth;
/// For handling different I/O operations
pub mod backend;
pub mod credentials;
#[cfg(feature = "filesystem")]
/// Environmental constants and subroutines for pre-checking the system
pub mod directory_store;
/// For services
pub mod external_services;
/// For errors
pub mod misc;
/// Contains basic subroutines for serialization
pub mod serialization;
pub mod server_misc_settings;
