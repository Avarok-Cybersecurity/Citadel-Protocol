//! Post-Quantum Cryptography Construction Options
//!
//! This module provides configuration and initialization options for post-quantum
//! cryptographic (PQC) operations in the Citadel Protocol. It includes structures for:
//!
//! - Configuring PQC instance parameters
//! - Managing recursive key derivation chains
//! - Handling shared secrets between participants
//!
//! # Features
//!
//! - Flexible cryptographic parameter configuration
//! - Secure recursive key derivation chain management
//! - Support for multi-round key exchanges
//! - Memory-safe secret handling
//!
//! # Examples
//!
//! ```rust
//! use citadel_pqcrypto::constructor_opts::{ConstructorOpts, RecursiveChain};
//! use citadel_types::crypto::CryptoParameters;
//!
//! // Create initial constructor options
//! let opts = ConstructorOpts::new_init(Some(CryptoParameters::default()));
//!
//! // Create chain for key derivation
//! let chain = [1u8; 32];
//! let alice = [2u8; 32];
//! let bob = [3u8; 32];
//! let chain = RecursiveChain::new(chain, alice, bob, true).unwrap();
//! ```
//!
//! # Security Considerations
//!
//! - All cryptographic parameters should be chosen based on security requirements
//! - Chain values must be protected and never exposed outside secure contexts
//! - Previous shared secrets should be carefully managed and zeroized after use
//! - Memory safety is critical for protecting sensitive key material
//!
//! # Related Components
//!
//! - [`citadel_types::crypto`] - Core cryptographic types and parameters
//! - [`citadel_pqcrypto::wire`] - Wire protocol for PQC operations
//! - [`citadel_pqcrypto::key_store`] - Secure key storage functionality

use citadel_types::crypto::CryptoParameters;
use citadel_types::prelude::SecurityLevel;
use serde::{Deserialize, Serialize};

/// WARNING! this struct, especially the `chain`, should never leave a node; it should only be extracted from the previous PQC when bob is constructing his PQC
#[derive(Clone, Default)]
pub struct ConstructorOpts {
    pub cryptography: Option<CryptoParameters>,
    pub chain: Option<RecursiveChain>,
}

pub trait ImpliedSecurityLevel {
    fn implied_security_level(&self) -> SecurityLevel;
}

impl ImpliedSecurityLevel for Vec<ConstructorOpts> {
    fn implied_security_level(&self) -> SecurityLevel {
        assert!(
            !self.is_empty(),
            "Security level cannot be derived from an empty vector"
        );
        assert!(
            self.len() < u8::MAX as usize,
            "Security level does not fit in u8"
        );
        SecurityLevel::from(self.len().saturating_sub(1) as u8)
    }
}

impl ConstructorOpts {
    /// Starts off a f(0) chain with a single layer of ratcheting
    pub fn new_init(cryptography: Option<impl Into<CryptoParameters>>) -> Self {
        Self {
            cryptography: cryptography.map(|r| r.into()),
            chain: None,
        }
    }

    pub fn new_vec_init(
        cryptography: Option<impl Into<CryptoParameters>>,
        security_level: SecurityLevel,
    ) -> Vec<Self> {
        let count = security_level.value() as usize + 1;
        let settings = cryptography.map(|r| r.into()).unwrap_or_default();
        (0..count).map(|_| Self::new_init(Some(settings))).collect()
    }

    /// Generates a new f(n) -> f(n +1) chain
    pub fn new_ratcheted(
        cryptography: Option<impl Into<CryptoParameters>>,
        previous_shared_secret: RecursiveChain,
    ) -> Self {
        Self {
            cryptography: cryptography.map(|r| r.into()),
            chain: Some(previous_shared_secret),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecursiveChain {
    pub chain: [u8; 32],
    pub alice: [u8; 32],
    pub bob: [u8; 32],
    pub(crate) first: bool,
}

impl RecursiveChain {
    pub fn new<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        chain: T,
        alice: R,
        bob: V,
        first: bool,
    ) -> Option<Self> {
        let chain = chain.as_ref();
        let alice = alice.as_ref();
        let bob = bob.as_ref();

        if chain.len() != 32 || alice.len() != 32 || bob.len() != 32 {
            None
        } else {
            let mut chain_ret: [u8; 32] = [0u8; 32];
            let mut alice_ret: [u8; 32] = [0u8; 32];
            let mut bob_ret: [u8; 32] = [0u8; 32];

            for (idx, val) in chain.iter().enumerate() {
                chain_ret[idx] = *val;
            }

            for (idx, val) in alice.iter().enumerate() {
                alice_ret[idx] = *val;
            }

            for (idx, val) in bob.iter().enumerate() {
                bob_ret[idx] = *val;
            }

            Some(Self {
                chain: chain_ret,
                alice: alice_ret,
                bob: bob_ret,
                first,
            })
        }
    }
}
