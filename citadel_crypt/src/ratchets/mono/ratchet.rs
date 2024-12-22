//! # Firebase Cloud Messaging (FCM) Ratchet
//!
//! This module implements a specialized cryptographic ratchet optimized for Firebase Cloud
//! Messaging (FCM) communication. It provides a lightweight, size-constrained implementation
//! that adheres to FCM's 4KB message limit while maintaining strong security guarantees.
//!
//! ## Features
//! - Compact ratchet implementation for FCM messages
//! - Size-optimized cryptographic operations
//! - Post-quantum cryptography support
//! - Secure key evolution and management
//! - Message protection and validation
//! - Support for local encryption/decryption
//!
//! ## Usage Example
//! ```rust. no_run
//! use crate::citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
//! use citadel_crypt::ratchets::mono::{MonoRatchet, MonoRatchetConstructor};
//! use citadel_crypt::ratchets::Ratchet;
//! use citadel_pqcrypto::constructor_opts::ConstructorOpts;
//! use citadel_types::crypto::SecurityLevel;
//!
//! # fn get_opts() -> Vec<ConstructorOpts> { todo!() }
//! // Create a new ratchet for Alice
//! let cid = 12345;
//! let version = 0;
//! let opts = get_opts();
//! let constructor = MonoRatchetConstructor::new_alice(
//!     opts,
//!     cid,
//!     version,
//! ).unwrap();
//!
//! // Build the ratchet
//! let ratchet = constructor.finish().unwrap();
//!
//! // Use the ratchet for encryption/decryption
//! let message = b"Hello FCM!";
//! let encrypted = ratchet.encrypt(message).unwrap();
//! let decrypted = ratchet.decrypt(&encrypted).unwrap();
//! assert_eq!(message.as_ref(), decrypted.as_slice());
//! ```
//!
//! ## Important Notes
//! - Optimized for FCM's 4KB message size limit
//! - Uses FireSaber for post-quantum security
//! - Implements the Ratchet trait for compatibility
//! - Supports both synchronous and asynchronous operations
//! - Maintains perfect forward secrecy
//!
//! ## Related Components
//! - [`FcmKeys`](super::keys::FcmKeys): FCM credential management
//! - [`EntropyBank`](crate::entropy_bank::EntropyBank): Entropy source
//! - [`PostQuantumContainer`](citadel_pqcrypto::PostQuantumContainer): PQ crypto operations
//! - [`Ratchet`](crate::ratchets::Ratchet): Base ratchet trait

use crate::endpoint_crypto_container::{
    AssociatedCryptoParams, AssociatedSecurityLevel, EndpointRatchetConstructor,
};
use crate::entropy_bank::EntropyBank;
use crate::misc::CryptError;
use crate::ratchets::Ratchet;
use arrayvec::ArrayVec;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::crypto::CryptoParameters;
use citadel_types::crypto::SecurityLevel;
use citadel_types::crypto::LARGEST_NONCE_LEN;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
/// A compact ratchet meant for protocols that require smaller payloads
pub struct MonoRatchet {
    inner: Arc<MonoRatchetInner>,
}

#[derive(Serialize, Deserialize)]
pub struct MonoRatchetInner {
    entropy_bank: EntropyBank,
    pqc: PostQuantumContainer,
}

impl Ratchet for MonoRatchet {
    type Constructor = MonoRatchetConstructor;

    fn get_default_security_level(&self) -> SecurityLevel {
        SecurityLevel::Standard
    }

    fn get_message_pqc_and_entropy_bank_at_layer(
        &self,
        idx: Option<usize>,
    ) -> Result<(&PostQuantumContainer, &EntropyBank), CryptError> {
        if let Some(idx) = idx {
            if idx != 0 {
                return Err(CryptError::OutOfBoundsError);
            }
        }

        Ok((&self.inner.pqc, &self.inner.entropy_bank))
    }

    fn get_scramble_pqc_and_entropy_bank(&self) -> (&PostQuantumContainer, &EntropyBank) {
        // Thin Ratchets have no difference between scramble and message ratchets
        self.get_message_pqc_and_entropy_bank_at_layer(None)
            .expect("This should never fail")
    }

    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts> {
        vec![ConstructorOpts::new_ratcheted(
            Some(self.inner.pqc.params),
            self.inner.pqc.get_chain().unwrap().clone(),
        )]
    }

    fn message_ratchet_count(&self) -> usize {
        1
    }
}

/// Used for constructing the ratchet
#[derive(Serialize, Deserialize)]
pub struct MonoRatchetConstructor {
    params: CryptoParameters,
    pqc: PostQuantumContainer,
    entropy_bank: Option<EntropyBank>,
    nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
    cid: u64,
    version: u32,
}

impl Debug for MonoRatchetConstructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThinRatchetConstructor")
            .field("params", &self.params)
            .field("cid", &self.cid)
            .field("version", &self.version)
            .finish()
    }
}

impl EndpointRatchetConstructor<MonoRatchet> for MonoRatchetConstructor {
    type AliceToBobWireTransfer = MonoAliceToBobTransfer;
    type BobToAliceWireTransfer = MonoBobToAliceTransfer;

    fn new_alice(opts: Vec<ConstructorOpts>, cid: u64, new_version: u32) -> Option<Self> {
        MonoRatchetConstructor::new_alice_constructor(cid, new_version, opts.into_iter().next()?)
    }

    fn new_bob<T: AsRef<[u8]>>(
        _cid: u64,
        opts: Vec<ConstructorOpts>,
        transfer: Self::AliceToBobWireTransfer,
        psks: &[T],
    ) -> Option<Self> {
        MonoRatchetConstructor::new_bob(opts.into_iter().next()?, transfer, psks)
    }

    fn stage0_alice(&self) -> Option<Self::AliceToBobWireTransfer> {
        self.stage0_alice()
    }

    fn stage0_bob(&mut self) -> Option<Self::BobToAliceWireTransfer> {
        self.stage0_bob()
    }

    fn stage1_alice<T: AsRef<[u8]>>(
        &mut self,
        transfer: Self::BobToAliceWireTransfer,
        psks: &[T],
    ) -> Result<(), CryptError> {
        self.stage1_alice(transfer, psks)
    }

    fn update_version(&mut self, version: u32) -> Option<()> {
        self.update_version(version)
    }

    fn finish_with_custom_cid(self, cid: u64) -> Option<MonoRatchet> {
        self.finish_with_custom_cid(cid)
    }

    fn finish(self) -> Option<MonoRatchet> {
        self.finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct MonoAliceToBobTransfer {
    transfer_params: AliceToBobTransferParameters,
    pub params: CryptoParameters,
    nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
    /// the declared cid
    pub cid: u64,
    /// the declared version
    pub version: u32,
}

impl AssociatedSecurityLevel for MonoAliceToBobTransfer {
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Standard
    }
}

impl AssociatedCryptoParams for MonoAliceToBobTransfer {
    fn crypto_params(&self) -> CryptoParameters {
        self.params
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MonoBobToAliceTransfer {
    params_tx: BobToAliceTransferParameters,
    encrypted_entropy_bank_bytes: Vec<u8>,
}

impl AssociatedSecurityLevel for MonoBobToAliceTransfer {
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Standard
    }
}

impl MonoRatchetConstructor {
    /// FCM limits messages to 4Kb, so we need to use firesaber alone
    pub fn new_alice_constructor(cid: u64, version: u32, opts: ConstructorOpts) -> Option<Self> {
        let params = opts.cryptography.unwrap_or_default();
        let pqc = PostQuantumContainer::new_alice(opts).ok()?;

        Some(Self {
            params,
            pqc,
            entropy_bank: None,
            nonce: EntropyBank::generate_public_nonce(params.encryption_algorithm),
            cid,
            version,
        })
    }

    pub fn new_bob<T: AsRef<[u8]>>(
        opts: ConstructorOpts,
        transfer: MonoAliceToBobTransfer,
        psks: &[T],
    ) -> Option<Self> {
        let params = transfer.params;
        let pqc = PostQuantumContainer::new_bob(opts, transfer.transfer_params, psks).ok()?;
        let entropy_bank =
            EntropyBank::new(transfer.cid, transfer.version, params.encryption_algorithm).ok()?;

        Some(Self {
            params,
            pqc,
            entropy_bank: Some(entropy_bank),
            nonce: transfer.nonce,
            cid: transfer.cid,
            version: transfer.version,
        })
    }

    pub fn stage0_alice(&self) -> Option<MonoAliceToBobTransfer> {
        let pk = self.pqc.generate_alice_to_bob_transfer().ok()?;
        Some(MonoAliceToBobTransfer {
            params: self.params,
            transfer_params: pk,
            nonce: self.nonce.clone(),
            cid: self.cid,
            version: self.version,
        })
    }

    pub fn stage0_bob(&mut self) -> Option<MonoBobToAliceTransfer> {
        Some(MonoBobToAliceTransfer {
            params_tx: self.pqc.generate_bob_to_alice_transfer().ok()?,
            encrypted_entropy_bank_bytes: self
                .pqc
                .encrypt(
                    self.entropy_bank.as_ref()?.serialize_to_vec().ok()?,
                    &self.nonce,
                )
                .ok()?,
        })
    }

    pub fn stage1_alice<T: AsRef<[u8]>>(
        &mut self,
        transfer: MonoBobToAliceTransfer,
        psks: &[T],
    ) -> Result<(), CryptError> {
        self.pqc
            .alice_on_receive_ciphertext(transfer.params_tx, psks)
            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;
        let bytes = self
            .pqc
            .decrypt(&transfer.encrypted_entropy_bank_bytes, &self.nonce)
            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;
        let entropy_bank = EntropyBank::deserialize_from(&bytes[..])?;
        self.entropy_bank = Some(entropy_bank);
        Ok(())
    }

    pub fn update_version(&mut self, version: u32) -> Option<()> {
        self.version = version;
        self.entropy_bank.as_mut()?.version = version;
        Some(())
    }

    pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<MonoRatchet> {
        self.cid = cid;
        self.entropy_bank.as_mut()?.cid = cid;
        self.finish()
    }

    pub fn finish(self) -> Option<MonoRatchet> {
        MonoRatchet::try_from(self).ok()
    }
}

impl TryFrom<MonoRatchetConstructor> for MonoRatchet {
    type Error = ();

    fn try_from(value: MonoRatchetConstructor) -> Result<Self, Self::Error> {
        let entropy_bank = value.entropy_bank.ok_or(())?;
        let pqc = value.pqc;
        let inner = MonoRatchetInner { entropy_bank, pqc };
        Ok(MonoRatchet {
            inner: Arc::new(inner),
        })
    }
}
