//! Stacked Ratchet: Perfect Forward Secrecy with Key Evolution
//!
//! This module implements a stacked ratchet system that provides perfect forward
//! secrecy through continuous key evolution. It supports both message protection
//! and scrambling operations with independent keys.
//!
//! # Features
//!
//! - Perfect forward secrecy
//! - Independent message and scramble keys
//! - Post-quantum cryptography support
//! - Key evolution and ratcheting
//! - Security level configuration
//! - Anti-replay attack protection
//! - Ordered packet delivery
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::ratchets::stacked::{StackedRatchet, constructor::StackedRatchetConstructor};
//! use crate::citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
//! use citadel_pqcrypto::constructor_opts::ConstructorOpts;
//! use citadel_crypt::ratchets::Ratchet;
//! use citadel_types::crypto::SecurityLevel;
//!
//! fn setup_ratchet() -> Option<StackedRatchet> {
//!     // Create constructor options
//!     let opts = vec![ConstructorOpts::default()];
//!     
//!     // Initialize Alice's constructor
//!     let constructor = StackedRatchetConstructor::new_alice(
//!         opts,
//!         1234,  // Client ID
//!         1,     // Version
//!     )?;
//!     
//!     // Generate Alice's initial ratchet
//!     let ratchet = constructor.finish()?;
//!     
//!     // Use ratchet for packet protection
//!     let mut packet = vec![0u8; 64];
//!     ratchet.protect_message_packet(None, 32, &mut packet).ok()?;
//!     
//!     Some(ratchet)
//! }
//! ```
//!
//! # Important Notes
//!
//! - Keys evolve after each use
//! - Message and scramble keys are independent
//! - Security levels affect key composition
//! - Packet order must be maintained
//! - Anti-replay protection is automatic
//!
//! # Related Components
//!
//! - [`EntropyBank`] - Provides entropy for key evolution
//! - [`PostQuantumContainer`] - Post-quantum cryptography
//! - [`crate::endpoint_crypto_container`] - Endpoint state management
//!

use crate::misc::CryptError;
use crate::ratchets::entropy_bank::EntropyBank;
use crate::ratchets::stacked::ratchet::constructor::StackedRatchetConstructor;
use crate::ratchets::Ratchet;
use citadel_pqcrypto::constructor_opts::{ConstructorOpts, RecursiveChain};
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::crypto::SecurityLevel;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::sync::Arc;

/// A container meant to establish perfect forward secrecy AND scrambling w/ an independent key
/// This is meant for messages, not file transfer. File transfers should use a single key throughout
/// the entire file
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StackedRatchet {
    pub(crate) inner: Arc<StackedRatchetInner>,
}

impl Ratchet for StackedRatchet {
    type Constructor = StackedRatchetConstructor;

    /// Gets the default security level (will use all available keys)
    fn get_default_security_level(&self) -> SecurityLevel {
        self.inner.default_security_level
    }

    fn get_message_pqc_and_entropy_bank_at_layer(
        &self,
        idx: Option<usize>,
    ) -> Result<(&PostQuantumContainer, &EntropyBank), CryptError> {
        let idx = idx.unwrap_or(0);
        self.inner
            .message
            .inner
            .get(idx)
            .map(|r| (&r.pqc, &r.entropy_bank))
            .ok_or(CryptError::OutOfBoundsError)
    }

    fn get_scramble_pqc_and_entropy_bank(&self) -> (&PostQuantumContainer, &EntropyBank) {
        (&self.inner.scramble.pqc, &self.inner.scramble.entropy_bank)
    }

    // This may panic if any of the ratchets are in an incomplete state
    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts> {
        let mut meta_chain_hasher = sha3::Sha3_256::default();
        for chain in self
            .inner
            .message
            .inner
            .iter()
            .map(|r| r.pqc.get_chain().unwrap())
        {
            meta_chain_hasher.update(&chain.chain[..]);
        }

        let meta_chain = meta_chain_hasher.finalize();
        //self.inner.message.inner.iter().map(|r| ConstructorOpts::new_from_previous(Some(r.pqc.params), r.pqc.get_chain().unwrap().clone())).collect()
        self.inner
            .message
            .inner
            .iter()
            .map(|r| {
                let prev_chain = r.pqc.get_chain().unwrap();
                let next_chain =
                    RecursiveChain::new(&meta_chain[..], prev_chain.alice, prev_chain.bob, false)
                        .unwrap();
                ConstructorOpts::new_ratcheted(Some(r.pqc.params), next_chain)
            })
            .collect()
    }

    fn message_ratchet_count(&self) -> usize {
        self.inner.message.inner.len()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackedRatchetInner {
    pub(crate) message: MessageRatchet,
    pub(crate) scramble: ScrambleRatchet,
    pub(crate) default_security_level: SecurityLevel,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MessageRatchet {
    inner: Vec<MessageRatchetInner>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MessageRatchetInner {
    pub(crate) entropy_bank: EntropyBank,
    pub(crate) pqc: PostQuantumContainer,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ScrambleRatchet {
    pub(crate) entropy_bank: EntropyBank,
    pub(crate) pqc: PostQuantumContainer,
}

impl From<StackedRatchetInner> for StackedRatchet {
    fn from(inner: StackedRatchetInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

/// For constructing the StackedRatchet during KEM stage
pub mod constructor {
    use crate::endpoint_crypto_container::{
        AssociatedCryptoParams, AssociatedSecurityLevel, EndpointRatchetConstructor,
    };
    use crate::prelude::CryptError;
    use crate::ratchets::entropy_bank::EntropyBank;
    use crate::ratchets::stacked::ratchet::StackedRatchet;
    use arrayvec::ArrayVec;
    use citadel_pqcrypto::constructor_opts::{ConstructorOpts, ImpliedSecurityLevel};
    use citadel_pqcrypto::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
    use citadel_pqcrypto::PostQuantumContainer;
    use citadel_types::crypto::CryptoParameters;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::crypto::LARGEST_NONCE_LEN;
    use serde::{Deserialize, Serialize};
    use std::fmt::{Debug, Formatter};

    /// Used during the key exchange process
    #[derive(Serialize, Deserialize)]
    pub struct StackedRatchetConstructor {
        pub(crate) message: MessageRatchetConstructor,
        pub(crate) scramble: ScrambleRatchetConstructor,
        nonce_message: ArrayVec<u8, LARGEST_NONCE_LEN>,
        nonce_scramble: ArrayVec<u8, LARGEST_NONCE_LEN>,
        cid: u64,
        new_version: u32,
        security_level: SecurityLevel,
        params: CryptoParameters,
    }

    impl Debug for StackedRatchetConstructor {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ThinRatchetConstructor")
                .field("params", &self.params)
                .field("cid", &self.cid)
                .field("version", &self.new_version)
                .finish()
        }
    }

    impl EndpointRatchetConstructor<StackedRatchet> for StackedRatchetConstructor {
        type AliceToBobWireTransfer = AliceToBobTransfer;
        type BobToAliceWireTransfer = BobToAliceTransfer;

        fn new_alice(opts: Vec<ConstructorOpts>, cid: u64, new_version: u32) -> Option<Self> {
            let security_level = opts.implied_security_level();
            log::trace!(target: "citadel", "[ALICE] Client {cid} creating container with {:?} security level", security_level);
            //let count = security_level.value() as usize + 1;
            let len = opts.len();
            let params = opts[0].cryptography.unwrap_or_default();
            let keys = opts
                .into_iter()
                .filter_map(|opts| {
                    Some(MessageRatchetConstructorInner {
                        entropy_bank: None,
                        pqc: PostQuantumContainer::new_alice(opts).ok()?,
                    })
                })
                .collect::<Vec<MessageRatchetConstructorInner>>();

            if keys.len() != len {
                return None;
            }

            Some(Self {
                params,
                message: MessageRatchetConstructor { inner: keys },
                scramble: ScrambleRatchetConstructor {
                    entropy_bank: None,
                    pqc: PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(params)))
                        .ok()?,
                },
                nonce_message: EntropyBank::generate_public_nonce(params.encryption_algorithm),
                nonce_scramble: EntropyBank::generate_public_nonce(params.encryption_algorithm),
                cid,
                new_version,
                security_level,
            })
        }

        fn new_bob<T: AsRef<[u8]>>(
            cid: u64,
            opts: Vec<ConstructorOpts>,
            transfer: Self::AliceToBobWireTransfer,
            psks: &[T],
        ) -> Option<Self> {
            let new_version = transfer.new_version;
            log::trace!(target: "citadel", "[BOB] Client {cid} creating container with {:?} security level", transfer.security_level);
            let count = transfer.security_level.value() as usize + 1;
            let params = transfer.params;
            let keys: Vec<MessageRatchetConstructorInner> = transfer
                .params_txs
                .into_iter()
                .zip(opts)
                .filter_map(|(params_tx, opts)| {
                    let entropy_bank =
                        EntropyBank::new(cid, new_version, params.encryption_algorithm).ok()?;
                    Some(MessageRatchetConstructorInner {
                        entropy_bank: Some(entropy_bank),
                        pqc: PostQuantumContainer::new_bob(opts, params_tx, psks).ok()?,
                    })
                })
                .collect();

            if keys.len() != count {
                log::error!(target: "citadel", "[BOB] not all keys parsed correctly. {} != {}", keys.len(), count);
                return None;
            }

            let scramble_entropy_bank =
                EntropyBank::new(cid, new_version, params.encryption_algorithm).ok()?;

            Some(Self {
                params,
                message: MessageRatchetConstructor { inner: keys },
                scramble: ScrambleRatchetConstructor {
                    entropy_bank: Some(scramble_entropy_bank),
                    pqc: PostQuantumContainer::new_bob(
                        ConstructorOpts::new_init(Some(params)),
                        transfer.scramble_alice_params,
                        psks,
                    )
                    .ok()?,
                },
                nonce_message: transfer.msg_nonce,
                nonce_scramble: transfer.scramble_nonce,
                cid,
                new_version,
                security_level: transfer.security_level,
            })
        }

        fn stage0_alice(&self) -> Option<Self::AliceToBobWireTransfer> {
            let pks = self
                .message
                .inner
                .iter()
                .filter_map(|inner| inner.pqc.generate_alice_to_bob_transfer().ok())
                .collect::<Vec<AliceToBobTransferParameters>>();

            if pks.len() != self.message.inner.len() {
                return None;
            }

            let scramble_alice_pk = self.scramble.pqc.generate_alice_to_bob_transfer().ok()?;
            let msg_nonce = self.nonce_message.clone();
            let scramble_nonce = self.nonce_scramble.clone();
            let cid = self.cid;
            let new_version = self.new_version;
            let params = self.params;
            let security_level = self.security_level;

            Some(AliceToBobTransfer {
                params,
                params_txs: pks,
                scramble_alice_params: scramble_alice_pk,
                msg_nonce,
                scramble_nonce,
                security_level,
                cid,
                new_version,
            })
        }

        fn stage0_bob(&mut self) -> Option<Self::BobToAliceWireTransfer> {
            let expected_count = self.message.inner.len();
            let security_level = self.security_level;
            let msg_bob_cts: Vec<BobToAliceTransferParameters> = self
                .message
                .inner
                .iter()
                .filter_map(|inner| inner.pqc.generate_bob_to_alice_transfer().ok())
                .collect();
            if msg_bob_cts.len() != expected_count {
                return None;
            }

            let scramble_bob_ct = self.scramble.pqc.generate_bob_to_alice_transfer().ok()?;

            // now, generate the serialized bytes
            let nonce_msg = &self.nonce_message;
            let nonce_scramble = &self.nonce_scramble;

            let encrypted_msg_entropy_banks: Vec<Vec<u8>> = self
                .message
                .inner
                .iter_mut()
                .filter_map(|inner| {
                    let entropy_bank = inner.entropy_bank.as_mut()?;
                    let serialized = entropy_bank.serialize_to_vec().ok()?;
                    let encrypted = inner.pqc.encrypt(serialized, nonce_msg).ok()?;
                    Some(encrypted)
                })
                .collect();
            if encrypted_msg_entropy_banks.len() != expected_count {
                return None;
            }

            let scramble_entropy_bank = self.scramble.entropy_bank.as_mut()?;
            let serialized = scramble_entropy_bank.serialize_to_vec().ok()?;
            let encrypted_scramble_entropy_bank =
                self.scramble.pqc.encrypt(serialized, nonce_scramble).ok()?;

            let transfer = BobToAliceTransfer {
                msg_bob_params_txs: msg_bob_cts,
                scramble_bob_params_tx: scramble_bob_ct,
                encrypted_msg_entropy_banks,
                encrypted_scramble_entropy_bank,
                security_level,
            };

            Some(transfer)
        }

        fn stage1_alice<T: AsRef<[u8]>>(
            &mut self,
            transfer: Self::BobToAliceWireTransfer,
            psks: &[T],
        ) -> Result<(), CryptError> {
            let nonce_msg = &self.nonce_message;
            for (container, bob_param_tx) in self
                .message
                .inner
                .iter_mut()
                .zip(transfer.msg_bob_params_txs.clone())
            {
                container
                    .pqc
                    .alice_on_receive_ciphertext(bob_param_tx, psks)
                    .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;
            }

            for (idx, container) in self.message.inner.iter_mut().enumerate() {
                // now, using the message pqc, decrypt the message entropy_bank
                let decrypted_msg_entropy_bank = match container.pqc.decrypt(
                    &transfer
                        .encrypted_msg_entropy_banks
                        .get(idx)
                        .ok_or_else(|| {
                            CryptError::RekeyUpdateError(
                                "Unable to get encrypted_msg_entropy_banks".to_string(),
                            )
                        })?[..],
                    nonce_msg,
                ) {
                    Ok(entropy_bank) => entropy_bank,
                    Err(err) => {
                        return Err(CryptError::RekeyUpdateError(err.to_string()));
                    }
                };
                let mut decrypted_entropy_bank =
                    EntropyBank::deserialize_from(&decrypted_msg_entropy_bank[..])?;
                decrypted_entropy_bank.cid = self.cid;
                container.entropy_bank = Some(decrypted_entropy_bank);
            }

            let nonce_scramble = &self.nonce_scramble;
            self.scramble
                .pqc
                .alice_on_receive_ciphertext(transfer.scramble_bob_params_tx, psks)
                .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;
            // do the same as above
            let decrypted_scramble_entropy_bank = self
                .scramble
                .pqc
                .decrypt(
                    &transfer.encrypted_scramble_entropy_bank[..],
                    nonce_scramble,
                )
                .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;

            let mut decrypted_entropy_bank =
                EntropyBank::deserialize_from(&decrypted_scramble_entropy_bank[..])?;
            decrypted_entropy_bank.cid = self.cid;
            self.scramble.entropy_bank = Some(decrypted_entropy_bank);

            // version check
            if self
                .scramble
                .entropy_bank
                .as_ref()
                .ok_or_else(|| {
                    CryptError::RekeyUpdateError(
                        "Unable to get encrypted_msg_entropy_banks".to_string(),
                    )
                })?
                .version
                != self.message.inner[0]
                    .entropy_bank
                    .as_ref()
                    .ok_or_else(|| {
                        CryptError::RekeyUpdateError(
                            "Unable to get encrypted_msg_entropy_banks".to_string(),
                        )
                    })?
                    .version
            {
                return Err(CryptError::RekeyUpdateError(
                    "Message entropy_bank version != scramble entropy_bank version".to_string(),
                ));
            }

            if self
                .scramble
                .entropy_bank
                .as_ref()
                .ok_or_else(|| {
                    CryptError::RekeyUpdateError(
                        "Unable to get encrypted_msg_entropy_banks".to_string(),
                    )
                })?
                .cid
                != self.message.inner[0]
                    .entropy_bank
                    .as_ref()
                    .ok_or_else(|| {
                        CryptError::RekeyUpdateError(
                            "Unable to get encrypted_msg_entropy_banks".to_string(),
                        )
                    })?
                    .cid
            {
                return Err(CryptError::RekeyUpdateError(
                    "Message entropy_bank cid != scramble entropy_bank cid".to_string(),
                ));
            }

            Ok(())
        }

        fn update_version(&mut self, version: u32) -> Option<()> {
            self.new_version = version;

            for container in self.message.inner.iter_mut() {
                container.entropy_bank.as_mut()?.version = version;
            }

            self.scramble.entropy_bank.as_mut()?.version = version;
            Some(())
        }

        fn finish_with_custom_cid(mut self, cid: u64) -> Option<StackedRatchet> {
            for container in self.message.inner.iter_mut() {
                container.entropy_bank.as_mut()?.cid = cid;
            }

            self.scramble.entropy_bank.as_mut()?.cid = cid;

            self.finish()
        }

        fn finish(self) -> Option<StackedRatchet> {
            StackedRatchet::try_from(self).ok()
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    /// Transferred during KEM
    pub struct AliceToBobTransfer {
        pub params: CryptoParameters,
        params_txs: Vec<AliceToBobTransferParameters>,
        scramble_alice_params: AliceToBobTransferParameters,
        scramble_nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
        msg_nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
        pub security_level: SecurityLevel,
        cid: u64,
        new_version: u32,
    }

    impl AssociatedSecurityLevel for AliceToBobTransfer {
        fn security_level(&self) -> SecurityLevel {
            self.security_level
        }
    }

    impl AssociatedCryptoParams for AliceToBobTransfer {
        fn crypto_params(&self) -> CryptoParameters {
            self.params
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    /// Transferred during KEM
    pub struct BobToAliceTransfer {
        msg_bob_params_txs: Vec<BobToAliceTransferParameters>,
        scramble_bob_params_tx: BobToAliceTransferParameters,
        encrypted_msg_entropy_banks: Vec<Vec<u8>>,
        encrypted_scramble_entropy_bank: Vec<u8>,
        // the security level
        pub security_level: SecurityLevel,
    }

    impl AssociatedSecurityLevel for BobToAliceTransfer {
        fn security_level(&self) -> SecurityLevel {
            self.security_level
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct MessageRatchetConstructor {
        pub(crate) inner: Vec<MessageRatchetConstructorInner>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct MessageRatchetConstructorInner {
        pub(crate) entropy_bank: Option<EntropyBank>,
        pub(crate) pqc: PostQuantumContainer,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct ScrambleRatchetConstructor {
        pub(crate) entropy_bank: Option<EntropyBank>,
        pub(crate) pqc: PostQuantumContainer,
    }
}

impl TryFrom<StackedRatchetConstructor> for StackedRatchet {
    type Error = ();

    fn try_from(value: StackedRatchetConstructor) -> Result<Self, Self::Error> {
        let StackedRatchetConstructor {
            message, scramble, ..
        } = value;
        let default_security_level = SecurityLevel::for_value(message.inner.len() - 1).ok_or(())?;
        // make sure the shared secret is loaded
        let _ = scramble.pqc.get_shared_secret().map_err(|_| ())?;
        let scramble_entropy_bank = scramble.entropy_bank.ok_or(())?;

        let mut inner = Vec::with_capacity(message.inner.len());
        for container in message.inner {
            // make sure shared secret is loaded
            let _ = container.pqc.get_shared_secret().map_err(|_| ())?;
            let message_entropy_bank = container.entropy_bank.ok_or(())?;

            if message_entropy_bank.version != scramble_entropy_bank.version
                || message_entropy_bank.cid != scramble_entropy_bank.cid
            {
                return Err(());
            }

            inner.push(MessageRatchetInner {
                entropy_bank: message_entropy_bank,
                pqc: container.pqc,
            });
        }

        let message = MessageRatchet { inner };

        let scramble = ScrambleRatchet {
            entropy_bank: scramble_entropy_bank,
            pqc: scramble.pqc,
        };

        Ok(StackedRatchet::from(StackedRatchetInner {
            message,
            scramble,
            default_security_level,
        }))
    }
}
