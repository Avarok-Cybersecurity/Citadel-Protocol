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
//! use citadel_crypt::stacked_ratchet::{StackedRatchet, constructor::StackedRatchetConstructor};
//! use citadel_pqcrypto::constructor_opts::ConstructorOpts;
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
//!         Some(SecurityLevel::Standard)
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

use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::entropy_bank::EntropyBank;
use crate::misc::CryptError;
use crate::stacked_ratchet::constructor::StackedRatchetConstructor;
use bytes::BytesMut;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use citadel_pqcrypto::constructor_opts::{ConstructorOpts, RecursiveChain};
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::crypto::SecurityLevel;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::borrow::Cow;
use std::sync::Arc;

/// A container meant to establish perfect forward secrecy AND scrambling w/ an independent key
/// This is meant for messages, not file transfer. File transfers should use a single key throughout
/// the entire file
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StackedRatchet {
    pub(crate) inner: Arc<StackedRatchetInner>,
}

/// For allowing registration inside the toolset
pub trait Ratchet: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + 'static {
    type Constructor: EndpointRatchetConstructor<Self> + Serialize + for<'a> Deserialize<'a>;

    /// Returns the client ID
    fn get_cid(&self) -> u64 {
        self.get_message_pqc_and_entropy_bank_at_layer(None)
            .expect("StackedRatchet::get_cid")
            .1
            .cid
    }

    /// Returns the version
    fn version(&self) -> u32 {
        self.get_message_pqc_and_entropy_bank_at_layer(None)
            .expect("StackedRatchet::version")
            .1
            .version
    }

    /// Determines if any of the ratchets have verified packets
    fn has_verified_packets(&self) -> bool {
        let max = self.message_ratchet_count();
        for n in 0..max {
            if let Ok((pqc, _entropy_bank)) =
                self.get_message_pqc_and_entropy_bank_at_layer(Some(n))
            {
                if pqc.has_verified_packets() {
                    return true;
                }
            }
        }

        self.get_scramble_pqc_and_entropy_bank()
            .0
            .has_verified_packets()
    }

    /// Resets the anti-replay attack counters
    fn reset_ara(&self) {
        let max = self.message_ratchet_count();
        for n in 0..max {
            if let Ok((pqc, _entropy_bank)) =
                self.get_message_pqc_and_entropy_bank_at_layer(Some(n))
            {
                pqc.reset_counters();
            }
        }

        self.get_scramble_pqc_and_entropy_bank().0.reset_counters()
    }

    /// Returns the default security level
    fn get_default_security_level(&self) -> SecurityLevel;

    /// Returns the message PQC and entropy_bank for the specified index
    fn get_message_pqc_and_entropy_bank_at_layer(
        &self,
        idx: Option<usize>,
    ) -> Result<(&PostQuantumContainer, &EntropyBank), CryptError>;

    /// Returns the scramble entropy_bank
    fn get_scramble_pqc_and_entropy_bank(&self) -> (&PostQuantumContainer, &EntropyBank);

    /// Returns the next constructor options
    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts>;

    /// Protects a message packet using the entire ratchet's security features
    fn protect_message_packet<T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header_len_bytes: usize,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;

        for n in 0..=idx {
            let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(Some(n))?;
            entropy_bank.protect_packet(pqc, header_len_bytes, packet)?;
        }

        Ok(())
    }

    /// Validates a message packet using the entire ratchet's security features
    fn validate_message_packet<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header: H,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;
        for n in (0..=idx).rev() {
            let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(Some(n))?;
            entropy_bank.validate_packet_in_place_split(pqc, &header, packet)?;
        }

        Ok(())
    }

    /// Returns the next Alice constructor
    fn next_alice_constructor(&self) -> Option<Self::Constructor> {
        Self::Constructor::new_alice(
            self.get_next_constructor_opts(),
            self.get_cid(),
            self.version().wrapping_add(1),
        )
    }

    /// Encrypts using a local key that is not shared with anyone. Relevant for RE-VFS
    fn local_encrypt<'a, T: Into<Cow<'a, [u8]>>>(
        &self,
        contents: T,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError> {
        let idx = self.verify_level(Some(security_level))?;
        let mut data = contents.into();
        for n in 0..=idx {
            let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(Some(n))?;
            data = Cow::Owned(entropy_bank.local_encrypt(pqc, &data)?);
        }

        Ok(data.into_owned())
    }

    /// Decrypts using a local key that is not shared with anyone. Relevant for RE-VFS
    fn local_decrypt<'a, T: Into<Cow<'a, [u8]>>>(
        &self,
        contents: T,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError> {
        let mut data = contents.into();
        if data.is_empty() {
            return Ok(vec![]);
        }

        let idx = self.verify_level(Some(security_level))?;
        for n in (0..=idx).rev() {
            let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(Some(n))?;
            data = Cow::Owned(entropy_bank.local_decrypt(pqc, &data)?);
        }

        Ok(data.into_owned())
    }

    fn message_ratchet_count(&self) -> usize;

    /// Verifies the target security level, returning the corresponding idx
    fn verify_level(
        &self,
        security_level: Option<SecurityLevel>,
    ) -> Result<usize, CryptError<String>> {
        let security_level = security_level.unwrap_or(SecurityLevel::Standard);
        let message_ratchet_count = self.message_ratchet_count();
        if security_level.value() as usize >= message_ratchet_count {
            log::warn!(target: "citadel", "OOB: Security value: {}, max: {} (default: {:?})|| Version: {}", security_level.value() as usize, message_ratchet_count- 1, self.get_default_security_level(), self.version());
            Err(CryptError::OutOfBoundsError)
        } else {
            Ok(security_level.value() as usize)
        }
    }

    /// Validates in-place when the header + payload have already been split
    fn validate_message_packet_in_place_split<H: AsRef<[u8]>>(
        &self,
        security_level: Option<SecurityLevel>,
        header: H,
        packet: &mut BytesMut,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;
        for n in (0..=idx).rev() {
            let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(Some(n))?;
            entropy_bank.validate_packet_in_place_split(pqc, &header, packet)?;
        }

        Ok(())
    }

    /// decrypts using a custom nonce configuration
    fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(None)?;
        entropy_bank.decrypt(pqc, contents)
    }

    /// Encrypts the data into a Vec<u8>
    fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, entropy_bank) = self.get_message_pqc_and_entropy_bank_at_layer(None)?;
        entropy_bank.encrypt(pqc, contents)
    }
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
    use crate::entropy_bank::EntropyBank;
    use crate::prelude::CryptError;
    use crate::stacked_ratchet::StackedRatchet;
    use arrayvec::ArrayVec;
    use bytes::BufMut;
    use bytes::BytesMut;
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
        pub(super) message: MessageRatchetConstructor,
        pub(super) scramble: ScrambleRatchetConstructor,
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
            StackedRatchetConstructor::new_alice_constructor(opts, cid, new_version)
        }

        fn new_bob<T: AsRef<[u8]>>(
            cid: u64,
            opts: Vec<ConstructorOpts>,
            transfer: Self::AliceToBobWireTransfer,
            psks: &[T],
        ) -> Option<Self> {
            StackedRatchetConstructor::new_bob_constructor(
                cid,
                transfer.new_version,
                opts,
                transfer,
                psks,
            )
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
                let decrypted_entropy_bank =
                    EntropyBank::deserialize_from(&decrypted_msg_entropy_bank[..])?;
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

            let decrypted_entropy_bank =
                EntropyBank::deserialize_from(&decrypted_scramble_entropy_bank[..])?;
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

    impl BobToAliceTransfer {
        pub fn serialize_into(&self, buf: &mut BytesMut) -> Option<()> {
            let len = bincode::serialized_size(self).ok()?;
            buf.reserve(len as usize);
            bincode::serialize_into(buf.writer(), self).ok()
        }

        pub fn deserialize_from<T: AsRef<[u8]>>(source: T) -> Option<BobToAliceTransfer> {
            bincode::deserialize(source.as_ref()).ok()
        }
    }

    impl AliceToBobTransfer {
        pub fn serialize_to_vec(&self) -> Option<Vec<u8>> {
            bincode::serialize(self).ok()
        }

        pub fn deserialize_from(source: &[u8]) -> Option<AliceToBobTransfer> {
            bincode::deserialize(source).ok()
        }

        /// Gets the declared new version
        pub fn get_declared_new_version(&self) -> u32 {
            self.new_version
        }

        /// Gets the declared cid
        pub fn get_declared_cid(&self) -> u64 {
            self.cid
        }
    }

    impl StackedRatchetConstructor {
        /// Called during the initialization stage
        pub fn new_alice_constructor(
            opts: Vec<ConstructorOpts>,
            cid: u64,
            new_version: u32,
        ) -> Option<Self> {
            let security_level = opts.implied_security_level();
            log::trace!(target: "citadel", "[ALICE] creating container with {:?} security level", security_level);
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

        /// Called when bob receives alice's pk's
        pub fn new_bob_constructor<T: AsRef<[u8]>>(
            cid: u64,
            new_version: u32,
            opts: Vec<ConstructorOpts>,
            transfer: AliceToBobTransfer,
            psks: &[T],
        ) -> Option<Self> {
            log::trace!(target: "citadel", "[BOB] creating container with {:?} security level", transfer.security_level);
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

        /// Generates the public key for the (message_pk, scramble_pk, nonce)
        pub fn stage0_alice(&self) -> Option<AliceToBobTransfer> {
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

        /// Returns the (message_bob_ct, scramble_bob_ct, msg_entropy_bank_serialized, scramble_entropy_bank_serialized)
        pub fn stage0_bob(&mut self) -> Option<BobToAliceTransfer> {
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

        /// Returns Ok(()) if process succeeded
        pub fn stage1_alice<T: AsRef<[u8]>>(
            &mut self,
            transfer: BobToAliceTransfer,
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
                // Overwrite the CID since the entropy bank bob encrypted had his CID
                decrypted_entropy_bank.cid = self.cid;
                container.entropy_bank = Some(decrypted_entropy_bank);
            }

            let nonce_scramble = &self.nonce_scramble;
            self.scramble
                .pqc
                .alice_on_receive_ciphertext(transfer.scramble_bob_params_tx, psks)
                .map_err(|err| {
                    println!(
                        "[DEBUG] Checkpoint 3 - Alice on receive scramble ciphertext error: {:?}",
                        err
                    );
                    CryptError::RekeyUpdateError(err.to_string())
                })?;
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
            // Overwrite the CID since the entropy bank bob encrypted had his CID
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

        /// Upgrades the construction into the StackedRatchet
        pub fn finish(self) -> Option<StackedRatchet> {
            StackedRatchet::try_from(self).ok()
        }

        /// Updates the internal version
        pub fn update_version(&mut self, version: u32) -> Option<()> {
            self.new_version = version;

            for container in self.message.inner.iter_mut() {
                container.entropy_bank.as_mut()?.version = version;
            }

            self.scramble.entropy_bank.as_mut()?.version = version;
            Some(())
        }

        /// Sometimes, replacing the CID is useful such as during peer KEM exchange wherein
        /// the CIDs between both parties are different. If a version is supplied, the version
        /// will be updated
        pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<StackedRatchet> {
            for container in self.message.inner.iter_mut() {
                container.entropy_bank.as_mut()?.cid = cid;
            }

            self.scramble.entropy_bank.as_mut()?.cid = cid;

            self.finish()
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(super) struct MessageRatchetConstructor {
        pub(super) inner: Vec<MessageRatchetConstructorInner>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(super) struct MessageRatchetConstructorInner {
        pub(super) entropy_bank: Option<EntropyBank>,
        pub(super) pqc: PostQuantumContainer,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(super) struct ScrambleRatchetConstructor {
        pub(super) entropy_bank: Option<EntropyBank>,
        pub(super) pqc: PostQuantumContainer,
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
