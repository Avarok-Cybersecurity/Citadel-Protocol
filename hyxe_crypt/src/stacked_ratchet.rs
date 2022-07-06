use crate::drill::{get_approx_serialized_drill_len, Drill, SecurityLevel};
use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::fcm::fcm_ratchet::ThinRatchet;
use crate::misc::CryptError;
use crate::net::crypt_splitter::calculate_nonce_version;
use crate::stacked_ratchet::constructor::StackedRatchetConstructor;
use bytes::BytesMut;
use ez_pqcrypto::bytes_in_place::EzBuffer;
use ez_pqcrypto::constructor_opts::{ConstructorOpts, RecursiveChain};
use ez_pqcrypto::PostQuantumContainer;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::convert::TryFrom;
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

    fn get_cid(&self) -> u64;
    fn version(&self) -> u32;
    fn has_verified_packets(&self) -> bool;
    fn reset_ara(&self);
    fn get_default_security_level(&self) -> SecurityLevel;
    fn message_pqc_drill(&self, idx: Option<usize>) -> (&PostQuantumContainer, &Drill);
    fn get_scramble_drill(&self) -> &Drill;

    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts>;

    fn protect_message_packet<T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header_len_bytes: usize,
        packet: &mut T,
    ) -> Result<(), CryptError<String>>;
    fn validate_message_packet<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header: H,
        packet: &mut T,
    ) -> Result<(), CryptError<String>>;

    fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>>;
    fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>>;

    fn next_alice_constructor(&self) -> Option<Self::Constructor> {
        Self::Constructor::new_alice(
            self.get_next_constructor_opts(),
            self.get_cid(),
            self.version().wrapping_add(1),
            Some(self.get_default_security_level()),
        )
    }
}

/// For returning a variable hyper ratchet from a function
pub enum RatchetType<R: Ratchet = StackedRatchet, Fcm: Ratchet = ThinRatchet> {
    Default(R),
    Fcm(Fcm),
}

impl<R: Ratchet, Fcm: Ratchet> RatchetType<R, Fcm> {
    ///
    pub fn assume_default(self) -> Option<R> {
        if let RatchetType::Default(r) = self {
            Some(r)
        } else {
            None
        }
    }

    ///
    pub fn assume_default_ref(&self) -> Option<&R> {
        if let RatchetType::Default(r) = self {
            Some(r)
        } else {
            None
        }
    }

    ///
    pub fn assume_fcm(self) -> Option<Fcm> {
        if let RatchetType::Fcm(r) = self {
            Some(r)
        } else {
            None
        }
    }

    ///
    pub fn assume_fcm_ref(&self) -> Option<&Fcm> {
        if let RatchetType::Fcm(r) = self {
            Some(r)
        } else {
            None
        }
    }

    /// returns the version
    pub fn version(&self) -> u32 {
        match self {
            RatchetType::Default(r) => r.version(),
            RatchetType::Fcm(r) => r.version(),
        }
    }

    /// returns the version
    pub fn get_cid(&self) -> u64 {
        match self {
            RatchetType::Default(r) => r.get_cid(),
            RatchetType::Fcm(r) => r.get_cid(),
        }
    }
}

impl Ratchet for StackedRatchet {
    type Constructor = StackedRatchetConstructor;

    fn get_cid(&self) -> u64 {
        self.get_cid()
    }

    fn version(&self) -> u32 {
        self.version()
    }

    fn has_verified_packets(&self) -> bool {
        self.has_verified_packets()
    }

    fn reset_ara(&self) {
        for ratchet in self.inner.message.inner.iter() {
            ratchet.pqc.reset_counters();
        }

        self.inner.scramble.pqc.reset_counters();
    }

    fn get_default_security_level(&self) -> SecurityLevel {
        self.get_default_security_level()
    }

    fn message_pqc_drill(&self, idx: Option<usize>) -> (&PostQuantumContainer, &Drill) {
        self.message_pqc_drill(idx)
    }

    fn get_scramble_drill(&self) -> &Drill {
        self.get_scramble_drill()
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
                    RecursiveChain::new(&meta_chain[..], &prev_chain.alice, &prev_chain.bob, false)
                        .unwrap();
                ConstructorOpts::new_from_previous(Some(r.pqc.params), next_chain)
            })
            .collect()
    }

    fn protect_message_packet<T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header_len_bytes: usize,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.protect_message_packet(security_level, header_len_bytes, packet)
    }

    fn validate_message_packet<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        ref header: H,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        self.validate_message_packet(security_level, header, packet)
    }

    fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt(contents)
    }

    fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt(contents)
    }
}

/// Returns the approximate size of each hyper ratchet, assuming LOW security level (default)
pub const fn get_approx_bytes_per_hyper_ratchet() -> usize {
    (2 * ez_pqcrypto::get_approx_bytes_per_container()) + (2 * get_approx_serialized_drill_len())
}

impl StackedRatchet {
    /// Determines if either the PQC's anti-replay attack containers have been engaged
    pub fn has_verified_packets(&self) -> bool {
        let max = self.inner.message.inner.len();
        for n in 0..max {
            if self.get_message_pqc(Some(n)).has_verified_packets() {
                return true;
            }
        }

        self.get_scramble_pqc().has_verified_packets()
    }

    /// returns the scramble PQC
    pub fn get_scramble_pqc(&self) -> &PostQuantumContainer {
        &self.inner.scramble.pqc
    }

    /// returns the message pqc and drill. Panics if idx is OOB
    #[inline]
    pub fn message_pqc_drill(&self, idx: Option<usize>) -> (&PostQuantumContainer, &Drill) {
        let idx = idx.unwrap_or(0);
        (
            &self.inner.message.inner[idx].pqc,
            &self.inner.message.inner[idx].drill,
        )
    }

    /// returns the message pqc and drill
    #[inline]
    pub fn scramble_pqc_drill(&self) -> (&PostQuantumContainer, &Drill) {
        (&self.inner.scramble.pqc, &self.inner.scramble.drill)
    }

    /// Verifies the target security level, returning the corresponding idx
    pub fn verify_level(
        &self,
        security_level: Option<SecurityLevel>,
    ) -> Result<usize, CryptError<String>> {
        let security_level = security_level.unwrap_or(SecurityLevel::LOW);
        if security_level.value() as usize >= self.inner.message.inner.len() {
            log::warn!(target: "lusna", "OOB: Security value: {}, max: {} (default: {:?})|| Version: {}", security_level.value() as usize, self.inner.message.inner.len() - 1, self.get_default_security_level(), self.version());
            Err(CryptError::OutOfBoundsError)
        } else {
            Ok(security_level.value() as usize)
        }
    }

    /// Protects the packet, treating the header as AAD, and the payload as the data that gets encrypted
    pub fn protect_message_packet_with_scrambler(
        &self,
        header_len_bytes: usize,
        packet: &mut BytesMut,
    ) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.protect_packet(pqc, header_len_bytes, packet)
    }

    /// Protects the packet, treating the header as AAD, and the payload as the data that gets encrypted
    pub fn protect_message_packet<T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        header_len_bytes: usize,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;

        for n in 0..=idx {
            let (pqc, drill) = self.message_pqc_drill(Some(n));
            drill.protect_packet(pqc, header_len_bytes, packet)?;
        }

        Ok(())
    }

    /// Validates a packet in place
    pub fn validate_message_packet<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        security_level: Option<SecurityLevel>,
        ref header: H,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;
        for n in (0..=idx).rev() {
            let (pqc, drill) = self.message_pqc_drill(Some(n));
            drill.validate_packet_in_place_split(pqc, header, packet)?;
        }

        Ok(())
    }

    /// Validates a packet in place
    pub fn validate_message_packet_with_scrambler<H: AsRef<[u8]>>(
        &self,
        header: H,
        packet: &mut BytesMut,
    ) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    /// Validates in-place when the header + payload have already been split
    pub fn validate_message_packet_in_place_split<H: AsRef<[u8]>>(
        &self,
        security_level: Option<SecurityLevel>,
        ref header: H,
        packet: &mut BytesMut,
    ) -> Result<(), CryptError<String>> {
        let idx = self.verify_level(security_level)?;
        for n in (0..=idx).rev() {
            let (pqc, drill) = self.message_pqc_drill(Some(n));
            drill.validate_packet_in_place_split(pqc, header, packet)?;
        }

        Ok(())
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt_custom(0, 0, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.aes_gcm_encrypt(
            calculate_nonce_version(wave_id as usize, group),
            pqc,
            contents,
        )
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_scrambler<T: AsRef<[u8]>>(
        &self,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt_custom_scrambler(0, 0, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom_scrambler<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_encrypt(
            calculate_nonce_version(wave_id as usize, group),
            pqc,
            contents,
        )
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt_custom(0, 0, contents)
    }

    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group_id: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.aes_gcm_decrypt(
            calculate_nonce_version(wave_id as usize, group_id),
            pqc,
            contents,
        )
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_scrambler<T: AsRef<[u8]>>(
        &self,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt_custom_scrambler(0, 0, contents)
    }

    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom_scrambler<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group_id: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_decrypt(
            calculate_nonce_version(wave_id as usize, group_id),
            pqc,
            contents,
        )
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_in_place<T: AsMut<[u8]>>(
        &self,
        contents: &mut T,
    ) -> Result<usize, CryptError<String>> {
        self.decrypt_in_place_custom(0, 0, contents)
    }

    /// decrypts in place using a custom nonce configuration
    pub fn decrypt_in_place_custom<T: AsMut<[u8]>>(
        &self,
        wave_id: u32,
        group_id: u64,
        contents: &mut T,
    ) -> Result<usize, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.aes_gcm_decrypt_in_place(
            calculate_nonce_version(wave_id as usize, group_id),
            pqc,
            contents,
        )
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_in_place_scrambler<T: AsMut<[u8]>>(
        &self,
        contents: &mut T,
    ) -> Result<usize, CryptError<String>> {
        self.decrypt_in_place_custom_scrambler(0, 0, contents)
    }

    /// decrypts in place using a custom nonce configuration
    pub fn decrypt_in_place_custom_scrambler<T: AsMut<[u8]>>(
        &self,
        wave_id: u32,
        group_id: u64,
        contents: &mut T,
    ) -> Result<usize, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_decrypt_in_place(
            calculate_nonce_version(wave_id as usize, group_id),
            pqc,
            contents,
        )
    }

    /// Returns the message drill
    pub fn get_message_drill(&self, idx: Option<usize>) -> &Drill {
        &self.inner.message.inner[idx.unwrap_or(0)].drill
    }

    /// Returns the message pqc
    pub fn get_message_pqc(&self, idx: Option<usize>) -> &PostQuantumContainer {
        &self.inner.message.inner[idx.unwrap_or(0)].pqc
    }

    /// Returns the scramble drill
    pub fn get_scramble_drill(&self) -> &Drill {
        &self.inner.scramble.drill
    }

    /// Returns the [StackedRatchet]'s version
    pub fn version(&self) -> u32 {
        self.inner.message.inner[0].drill.version
    }

    /// Returns the CID
    pub fn get_cid(&self) -> u64 {
        self.inner.message.inner[0].drill.cid
    }

    /// Gets the default security level (will use all available keys)
    pub fn get_default_security_level(&self) -> SecurityLevel {
        self.inner.default_security_level
    }
}

#[derive(Serialize, Deserialize, Debug)]
///
pub struct StackedRatchetInner {
    pub(crate) message: MessageRatchet,
    pub(crate) scramble: ScrambleRatchet,
    pub(crate) default_security_level: SecurityLevel,
}

///
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MessageRatchet {
    inner: Vec<MessageRatchetInner>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MessageRatchetInner {
    pub(crate) drill: Drill,
    pub(crate) pqc: PostQuantumContainer,
}

///
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ScrambleRatchet {
    pub(crate) drill: Drill,
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
    use crate::drill::{Drill, SecurityLevel};
    use crate::endpoint_crypto_container::EndpointRatchetConstructor;
    use crate::fcm::fcm_ratchet::{FcmAliceToBobTransfer, FcmBobToAliceTransfer, ThinRatchet};
    use crate::stacked_ratchet::{Ratchet, StackedRatchet};
    use arrayvec::ArrayVec;
    use bytes::BufMut;
    use bytes::BytesMut;
    use ez_pqcrypto::algorithm_dictionary::CryptoParameters;
    use ez_pqcrypto::constructor_opts::ConstructorOpts;
    use ez_pqcrypto::PostQuantumContainer;
    use ez_pqcrypto::LARGEST_NONCE_LEN;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

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

    /// For differentiating between two types when inputting into function parameters
    #[derive(Serialize, Deserialize)]
    pub enum ConstructorType<R: Ratchet = StackedRatchet, Fcm: Ratchet = ThinRatchet> {
        Default(R::Constructor),
        Fcm(Fcm::Constructor),
    }

    impl<R: Ratchet, Fcm: Ratchet> ConstructorType<R, Fcm> {
        pub fn stage1_alice(&mut self, transfer: &BobToAliceTransferType) -> Option<()> {
            match self {
                ConstructorType::Default(con) => con.stage1_alice(transfer),

                ConstructorType::Fcm(con) => con.stage1_alice(transfer),
            }
        }

        pub fn assume_default(self) -> Option<R::Constructor> {
            if let ConstructorType::Default(c) = self {
                Some(c)
            } else {
                None
            }
        }

        pub fn assume_fcm(self) -> Option<Fcm::Constructor> {
            if let ConstructorType::Fcm(c) = self {
                Some(c)
            } else {
                None
            }
        }

        pub fn assume_default_ref(&self) -> Option<&R::Constructor> {
            if let ConstructorType::Default(c) = self {
                Some(c)
            } else {
                None
            }
        }

        pub fn assume_fcm_ref(&self) -> Option<&Fcm::Constructor> {
            if let ConstructorType::Fcm(c) = self {
                Some(c)
            } else {
                None
            }
        }

        pub fn is_fcm(&self) -> bool {
            match self {
                Self::Fcm(..) => true,
                _ => false,
            }
        }
    }

    /// For denoting the different transfer types that have local lifetimes
    #[derive(Serialize, Deserialize)]
    pub enum AliceToBobTransferType<'a> {
        #[serde(borrow)]
        Default(AliceToBobTransfer<'a>),
        #[serde(borrow)]
        Fcm(FcmAliceToBobTransfer<'a>),
    }

    impl AliceToBobTransferType<'_> {
        pub fn get_security_opts(&self) -> (CryptoParameters, SecurityLevel) {
            match self {
                Self::Default(tx) => (tx.params, tx.security_level),
                Self::Fcm(tx) => (tx.params, SecurityLevel::LOW),
            }
        }

        pub fn get_declared_new_version(&self) -> u32 {
            match self {
                AliceToBobTransferType::Default(tx) => tx.new_version,
                AliceToBobTransferType::Fcm(tx) => tx.version,
            }
        }

        pub fn assume_default(&self) -> Option<&AliceToBobTransfer<'_>> {
            match self {
                Self::Default(tx) => Some(tx),
                _ => None,
            }
        }

        pub fn assume_fcm(&self) -> Option<&FcmAliceToBobTransfer<'_>> {
            match self {
                Self::Fcm(tx) => Some(tx),
                _ => None,
            }
        }

        pub fn is_fcm(&self) -> bool {
            match self {
                Self::Fcm(_) => true,
                _ => false,
            }
        }
    }

    impl EndpointRatchetConstructor<StackedRatchet> for StackedRatchetConstructor {
        fn new_alice(
            opts: Vec<ConstructorOpts>,
            cid: u64,
            new_version: u32,
            security_level: Option<SecurityLevel>,
        ) -> Option<Self> {
            StackedRatchetConstructor::new_alice(opts, cid, new_version, security_level)
        }

        fn new_bob(
            cid: u64,
            new_drill_vers: u32,
            opts: Vec<ConstructorOpts>,
            transfer: AliceToBobTransferType<'_>,
        ) -> Option<Self> {
            match transfer {
                AliceToBobTransferType::Default(transfer) => {
                    StackedRatchetConstructor::new_bob(cid, new_drill_vers, opts, transfer)
                }

                _ => {
                    log::error!(target: "lusna", "Incompatible Ratchet Type passed! [X-22]");
                    None
                }
            }
        }

        fn stage0_alice(&self) -> AliceToBobTransferType<'_> {
            AliceToBobTransferType::Default(self.stage0_alice())
        }

        fn stage0_bob(&self) -> Option<BobToAliceTransferType> {
            Some(BobToAliceTransferType::Default(self.stage0_bob()?))
        }

        fn stage1_alice(&mut self, transfer: &BobToAliceTransferType) -> Option<()> {
            self.stage1_alice(transfer)
        }

        fn update_version(&mut self, version: u32) -> Option<()> {
            self.update_version(version)
        }

        fn finish_with_custom_cid(self, cid: u64) -> Option<StackedRatchet> {
            self.finish_with_custom_cid(cid)
        }

        fn finish(self) -> Option<StackedRatchet> {
            self.finish()
        }
    }

    #[derive(Serialize, Deserialize)]
    /// Transferred during KEM
    pub struct AliceToBobTransfer<'a> {
        ///
        pub params: CryptoParameters,
        #[serde(borrow)]
        pks: Vec<&'a [u8]>,
        #[serde(borrow)]
        scramble_alice_pk: &'a [u8],
        scramble_nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
        msg_nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
        ///
        pub security_level: SecurityLevel,
        cid: u64,
        new_version: u32,
    }

    #[derive(Serialize, Deserialize)]
    /// Transferred during KEM
    pub struct BobToAliceTransfer {
        msg_bob_cts: Vec<Vec<u8>>,
        scramble_bob_ct: Vec<u8>,
        encrypted_msg_drills: Vec<Vec<u8>>,
        encrypted_scramble_drill: Vec<u8>,
        // the security level
        pub security_level: SecurityLevel,
    }

    /// for denoting different types
    #[derive(Serialize, Deserialize)]
    pub enum BobToAliceTransferType {
        Default(BobToAliceTransfer),
        Fcm(FcmBobToAliceTransfer),
    }

    impl BobToAliceTransferType {
        pub fn assume_fcm(self) -> Option<FcmBobToAliceTransfer> {
            match self {
                Self::Fcm(this) => Some(this),
                _ => None,
            }
        }

        pub fn assume_default(self) -> Option<BobToAliceTransfer> {
            match self {
                Self::Default(this) => Some(this),
                _ => None,
            }
        }
    }

    impl BobToAliceTransfer {
        ///
        pub fn serialize_into(&self, buf: &mut BytesMut) -> Option<()> {
            let len = bincode2::serialized_size(self).ok()?;
            buf.reserve(len as usize);
            bincode2::serialize_into(buf.writer(), self).ok()
        }

        ///
        #[allow(dead_code)]
        pub fn serialize_to_vec(&self) -> Option<Vec<u8>> {
            bincode2::serialize(self).ok()
        }

        ///
        #[allow(dead_code)]
        pub fn deserialize_from<T: AsRef<[u8]>>(source: T) -> Option<BobToAliceTransfer> {
            bincode2::deserialize(source.as_ref()).ok()
        }
    }

    impl AliceToBobTransfer<'_> {
        ///
        pub fn serialize_into(&self, buf: &mut BytesMut) -> Option<()> {
            let len = bincode2::serialized_size(self).ok()?;
            buf.reserve(len as usize);
            bincode2::serialize_into(buf.writer(), self).ok()
        }

        ///
        pub fn serialize_to_vec(&self) -> Option<Vec<u8>> {
            bincode2::serialize(self).ok()
        }

        ///
        pub fn deserialize_from(source: &[u8]) -> Option<AliceToBobTransfer> {
            bincode2::deserialize(source).ok()
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
        pub fn new_alice(
            opts: Vec<ConstructorOpts>,
            cid: u64,
            new_version: u32,
            security_level: Option<SecurityLevel>,
        ) -> Option<Self> {
            let security_level = security_level.unwrap_or(SecurityLevel::LOW);
            log::trace!(target: "lusna", "[ALICE] creating container with {:?} security level", security_level);
            //let count = security_level.value() as usize + 1;
            let len = opts.len();
            let params = opts[0].cryptography.unwrap_or_default();
            let keys = opts
                .into_iter()
                .filter_map(|opts| {
                    Some(MessageRatchetConstructorInner {
                        drill: None,
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
                    drill: None,
                    pqc: PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(params)))
                        .ok()?,
                },
                nonce_message: Drill::generate_public_nonce(params.encryption_algorithm),
                nonce_scramble: Drill::generate_public_nonce(params.encryption_algorithm),
                cid,
                new_version,
                security_level,
            })
        }

        /// Called when bob receives alice's pk's
        pub fn new_bob(
            cid: u64,
            new_drill_vers: u32,
            opts: Vec<ConstructorOpts>,
            transfer: AliceToBobTransfer,
        ) -> Option<Self> {
            log::trace!(target: "lusna", "[BOB] creating container with {:?} security level", transfer.security_level);
            let count = transfer.security_level.value() as usize + 1;
            let params = transfer.params;
            let keys: Vec<MessageRatchetConstructorInner> = transfer
                .pks
                .into_iter()
                .zip(opts.into_iter())
                .filter_map(|(pk, opts)| {
                    Some(MessageRatchetConstructorInner {
                        drill: Some(
                            Drill::new(cid, new_drill_vers, params.encryption_algorithm).ok()?,
                        ),
                        pqc: PostQuantumContainer::new_bob(opts, pk).ok()?,
                    })
                })
                .collect();

            if keys.len() != count {
                log::error!(target: "lusna", "[BOB] not all keys parsed correctly. {} != {}", keys.len(), count);
                return None;
            }

            Some(Self {
                params,
                message: MessageRatchetConstructor { inner: keys },
                scramble: ScrambleRatchetConstructor {
                    drill: Some(Drill::new(cid, new_drill_vers, params.encryption_algorithm).ok()?),
                    pqc: PostQuantumContainer::new_bob(
                        ConstructorOpts::new_init(Some(params)),
                        transfer.scramble_alice_pk,
                    )
                    .ok()?,
                },
                nonce_message: transfer.msg_nonce,
                nonce_scramble: transfer.scramble_nonce,
                cid,
                new_version: new_drill_vers,
                security_level: transfer.security_level,
            })
        }

        /// Generates the public key for the (message_pk, scramble_pk, nonce)
        pub fn stage0_alice(&self) -> AliceToBobTransfer<'_> {
            let pks = self
                .message
                .inner
                .iter()
                .map(|inner| inner.pqc.get_public_key())
                .collect();

            let scramble_alice_pk = self.scramble.pqc.get_public_key();
            let msg_nonce = self.nonce_message.clone();
            let scramble_nonce = self.nonce_scramble.clone();
            let cid = self.cid;
            let new_version = self.new_version;
            let params = self.params;
            let security_level = self.security_level;

            AliceToBobTransfer {
                params,
                pks,
                scramble_alice_pk,
                msg_nonce,
                scramble_nonce,
                security_level,
                cid,
                new_version,
            }
        }

        /// Returns the (message_bob_ct, scramble_bob_ct, msg_drill_serialized, scramble_drill_serialized)
        pub fn stage0_bob(&self) -> Option<BobToAliceTransfer> {
            let expected_count = self.message.inner.len();
            let security_level = self.security_level;
            let msg_bob_cts: Vec<Vec<u8>> = self
                .message
                .inner
                .iter()
                .filter_map(|inner| Some(inner.pqc.get_ciphertext().ok()?.to_vec()))
                .collect();
            if msg_bob_cts.len() != expected_count {
                return None;
            }

            let scramble_bob_ct = self.scramble.pqc.get_ciphertext().ok()?.to_vec();
            // now, generate the serialized bytes
            let nonce_msg = &self.nonce_message;
            let nonce_scramble = &self.nonce_scramble;

            let encrypted_msg_drills: Vec<Vec<u8>> = self
                .message
                .inner
                .iter()
                .filter_map(|inner| {
                    inner
                        .pqc
                        .encrypt(inner.drill.as_ref()?.serialize_to_vec().ok()?, nonce_msg)
                        .ok()
                })
                .collect();
            if encrypted_msg_drills.len() != expected_count {
                return None;
            }

            let encrypted_scramble_drill = self
                .scramble
                .pqc
                .encrypt(
                    self.scramble.drill.as_ref()?.serialize_to_vec().ok()?,
                    nonce_scramble,
                )
                .ok()?;

            let transfer = BobToAliceTransfer {
                msg_bob_cts,
                scramble_bob_ct,
                encrypted_msg_drills,
                encrypted_scramble_drill,
                security_level,
            };

            Some(transfer)
        }

        /// Returns Some(()) if process succeeded
        pub fn stage1_alice(&mut self, transfer: &BobToAliceTransferType) -> Option<()> {
            if let BobToAliceTransferType::Default(transfer) = transfer {
                let nonce_msg = &self.nonce_message;

                for (idx, container) in self.message.inner.iter_mut().enumerate() {
                    container
                        .pqc
                        .alice_on_receive_ciphertext(&transfer.msg_bob_cts.get(idx)?[..])
                        .ok()?;
                }

                for (idx, container) in self.message.inner.iter_mut().enumerate() {
                    // now, using the message pqc, decrypt the message drill
                    let decrypted_msg_drill = container
                        .pqc
                        .decrypt(&transfer.encrypted_msg_drills.get(idx)?[..], nonce_msg)
                        .ok()?;
                    container.drill = Some(Drill::deserialize_from(&decrypted_msg_drill[..]).ok()?);
                }

                let nonce_scramble = &self.nonce_scramble;
                self.scramble
                    .pqc
                    .alice_on_receive_ciphertext(&transfer.scramble_bob_ct[..])
                    .ok()?;
                // do the same as above
                let decrypted_scramble_drill = self
                    .scramble
                    .pqc
                    .decrypt(&transfer.encrypted_scramble_drill[..], nonce_scramble)
                    .ok()?;
                self.scramble.drill =
                    Some(Drill::deserialize_from(&decrypted_scramble_drill[..]).ok()?);

                // version check
                if self.scramble.drill.as_ref()?.version
                    != self.message.inner[0].drill.as_ref()?.version
                {
                    return None;
                }

                if self.scramble.drill.as_ref()?.cid != self.message.inner[0].drill.as_ref()?.cid {
                    return None;
                }

                Some(())
            } else {
                log::error!(target: "lusna", "Incompatible Ratchet Type passed! [X-40]");
                None
            }
        }

        /// Upgrades the construction into the StackedRatchet
        pub fn finish(self) -> Option<StackedRatchet> {
            StackedRatchet::try_from(self).ok()
        }

        /// Updates the internal version
        pub fn update_version(&mut self, proposed_version: u32) -> Option<()> {
            self.new_version = proposed_version;

            for container in self.message.inner.iter_mut() {
                container.drill.as_mut()?.version = proposed_version;
            }

            self.scramble.drill.as_mut()?.version = proposed_version;
            Some(())
        }

        /// Sometimes, replacing the CID is useful such as during peer KEM exhcange wherein
        /// the CIDs between both parties are different. If a version is supplied, the version
        /// will be updated
        pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<StackedRatchet> {
            for container in self.message.inner.iter_mut() {
                container.drill.as_mut()?.cid = cid;
            }

            self.scramble.drill.as_mut()?.cid = cid;

            self.finish()
        }
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct MessageRatchetConstructor {
        pub(super) inner: Vec<MessageRatchetConstructorInner>,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct MessageRatchetConstructorInner {
        pub(super) drill: Option<Drill>,
        pub(super) pqc: PostQuantumContainer,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct ScrambleRatchetConstructor {
        pub(super) drill: Option<Drill>,
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
        let scramble_drill = scramble.drill.ok_or(())?;

        let mut inner = Vec::with_capacity(message.inner.len());
        for container in message.inner {
            // make sure shared secret is loaded
            let _ = container.pqc.get_shared_secret().map_err(|_| ())?;
            let message_drill = container.drill.ok_or(())?;

            if message_drill.version != scramble_drill.version
                || message_drill.cid != scramble_drill.cid
            {
                return Err(());
            }

            inner.push(MessageRatchetInner {
                drill: message_drill,
                pqc: container.pqc,
            });
        }

        let message = MessageRatchet { inner };

        let scramble = ScrambleRatchet {
            drill: scramble_drill,
            pqc: scramble.pqc,
        };

        Ok(StackedRatchet::from(StackedRatchetInner {
            message,
            scramble,
            default_security_level,
        }))
    }
}
