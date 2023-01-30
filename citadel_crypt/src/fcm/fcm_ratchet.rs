use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::entropy_bank::{EntropyBank, SecurityLevel};
use crate::misc::CryptError;
use crate::scramble::crypt_splitter::calculate_nonce_version;
use crate::stacked_ratchet::constructor::{AliceToBobTransferType, BobToAliceTransferType};
use crate::stacked_ratchet::Ratchet;
use arrayvec::ArrayVec;
use citadel_pqcrypto::algorithm_dictionary::CryptoParameters;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use citadel_pqcrypto::PostQuantumContainer;
use citadel_pqcrypto::LARGEST_NONCE_LEN;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
/// A compact ratchet meant for thin protocol messages
pub struct ThinRatchet {
    inner: Arc<ThinRatchetInner>,
}

impl ThinRatchet {
    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group_id: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.decrypt(
            calculate_nonce_version(wave_id as usize, group_id),
            pqc,
            contents,
        )
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom<T: AsRef<[u8]>>(
        &self,
        wave_id: u32,
        group: u64,
        contents: T,
    ) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.encrypt(
            calculate_nonce_version(wave_id as usize, group),
            pqc,
            contents,
        )
    }
}

#[derive(Serialize, Deserialize)]
///
pub struct ThinRatchetInner {
    drill: EntropyBank,
    pqc: PostQuantumContainer,
}

impl Ratchet for ThinRatchet {
    type Constructor = ThinRatchetConstructor;

    fn get_cid(&self) -> u64 {
        self.inner.drill.cid
    }

    fn version(&self) -> u32 {
        self.inner.drill.version
    }

    fn has_verified_packets(&self) -> bool {
        self.inner.pqc.has_verified_packets()
    }

    fn reset_ara(&self) {
        self.inner.pqc.reset_counters()
    }

    fn get_default_security_level(&self) -> SecurityLevel {
        SecurityLevel::Standard
    }

    fn message_pqc_drill(&self, _idx: Option<usize>) -> (&PostQuantumContainer, &EntropyBank) {
        (&self.inner.pqc, &self.inner.drill)
    }

    fn get_scramble_drill(&self) -> &EntropyBank {
        &self.inner.drill
    }

    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts> {
        vec![ConstructorOpts::new_from_previous(
            Some(self.inner.pqc.params),
            self.inner.pqc.get_chain().unwrap().clone(),
        )]
    }

    fn protect_message_packet<T: EzBuffer>(
        &self,
        _security_level: Option<SecurityLevel>,
        header_len_bytes: usize,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.protect_packet(pqc, header_len_bytes, packet)
    }

    fn validate_message_packet<H: AsRef<[u8]>, T: EzBuffer>(
        &self,
        _security_level: Option<SecurityLevel>,
        header: H,
        packet: &mut T,
    ) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    fn local_encrypt<'a, T: Into<Cow<'a, [u8]>>>(
        &self,
        contents: T,
        _security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.local_encrypt(pqc, contents.into())
    }

    fn local_decrypt<'a, T: Into<Cow<'a, [u8]>>>(
        &self,
        contents: T,
        _security_level: SecurityLevel,
    ) -> Result<Vec<u8>, CryptError> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.local_decrypt(pqc, contents.into())
    }
}

/// Used for constructing the ratchet
#[derive(Serialize, Deserialize)]
pub struct ThinRatchetConstructor {
    params: CryptoParameters,
    pqc: PostQuantumContainer,
    drill: Option<EntropyBank>,
    nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
    cid: u64,
    version: u32,
}

impl EndpointRatchetConstructor<ThinRatchet> for ThinRatchetConstructor {
    fn new_alice(
        mut opts: Vec<ConstructorOpts>,
        cid: u64,
        new_version: u32,
        _security_level: Option<SecurityLevel>,
    ) -> Option<Self> {
        ThinRatchetConstructor::new_alice(cid, new_version, opts.remove(0))
    }

    fn new_bob(
        _cid: u64,
        _new_drill_vers: u32,
        mut opts: Vec<ConstructorOpts>,
        transfer: AliceToBobTransferType,
    ) -> Option<Self> {
        match transfer {
            AliceToBobTransferType::Fcm(transfer) => {
                ThinRatchetConstructor::new_bob(opts.remove(0), transfer)
            }

            _ => {
                log::error!(target: "citadel", "Incompatible Ratchet Type passed! [X-43]");
                None
            }
        }
    }

    fn stage0_alice(&self) -> Option<AliceToBobTransferType> {
        Some(AliceToBobTransferType::Fcm(self.stage0_alice()?))
    }

    fn stage0_bob(&self) -> Option<BobToAliceTransferType> {
        Some(BobToAliceTransferType::Fcm(self.stage0_bob()?))
    }

    fn stage1_alice(&mut self, transfer: BobToAliceTransferType) -> Result<(), CryptError> {
        match transfer {
            BobToAliceTransferType::Fcm(transfer) => self.stage1_alice(transfer),

            _ => Err(CryptError::DrillUpdateError(
                "Incompatible Ratchet Type passed! [X-44]".to_string(),
            )),
        }
    }

    fn update_version(&mut self, version: u32) -> Option<()> {
        self.update_version(version)
    }

    fn finish_with_custom_cid(self, cid: u64) -> Option<ThinRatchet> {
        self.finish_with_custom_cid(cid)
    }

    fn finish(self) -> Option<ThinRatchet> {
        self.finish()
    }
}

#[derive(Serialize, Deserialize)]
///
pub struct FcmAliceToBobTransfer {
    transfer_params: AliceToBobTransferParameters,
    pub params: CryptoParameters,
    nonce: ArrayVec<u8, LARGEST_NONCE_LEN>,
    /// the declared cid
    pub cid: u64,
    /// the declared version
    pub version: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FcmBobToAliceTransfer {
    params_tx: BobToAliceTransferParameters,
    encrypted_drill_bytes: Vec<u8>,
}

impl ThinRatchetConstructor {
    /// FCM limits messages to 4Kb, so we need to use firesaber alone
    pub fn new_alice(cid: u64, version: u32, opts: ConstructorOpts) -> Option<Self> {
        let params = opts.cryptography.unwrap_or_default();
        let pqc = PostQuantumContainer::new_alice(opts).ok()?;

        Some(Self {
            params,
            pqc,
            drill: None,
            nonce: EntropyBank::generate_public_nonce(params.encryption_algorithm),
            cid,
            version,
        })
    }

    ///
    pub fn new_bob(opts: ConstructorOpts, transfer: FcmAliceToBobTransfer) -> Option<Self> {
        let params = transfer.params;
        let pqc = PostQuantumContainer::new_bob(opts, transfer.transfer_params).ok()?;
        let drill =
            EntropyBank::new(transfer.cid, transfer.version, params.encryption_algorithm).ok()?;

        Some(Self {
            params,
            pqc,
            drill: Some(drill),
            nonce: transfer.nonce,
            cid: transfer.cid,
            version: transfer.version,
        })
    }

    ///
    pub fn stage0_alice(&self) -> Option<FcmAliceToBobTransfer> {
        let pk = self.pqc.generate_alice_to_bob_transfer().ok()?;
        Some(FcmAliceToBobTransfer {
            params: self.params,
            transfer_params: pk,
            nonce: self.nonce.clone(),
            cid: self.cid,
            version: self.version,
        })
    }

    ///
    pub fn stage0_bob(&self) -> Option<FcmBobToAliceTransfer> {
        Some(FcmBobToAliceTransfer {
            params_tx: self.pqc.generate_bob_to_alice_transfer().ok()?,
            encrypted_drill_bytes: self
                .pqc
                .encrypt(self.drill.as_ref()?.serialize_to_vec().ok()?, &self.nonce)
                .ok()?,
        })
    }

    ///
    pub fn stage1_alice(&mut self, transfer: FcmBobToAliceTransfer) -> Result<(), CryptError> {
        self.pqc
            .alice_on_receive_ciphertext(transfer.params_tx)
            .map_err(|err| CryptError::DrillUpdateError(err.to_string()))?;
        let bytes = self
            .pqc
            .decrypt(&transfer.encrypted_drill_bytes, &self.nonce)
            .map_err(|err| CryptError::DrillUpdateError(err.to_string()))?;
        let drill = EntropyBank::deserialize_from(&bytes[..])?;
        self.drill = Some(drill);
        Ok(())
    }

    ///
    pub fn update_version(&mut self, version: u32) -> Option<()> {
        self.version = version;
        self.drill.as_mut()?.version = version;
        Some(())
    }

    ///
    pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<ThinRatchet> {
        self.cid = cid;
        self.drill.as_mut()?.cid = cid;
        self.finish()
    }

    ///
    pub fn finish(self) -> Option<ThinRatchet> {
        ThinRatchet::try_from(self).ok()
    }
}

impl TryFrom<ThinRatchetConstructor> for ThinRatchet {
    type Error = ();

    fn try_from(value: ThinRatchetConstructor) -> Result<Self, Self::Error> {
        let drill = value.drill.ok_or(())?;
        let pqc = value.pqc;
        let inner = ThinRatchetInner { drill, pqc };
        Ok(ThinRatchet {
            inner: Arc::new(inner),
        })
    }
}
