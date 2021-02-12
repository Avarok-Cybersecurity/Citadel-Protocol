use crate::drill::{Drill, SecurityLevel};
use ez_pqcrypto::PostQuantumContainer;
use std::sync::Arc;
use crate::hyper_ratchet::Ratchet;
use serde::{Serialize, Deserialize};
use crate::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use std::convert::TryFrom;
use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::hyper_ratchet::constructor::{AliceToBobTransferType, BobToAliceTransferType};
use crate::misc::CryptError;
use bytes::BytesMut;
use crate::net::crypt_splitter::calculate_nonce_version;
use std::alloc::Global;

#[derive(Clone, Serialize, Deserialize)]
/// A compact ratchet meant for FCM messages
pub struct FcmRatchet {
    inner: Arc<FcmRatchetInner>
}

impl FcmRatchet {
    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom<T: AsRef<[u8]>>(&self, wave_id: u32, group_id: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.aes_gcm_decrypt(calculate_nonce_version(wave_id as usize, group_id), pqc, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom<T: AsRef<[u8]>>(&self, wave_id: u32, group: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.aes_gcm_encrypt(calculate_nonce_version(wave_id as usize, group), pqc, contents)
    }
}

#[derive(Serialize, Deserialize)]
///
pub struct FcmRatchetInner {
    drill: Drill,
    pqc: PostQuantumContainer
}

impl<'a> Ratchet for FcmRatchet {
    type Constructor = FcmRatchetConstructor;

    fn get_cid(&self) -> u64 {
        self.inner.drill.cid
    }

    fn version(&self) -> u32 {
        self.inner.drill.version
    }

    fn has_verified_packets(&self) -> bool {
        self.inner.pqc.has_verified_packets()
    }

    fn message_pqc_drill(&self, _idx: Option<usize>) -> (&PostQuantumContainer, &Drill) {
        (&self.inner.pqc, &self.inner.drill)
    }

    fn get_scramble_drill(&self) -> &Drill {
        &self.inner.drill
    }

    fn protect_message_packet(&self, _security_level: Option<SecurityLevel>, header_len_bytes: usize, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.protect_packet(pqc, header_len_bytes, packet)
    }

    fn validate_message_packet<H: AsRef<[u8]>>(&self, _security_level: Option<SecurityLevel>, ref header: H, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill(None);
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8, Global>, CryptError<String>> {
        self.decrypt_custom(0, 0, contents)
    }

    fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8, Global>, CryptError<String>> {
        self.encrypt_custom(0, 0, contents)
    }
}

/// Used for constructing the ratchet
pub struct FcmRatchetConstructor {
    pqc: PostQuantumContainer,
    drill: Option<Drill>,
    nonce: [u8; AES_GCM_NONCE_LEN_BYTES],
    cid: u64,
    version: u32
}

impl EndpointRatchetConstructor<FcmRatchet> for FcmRatchetConstructor {
    fn new_alice(_algorithm: Option<u8>, cid: u64, new_version: u32, _security_level: Option<SecurityLevel>) -> Self {
        FcmRatchetConstructor::new_alice(cid, new_version)
    }

    fn new_bob(_algorithm: u8, _cid: u64, _new_drill_vers: u32, transfer: AliceToBobTransferType<'_>) -> Option<Self> {
        match transfer {
            AliceToBobTransferType::Fcm(transfer) => {
                FcmRatchetConstructor::new_bob(transfer)
            }

            _ => {
                log::error!("Incompatible Ratchet Type passed! [X-43]");
                None
            }
        }
    }

    fn stage0_alice(&self) -> AliceToBobTransferType<'_> {
        AliceToBobTransferType::Fcm(self.stage0_alice())
    }

    fn stage0_bob(&self) -> Option<BobToAliceTransferType> {
        Some(BobToAliceTransferType::Fcm(self.stage0_bob()?))
    }

    fn stage1_alice(&mut self, transfer: BobToAliceTransferType) -> Option<()> {
        match transfer {
            BobToAliceTransferType::Fcm(transfer) => {
                self.stage1_alice(transfer)
            }

            _ => {
                log::error!("Incompatible Ratchet Type passed! [X-44]");
                None
            }
        }
    }

    fn update_version(&mut self, version: u32) -> Option<()> {
        self.update_version(version)
    }

    fn finish_with_custom_cid(self, cid: u64) -> Option<FcmRatchet> {
        self.finish_with_custom_cid(cid)
    }

    fn finish(self) -> Option<FcmRatchet> {
        self.finish()
    }
}

#[derive(Serialize, Deserialize)]
///
pub struct FcmAliceToBobTransfer<'a> {
    pk: &'a [u8],
    nonce: [u8; AES_GCM_NONCE_LEN_BYTES],
    /// the declared cid
    pub cid: u64,
    /// the declared version
    pub version: u32
}

#[derive(Serialize, Deserialize)]
pub struct FcmBobToAliceTransfer {
    ct: Vec<u8>,
    encrypted_drill_bytes: Vec<u8>
}

impl FcmRatchetConstructor {
    /// FCM limits messages to 4Kb, so we need to use firesaber alone
    pub fn new_alice(cid: u64, version: u32) -> Self {
        let pqc = PostQuantumContainer::new_alice(None);
        Self {
            pqc,
            drill: None,
            nonce: Drill::generate_public_nonce(),
            cid,
            version
        }
    }

    ///
    pub fn new_bob(transfer: FcmAliceToBobTransfer<'_>) -> Option<Self> {
        let pqc = PostQuantumContainer::new_bob(0, transfer.pk).ok()?;
        let drill = Drill::new(transfer.cid, transfer.version).ok()?;
        Some(Self {
            pqc,
            drill: Some(drill),
            nonce: transfer.nonce,
            cid: transfer.cid,
            version: transfer.version
        })
    }

    ///
    pub fn stage0_alice(&self) -> FcmAliceToBobTransfer<'_> {
        let pk = self.pqc.get_public_key();
        FcmAliceToBobTransfer {
            pk,
            nonce: self.nonce.clone(),
            cid: self.cid,
            version: self.version
        }
    }

    ///
    pub fn stage0_bob(&self) -> Option<FcmBobToAliceTransfer> {
        Some(
            FcmBobToAliceTransfer {
                ct: self.pqc.get_ciphertext().ok()?.to_vec(),
                encrypted_drill_bytes: self.pqc.encrypt(self.drill.as_ref()?.serialize_to_vec().ok()?, &self.nonce).ok()?
            }
        )
    }

    ///
    pub fn stage1_alice(&mut self, transfer: FcmBobToAliceTransfer) -> Option<()> {
        self.pqc.alice_on_receive_ciphertext(transfer.ct.as_slice()).ok()?;
        let bytes = self.pqc.decrypt(transfer.encrypted_drill_bytes, &self.nonce).ok()?;
        let drill = Drill::deserialize_from(&bytes[..]).ok()?;
        self.drill = Some(drill);
        Some(())
    }

    ///
    pub fn update_version(&mut self, version: u32) -> Option<()> {
        self.version = version;
        self.drill.as_mut()?.version = version;
        Some(())
    }

    ///
    pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<FcmRatchet> {
        self.cid = cid;
        self.drill.as_mut()?.cid = cid;
        self.finish()
    }

    ///
    pub fn finish(self) -> Option<FcmRatchet> {
        FcmRatchet::try_from(self).ok()
    }
}

impl TryFrom<FcmRatchetConstructor> for FcmRatchet {
    type Error = ();

    fn try_from(value: FcmRatchetConstructor) -> Result<Self, Self::Error> {
        let drill = value.drill.ok_or(())?;
        let pqc = value.pqc;
        let inner = FcmRatchetInner { drill, pqc };
        Ok(FcmRatchet { inner: Arc::new(inner) })
    }
}