use crate::drill::{Drill, BYTES_PER_3D_ARRAY};
use ez_pqcrypto::PostQuantumContainer;
use std::sync::Arc;
use crate::hyper_ratchet::constructor::HyperRatchetConstructor;
use std::convert::TryFrom;
use bytes::BytesMut;
use crate::misc::CryptError;
use serde::{Serialize, Deserialize};
use crate::net::crypt_splitter::calculate_nonce_version;

/// A container meant to establish perfect forward secrecy AND scrambling w/ an independent key
/// This is meant for messages, not file transfer. File transfers should use a single key throughout
/// the entire file
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HyperRatchet {
    pub(crate) inner: Arc<HyperRatchetInner>
}

unsafe impl Send for HyperRatchet {}
unsafe impl Sync for HyperRatchet {}

/// Returns the approximate size of each hyper ratchet
pub const fn get_approx_bytes_per_hyper_ratchet() -> usize {
    (2 * ez_pqcrypto::get_approx_bytes_per_container()) +
        (2 * BYTES_PER_3D_ARRAY)
}

impl HyperRatchet {
    /// Determines if either the PQC's anti-replay attack containers have been engaged
    pub fn has_verified_packets(&self) -> bool {
        self.get_message_pqc().has_verified_packets()
        || self.get_scramble_pqc().has_verified_packets()
    }

    /// returns the scramble PQC
    pub fn get_scramble_pqc(&self) -> &PostQuantumContainer {
        &self.inner.scramble.pqc
    }

    /// returns the message pqc and drill
    pub fn message_pqc_drill(&self) -> (&PostQuantumContainer, &Drill) {
        (&self.inner.message.pqc, &self.inner.message.drill)
    }

    /// returns the message pqc and drill
    pub fn scramble_pqc_drill(&self) -> (&PostQuantumContainer, &Drill) {
        (&self.inner.scramble.pqc, &self.inner.scramble.drill)
    }

    /// Protects the packet, treating the header as AAD, and the payload as the data that gets encrypted
    pub fn protect_message_packet_with_scrambler(&self, header_len_bytes: usize, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.protect_packet(pqc, header_len_bytes, packet)
    }

    /// Protects the packet, treating the header as AAD, and the payload as the data that gets encrypted
    pub fn protect_message_packet(&self, header_len_bytes: usize, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.protect_packet(pqc, header_len_bytes, packet)
    }

    /// Validates a packet in place
    pub fn validate_message_packet<H: AsRef<[u8]>>(&self, header: H, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    /// Validates a packet in place
    pub fn validate_message_packet_with_scrambler<H: AsRef<[u8]>>(&self, header: H, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    /// Validates in-place when the header + payload have already been split
    pub fn validate_message_packet_in_place_split<H: AsRef<[u8]>>(&self, header: H, packet: &mut BytesMut) -> Result<(), CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.validate_packet_in_place_split(pqc, header, packet)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt_custom(0, 0, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom<T: AsRef<[u8]>>(&self, wave_id: u32, group: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.aes_gcm_encrypt(calculate_nonce_version(wave_id as usize, group), pqc, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_scrambler<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.encrypt_custom_scrambler(0, 0, contents)
    }

    /// Encrypts the data into a Vec<u8>
    pub fn encrypt_custom_scrambler<T: AsRef<[u8]>>(&self, wave_id: u32, group: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_encrypt(calculate_nonce_version(wave_id as usize, group), pqc, contents)
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt_custom(0, 0, contents)
    }

    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom<T: AsRef<[u8]>>(&self, wave_id: u32, group_id: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.aes_gcm_decrypt(calculate_nonce_version(wave_id as usize, group_id), pqc, contents)
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_scrambler<T: AsRef<[u8]>>(&self, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        self.decrypt_custom_scrambler(0, 0, contents)
    }

    /// decrypts using a custom nonce configuration
    pub fn decrypt_custom_scrambler<T: AsRef<[u8]>>(&self, wave_id: u32, group_id: u64, contents: T) -> Result<Vec<u8>, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_decrypt(calculate_nonce_version(wave_id as usize, group_id), pqc, contents)
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_in_place<T: AsMut<[u8]>>(&self, contents: &mut T) -> Result<usize, CryptError<String>> {
        self.decrypt_in_place_custom(0, 0, contents)
    }

    /// decrypts in place using a custom nonce configuration
    pub fn decrypt_in_place_custom<T: AsMut<[u8]>>(&self, wave_id: u32, group_id: u64, contents: &mut T) -> Result<usize, CryptError<String>> {
        let (pqc, drill) = self.message_pqc_drill();
        drill.aes_gcm_decrypt_in_place(calculate_nonce_version(wave_id as usize, group_id), pqc, contents)
    }

    /// Decrypts the contents into a Vec<u8>
    pub fn decrypt_in_place_scrambler<T: AsMut<[u8]>>(&self, contents: &mut T) -> Result<usize, CryptError<String>> {
        self.decrypt_in_place_custom_scrambler(0, 0, contents)
    }

    /// decrypts in place using a custom nonce configuration
    pub fn decrypt_in_place_custom_scrambler<T: AsMut<[u8]>>(&self, wave_id: u32, group_id: u64, contents: &mut T) -> Result<usize, CryptError<String>> {
        let (pqc, drill) = self.scramble_pqc_drill();
        drill.aes_gcm_decrypt_in_place(calculate_nonce_version(wave_id as usize, group_id), pqc, contents)
    }

    /// Returns the message drill
    pub fn get_message_drill(&self) -> &Drill {
        &self.inner.message.drill
    }

    /// Returns the message pqc
    pub fn get_message_pqc(&self) -> &PostQuantumContainer {
        &self.inner.message.pqc
    }

    /// Returns the scramble drill
    pub fn get_scramble_drill(&self) -> &Drill {
        &self.inner.scramble.drill
    }

    /// Returns the [HyperRatchet]'s version
    pub fn version(&self) -> u32 {
        self.inner.message.drill.version
    }

    /// Returns the CID
    pub fn get_cid(&self) -> u64 {
        self.inner.message.drill.cid
    }
}

#[derive(Serialize, Deserialize, Debug)]
///
pub struct HyperRatchetInner {
    pub(crate) message: MessageRatchet,
    pub(crate) scramble: ScrambleRatchet
}

///
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MessageRatchet {
    pub(crate) drill: Drill,
    pub(crate) pqc: PostQuantumContainer
}

///
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ScrambleRatchet {
    pub(crate) drill: Drill,
    pub(crate) pqc: PostQuantumContainer
}

impl From<HyperRatchetInner> for HyperRatchet {
    fn from(inner: HyperRatchetInner) -> Self {
        Self { inner: Arc::new(inner) }
    }
}

/// For constructing the HyperRatchet during KEM stage
pub mod constructor {
    use crate::drill::Drill;
    use ez_pqcrypto::PostQuantumContainer;
    use serde::{Serialize, Deserialize};
    use crate::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use crate::hyper_ratchet::HyperRatchet;
    use std::convert::TryFrom;
    use bytes::BytesMut;
    use bytes::buf::BufMutExt;

    /// Used during the key exchange process
    pub struct HyperRatchetConstructor {
        pub(super) message: MessageRatchetConstructor,
        pub(super) scramble: ScrambleRatchetConstructor,
        nonce_message: [u8; AES_GCM_NONCE_LEN_BYTES],
        nonce_scramble: [u8; AES_GCM_NONCE_LEN_BYTES]
    }

    #[derive(Serialize, Deserialize)]
    /// Transferred during KEM
    pub struct AliceToBobTransfer<'a> {
        msg_alice_pk: &'a [u8],
        scramble_alice_pk: &'a [u8],
        msg_nonce: [u8; AES_GCM_NONCE_LEN_BYTES],
        scramble_nonce: [u8; AES_GCM_NONCE_LEN_BYTES]
    }

    #[derive(Serialize, Deserialize)]
    /// Transferred during KEM
    pub struct BobToAliceTransfer {
        msg_bob_ct: Vec<u8>,
        scramble_bob_ct: Vec<u8>,
        encrypted_msg_drill: Vec<u8>,
        encrypted_scramble_drill: Vec<u8>
    }

    impl BobToAliceTransfer {
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
    }

    impl HyperRatchetConstructor {
        /// Called during the initialization stage
        pub fn new_alice(algorithm: Option<u8>) -> Self {
            Self {
                message: MessageRatchetConstructor { drill: None, pqc: PostQuantumContainer::new_alice(algorithm) },
                scramble: ScrambleRatchetConstructor { drill: None, pqc: PostQuantumContainer::new_alice(algorithm) },
                nonce_message: Drill::generate_public_nonce(),
                nonce_scramble: Drill::generate_public_nonce()
            }
        }

        /// Called when bob receives alice's pk's
        pub fn new_bob(algorithm: u8, cid: u64, new_drill_vers: u32, transfer: AliceToBobTransfer) -> Option<Self> {
            Some(Self {
                message: MessageRatchetConstructor { drill: Some(Drill::new(cid, new_drill_vers).ok()?), pqc: PostQuantumContainer::new_bob(algorithm, transfer.msg_alice_pk).ok()? },
                scramble: ScrambleRatchetConstructor { drill: Some(Drill::new(cid, new_drill_vers).ok()?), pqc: PostQuantumContainer::new_bob(algorithm, transfer.scramble_alice_pk).ok()? },
                nonce_message: transfer.msg_nonce,
                nonce_scramble: transfer.scramble_nonce
            })
        }

        /// Generates the public key for the (message_pk, scramble_pk, nonce)
        pub fn stage0_alice(&self) -> AliceToBobTransfer<'_> {
            let msg_alice_pk = self.message.pqc.get_public_key();
            let scramble_alice_pk = self.scramble.pqc.get_public_key();
            let msg_nonce = self.nonce_message;
            let scramble_nonce = self.nonce_scramble;

            AliceToBobTransfer {
                msg_alice_pk,
                scramble_alice_pk,
                msg_nonce,
                scramble_nonce
            }
        }

        /// Returns the (message_bob_ct, scramble_bob_ct, msg_drill_serialized, scramble_drill_serialized)
        pub fn stage0_bob(&self) -> Option<BobToAliceTransfer> {
            let msg_bob_ct = self.message.pqc.get_ciphertext().ok()?.to_vec();
            let scramble_bob_ct = self.scramble.pqc.get_ciphertext().ok()?.to_vec();
            // now, generate the serialized bytes
            let msg_drill_serialized = self.message.drill.as_ref()?.serialize_to_vec().ok()?;
            let scramble_drill_serialized = self.scramble.drill.as_ref()?.serialize_to_vec().ok()?;

            let ref nonce_msg = self.nonce_message;
            let ref nonce_scramble = self.nonce_scramble;
            let encrypted_msg_drill = self.message.pqc.encrypt(msg_drill_serialized, nonce_msg).ok()?;
            let encrypted_scramble_drill = self.scramble.pqc.encrypt(scramble_drill_serialized, nonce_scramble).ok()?;

            let transfer = BobToAliceTransfer {
                msg_bob_ct,
                scramble_bob_ct,
                encrypted_msg_drill,
                encrypted_scramble_drill
            };

            Some(transfer)
        }

        /// Returns Some(()) if process succeeded
        pub fn stage1_alice(&mut self, transfer: BobToAliceTransfer) -> Option<()> {
            let ref nonce_msg = self.nonce_message;
            self.message.pqc.alice_on_receive_ciphertext(&transfer.msg_bob_ct[..]).ok()?;
            // now, using the message pqc, decrypt the message drill
            let decrypted_msg_drill = self.message.pqc.decrypt(&transfer.encrypted_msg_drill[..], nonce_msg).ok()?;
            self.message.drill = Some(Drill::deserialize_from(&decrypted_msg_drill[..]).ok()?);

            let ref nonce_scramble = self.nonce_scramble;
            self.scramble.pqc.alice_on_receive_ciphertext(&transfer.scramble_bob_ct[..]).ok()?;
            // do the same as above
            let decrypted_scramble_drill = self.scramble.pqc.decrypt(&transfer.encrypted_scramble_drill[..], nonce_scramble).ok()?;
            self.scramble.drill = Some(Drill::deserialize_from(&decrypted_scramble_drill[..]).ok()?);

            // version check
            if self.scramble.drill.as_ref().unwrap().version != self.message.drill.as_ref().unwrap().version {
                return None;
            }

            if self.scramble.drill.as_ref().unwrap().cid != self.message.drill.as_ref().unwrap().cid {
                return None;
            }

            Some(())
        }

        /// Upgrades the construction into the HyperRatchet
        pub fn finish(self) -> Option<HyperRatchet> {
            HyperRatchet::try_from(self).ok()
        }

        /// Sometimes, replacing the CID is useful such as during peer KEM exhcange wherein
        /// the CIDs between both parties are different
        pub fn finish_with_custom_cid(mut self, cid: u64) -> Option<HyperRatchet> {
            self.message.drill.as_mut()?.cid = cid;
            self.scramble.drill.as_mut()?.cid = cid;
            self.finish()
        }
    }

    ///
    pub(super) struct MessageRatchetConstructor {
        pub(super) drill: Option<Drill>,
        pub(super) pqc: PostQuantumContainer
    }

    ///
    pub(super) struct ScrambleRatchetConstructor {
        pub(super) drill: Option<Drill>,
        pub(super) pqc: PostQuantumContainer
    }
}

impl TryFrom<HyperRatchetConstructor> for HyperRatchet {
    type Error = ();

    fn try_from(value: HyperRatchetConstructor) -> Result<Self, Self::Error> {
        let HyperRatchetConstructor { message, scramble, .. } = value;
        // make sure shared secrets are loaded
        let _ = message.pqc.get_shared_secret().map_err(|_| ())?;
        let _ = scramble.pqc.get_shared_secret().map_err(|_| ())?;

        let message_drill = message.drill.ok_or(())?;
        let scramble_drill = scramble.drill.ok_or(())?;

        if message_drill.version != scramble_drill.version
            || message_drill.cid != scramble_drill.cid {
            return Err(())
        }

        let message = MessageRatchet {
            drill: message_drill,
            pqc: message.pqc
        };

        let scramble = ScrambleRatchet {
            drill: scramble_drill,
            pqc: scramble.pqc
        };

        Ok(HyperRatchet { inner: Arc::new(HyperRatchetInner { message, scramble }) })
    }
}