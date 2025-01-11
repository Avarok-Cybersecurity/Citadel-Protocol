use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::misc::CryptError;
use bytes::BytesMut;
use citadel_pqcrypto::bytes_in_place::EzBuffer;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::crypto::SecurityLevel;
use entropy_bank::EntropyBank;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Debug;

/// Organizes the different types of entropy_banks that can be used. Currently, there is only one: The Standard Drill
pub mod entropy_bank;
pub mod mono;
/// `RatchetManager` provides a robust, sync-safe method to rekey across networks between two nodes
pub mod ratchet_manager;
pub mod stacked;

/// For allowing registration inside the toolset
pub trait Ratchet:
    Debug + Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + 'static
{
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
