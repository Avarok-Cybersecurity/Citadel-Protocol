#![allow(non_camel_case_types)]

use pqcrypto_traits::Error;
use crate::ez_error::EzError;
use crate::bytes_in_place::{InPlaceBuffer, InPlaceByteSliceMut, EzBuffer};
use std::fmt::Debug;
use std::fmt::Formatter;
use crate::algorithm_dictionary::{KemAlgorithm, CryptoParameters, EncryptionAlgorithm};
use serde::{Serialize, Deserialize};
use crate::function_pointers::{ALICE_FP, BOB_FP};
use crate::encryption::AeadModule;

#[cfg(not(feature = "unordered"))]
pub type AntiReplayAttackContainer = crate::replay_attack_container::ordered::AntiReplayAttackContainer;

#[cfg(feature = "unordered")]
pub type AntiReplayAttackContainer = crate::replay_attack_container::unordered::AntiReplayAttackContainer;

pub mod prelude {
    pub use pqcrypto_traits::Error;
    pub use crate::{PQNode, PostQuantumContainer, PostQuantumType, algorithm_dictionary};
}

pub const LARGEST_NONCE_LEN: usize = 24;

pub const CHA_CHA_NONCE_LENGTH_BYTES: usize = 24;

pub const AES_GCM_NONCE_LENGTH_BYTES: usize = 12;

pub mod bytes_in_place;

/// For handling serialization/deserialization
pub mod export;

/// For organizing error types
pub mod ez_error;

/// For protecting against replay attacks
pub mod replay_attack_container;

/// For abstracting-away the use of aead
pub mod encryption;

/// For debug purposes
#[cfg(not(feature = "unordered"))]
pub const fn build_tag() -> &'static str {
    "ordered"
}

/// For debug purposes
#[cfg(feature = "unordered")]
pub const fn build_tag() -> &'static str {
    "unordered"
}

/// Returns the approximate size of each PQC
pub const fn get_approx_bytes_per_container() -> usize {
    pqcrypto_saber::firesaber_ciphertext_bytes() +
        pqcrypto_saber::firesaber_public_key_bytes() +
        pqcrypto_saber::firesaber_secret_key_bytes() +
        pqcrypto_saber::firesaber_shared_secret_bytes()
}

/// The number of bytes in a firesaber pk
//pub const FIRESABER_PK_SIZE: usize = pqcrypto_saber::firesaber_public_key_bytes();

/// Contains the public keys for Alice and Bob
#[derive(Serialize)]
pub struct PostQuantumContainer {
    pub params: CryptoParameters,
    pub(crate) data: Box<dyn PostQuantumType>,
    pub(crate) anti_replay_attack: AntiReplayAttackContainer,
    #[serde(skip)]
    pub(crate) shared_secret: Option<Box<dyn AeadModule>>,
    pub(crate) node: PQNode
}

/// Used to denote the local node's instance type
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum PQNode {
    /// The first node in the exchange. Alice generates a key, gets a public key (pk)
    /// and a secret key (sk). Alice sends pk to Bob
    Alice,
    /// The second node in the exchange. Bob receives the Public key, pk, and encapsulates it.
    /// The encapsulation function returns a shared secret (ss) and a ciphertext (ct) for Bob.
    /// Bob then sends ct to Alice. Finally, Bob uses the newly received ct, coupled with his
    /// local sk to get the shared secret, ss. Ultimately, the ss is used to xor the bytes
    Bob,
}

impl PostQuantumContainer {
    /// Creates a new [PostQuantumContainer] for Alice. This will panic if the algorithm is
    /// invalid
    ///
    /// `algorithm`: If this is None, a random algorithm will be used
    pub fn new_alice(params: Option<impl Into<CryptoParameters>>) -> Self {
        let params = params.map(|r| r.into()).unwrap_or_default();
        let data = Self::get_new_alice(params.kem_algorithm);
        let aes_gcm_key = None;
        Self { params, data, shared_secret: aes_gcm_key, anti_replay_attack: AntiReplayAttackContainer::default(), node: PQNode::Alice }
    }

    /// Creates a new [PostQuantumContainer] for Bob. This will panic if the algorithm is
    /// invalid
    pub fn new_bob(params: Option<impl Into<CryptoParameters>>, public_key: &[u8]) -> Result<Self, Error> {
        let params = params.map(|r| r.into()).unwrap_or_default();

        let data = Self::get_new_bob(params.kem_algorithm, public_key)?;
        // We must call the below to refresh the internal state to allow get_shared_secret to function
        let ss = data.get_shared_secret().unwrap();


        let aes_gcm_key = Some(Self::get_aes_gcm_key(params.encryption_algorithm, ss)?);

        Ok(Self { params, shared_secret: aes_gcm_key, data, anti_replay_attack: AntiReplayAttackContainer::default(), node: PQNode::Bob })
    }

    fn get_aes_gcm_key(encryption_algorithm: EncryptionAlgorithm, ss: &[u8]) -> Result<Box<dyn AeadModule>, Error> {
        match encryption_algorithm {
            EncryptionAlgorithm::AES_GCM_256_SIV => {
                use aes_gcm_siv::aead::NewAead;
                //let key = aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_slice(ss);
                let key = aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(ss.into_iter().cloned()).ok_or(Error::BadLength {
                    name: "",
                    actual: 0,
                    expected: 0
                })?;

                Ok(Box::new(aes_gcm_siv::Aes256GcmSiv::new(&key)))
            }

            EncryptionAlgorithm::Xchacha20Poly_1305 => {
                use chacha20poly1305::aead::NewAead;
                //let key = chacha20poly1305::aead::generic_array::GenericArray::<u8, _>::from_slice(ss);
                let key = aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(ss.into_iter().cloned()).ok_or(Error::BadLength {
                    name: "",
                    actual: 0,
                    expected: 0
                })?;

                Ok(Box::new(chacha20poly1305::XChaCha20Poly1305::new(&key)))
            }
        }
    }

    /// Resets the counters to zero, as well as reset and additional stateful resources
    pub fn reset_counters(&self) {
        self.anti_replay_attack.reset();
    }

    /// This should always be called after deserialization
    fn load_symmetric_key(&mut self) -> Result<(), Error> {
        let algo = self.params.encryption_algorithm;
        let ss = self.get_shared_secret()?;
        self.shared_secret = Some(Self::get_aes_gcm_key(algo, ss)?);
        Ok(())
        //self.shared_secret = Some(AeadKey::new(&GenericArray::clone_from_slice(self.get_shared_secret().unwrap())))
    }

    /// Internally creates shared key after bob sends a response back to Alice
    pub fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        //debug_assert_eq!(self.node, PQNode::Alice);
        self.data.alice_on_receive_ciphertext(ciphertext)?;
        let _ss = self.data.get_shared_secret()?; // call once to load internally
        self.load_symmetric_key()
    }

    /// Returns true if either Tx/Rx Anti-replay attack counters have been engaged (useful for determining
    /// if resetting the state is necessary)
    pub fn has_verified_packets(&self) -> bool {
        self.anti_replay_attack.has_tracked_packets()
    }

    /// Gets the public key
    pub fn get_public_key(&self) -> &[u8] {
        self.data.get_public_key()
    }
    /// Gets the secret key (If node is Alice type)
    pub fn get_secret_key(&self) -> Result<&[u8], Error> {
        self.data.get_secret_key()
    }
    /// Gets the ciphertext
    pub fn get_ciphertext(&self) -> Result<&[u8], Error> {
        self.data.get_ciphertext()
    }
    /// Gets the shared secret
    pub fn get_shared_secret(&self) -> Result<&[u8], Error> {
        self.data.get_shared_secret()
    }

    /// Serializes the entire package to a vector
    pub fn serialize_to_vector(&self) -> Result<Vec<u8>, EzError> {
        bincode2::serialize(self).map_err(|_err| EzError::Generic("Deserialization failure"))
    }

    /// Attempts to deserialize the input bytes presumed to be of type [PostQuantumExport],
    /// into a [PostQuantumContainer]
    pub fn deserialize_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, EzError> {
        bincode2::deserialize::<PostQuantumContainer>(bytes.as_ref()).map_err(|_err| EzError::Generic("Deserialization failure"))
    }

    /// Returns either Alice or Bob
    pub fn get_node_type(&self) -> PQNode {
        self.node
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, input: T, nonce: R) -> Result<Vec<u8>, EzError> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            aes_gcm_key.encrypt(nonce, input)
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    pub fn protect_packet_in_place<T: EzBuffer, R: AsRef<[u8]>>(&self, header_len: usize, full_packet: &mut T, nonce: R) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let mut payload = full_packet.split_off(header_len);
        let header = full_packet;

        // next, push the ARA-generated PID
        payload.put_u64(self.anti_replay_attack.get_next_pid());
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(&mut payload, 0..payload_len).ok_or_else(|| EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            aes_gcm_key.encrypt_in_place(nonce, header.subset(0..header_len), &mut in_place_payload).map_err(|_| EzError::AesGcmEncryptionFailure)?;
            header.unsplit(payload);
            Ok(())
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Validates the AAD (header) and produces the plaintext given the input of ciphertext
    pub fn validate_packet_in_place<T: EzBuffer, H: AsRef<[u8]>, R: AsRef<[u8]>>(&self, header: H, payload: &mut T, nonce: R) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let header = header.as_ref();
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(payload, 0..payload_len).ok_or_else(|| EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            aes_gcm_key.decrypt_in_place(nonce, header, &mut in_place_payload).map_err(|_| EzError::AesGcmDecryptionFailure)
                .and_then(|_| {
                    // get the last 8 bytes of the payload
                    let end_idx = payload.len();
                    let start_idx = end_idx.saturating_sub(8);
                    if end_idx - start_idx == 8 {
                        let mut array: [u8; 8] = Default::default();
                        array.copy_from_slice(payload.subset(start_idx..end_idx));
                        if self.anti_replay_attack.on_pid_received(u64::from_be_bytes(array)) {
                            // remove the PID from the payload
                            payload.truncate(start_idx);
                            Ok(())
                        } else {
                            Err(EzError::Generic("Anti-replay-attack: invalid"))
                        }
                    } else {
                        Err(EzError::Generic("Anti-replay-attack: Invalid inscription length"))
                    }
                })
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, input: T, nonce: R) -> Result<Vec<u8>, EzError> where Self: Sized {
        let input = input.as_ref();
        let nonce = nonce.as_ref();
        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            match aes_gcm_key.decrypt(nonce, input) {
                Err(_) => {
                    Err(EzError::AesGcmDecryptionFailure)
                },

                Ok(vec) => {
                    Ok(vec)
                }
            }
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn decrypt_in_place<T: AsMut<[u8]>, R: AsRef<[u8]>>(&self, mut input: T, nonce: R) -> Result<usize, EzError> where Self: Sized {
        let input = input.as_mut();
        let mut buf = InPlaceByteSliceMut::from(input);
        let nonce = nonce.as_ref();
        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            match aes_gcm_key.decrypt_in_place(nonce, &[], &mut buf) {
                Err(_) => {
                    Err(EzError::AesGcmDecryptionFailure)
                },

                Ok(_) => {
                    Ok(buf.get_finished_len())
                }
            }
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// This, for now, only gets FIRESABER
    fn get_new_alice(kem_algorithm: KemAlgorithm) -> Box<dyn PostQuantumType> {
        ALICE_FP[kem_algorithm as u8 as usize]().into()
    }

    /// This, for now, only gets FIRESABER
    fn get_new_bob(kem_algorithm: KemAlgorithm, public_key: &[u8]) -> Result<Box<dyn PostQuantumType>, Error> {
        BOB_FP[kem_algorithm as u8 as usize](public_key)
    }
}

impl Clone for PostQuantumContainer {
    fn clone(&self) -> Self {
        let ser = self.serialize_to_vector().unwrap();
        PostQuantumContainer::deserialize_from_bytes(ser).unwrap()
    }
}

/// Used for packet transmission
#[allow(missing_docs)]
pub mod algorithm_dictionary {
    use enum_primitive::*;
    use std::convert::{TryFrom, TryInto};
    use serde::{Serialize, Deserialize};
    use std::ops::Add;
    use crate::{AES_GCM_NONCE_LENGTH_BYTES, CHA_CHA_NONCE_LENGTH_BYTES};
    use strum::ParseError;

    #[derive(Default, Serialize, Deserialize, Copy, Clone, Debug)]
    pub struct CryptoParameters {
        pub encryption_algorithm: EncryptionAlgorithm,
        pub kem_algorithm: KemAlgorithm
    }

    impl Into<u8> for CryptoParameters {
        fn into(self) -> u8 {
            self.encryption_algorithm as u8 + self.kem_algorithm as u8
        }
    }

    impl TryFrom<u8> for CryptoParameters {
        type Error = ();

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                x if x >= EncryptionAlgorithm::AES_GCM_256_SIV.into() && x < EncryptionAlgorithm::Xchacha20Poly_1305.into() => {
                    let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
                    let kem_algorithm = (x % ALGORITHM_COUNT).try_into()?;
                    Ok(Self { encryption_algorithm, kem_algorithm })
                }

                x if x >= EncryptionAlgorithm::Xchacha20Poly_1305.into() && x < (2 * ALGORITHM_COUNT) => {
                    let encryption_algorithm = EncryptionAlgorithm::Xchacha20Poly_1305;
                    let kem_algorithm = (x % ALGORITHM_COUNT).try_into()?;
                    Ok(Self { encryption_algorithm, kem_algorithm })
                }

                _ => Err(())
            }
        }
    }

    impl Add<EncryptionAlgorithm> for KemAlgorithm {
        type Output = CryptoParameters;

        fn add(self, rhs: EncryptionAlgorithm) -> Self::Output {
            CryptoParameters { kem_algorithm: self, encryption_algorithm: rhs }
        }
    }

    impl Add<KemAlgorithm> for EncryptionAlgorithm {
        type Output = CryptoParameters;

        fn add(self, rhs: KemAlgorithm) -> Self::Output {
            CryptoParameters { kem_algorithm: rhs, encryption_algorithm: self }
        }
    }

    enum_from_primitive! {
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum EncryptionAlgorithm {
            AES_GCM_256_SIV = 0, Xchacha20Poly_1305 = ALGORITHM_COUNT as isize
        }
    }

    impl EncryptionAlgorithm {
        pub fn nonce_len(&self) -> usize {
            match self {
                Self::AES_GCM_256_SIV => AES_GCM_NONCE_LENGTH_BYTES,
                Self::Xchacha20Poly_1305 => CHA_CHA_NONCE_LENGTH_BYTES
            }
        }

        pub fn list() -> Vec<EncryptionAlgorithm> {
            vec![EncryptionAlgorithm::AES_GCM_256_SIV, EncryptionAlgorithm::Xchacha20Poly_1305]
        }
    }

    impl TryFrom<u8> for EncryptionAlgorithm {
        type Error = ();

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            EncryptionAlgorithm::from_u8(value).ok_or(())
        }
    }

    impl Into<u8> for EncryptionAlgorithm {
        fn into(self) -> u8 {
            self as u8
        }
    }

    impl Default for EncryptionAlgorithm {
        fn default() -> Self {
            EncryptionAlgorithm::AES_GCM_256_SIV
        }
    }

    pub const ALGORITHM_COUNT: u8 = 10;

    enum_from_primitive! {
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, strum::EnumString, strum::EnumIter)]
        pub enum KemAlgorithm {
            #[strum(ascii_case_insensitive)]
            Lightsaber = 0,
            #[strum(ascii_case_insensitive)]
            Saber = 1,
            #[strum(ascii_case_insensitive)]
            Firesaber = 2,
            #[strum(ascii_case_insensitive)]
            Kyber512_90s = 3,
            #[strum(ascii_case_insensitive)]
            Kyber768_90s = 4,
            #[strum(ascii_case_insensitive)]
            Kyber1024_90s = 5,
            #[strum(ascii_case_insensitive)]
            Ntruhps2048509 = 6,
            #[strum(ascii_case_insensitive)]
            Ntruhps2048677 = 7,
            #[strum(ascii_case_insensitive)]
            Ntruhps4096821 = 8,
            #[strum(ascii_case_insensitive)]
            Ntruhrss701 = 9
        }
    }

    impl KemAlgorithm {
        pub fn list() -> Vec<KemAlgorithm> {
            vec![KemAlgorithm::Lightsaber, KemAlgorithm::Saber, KemAlgorithm::Firesaber,
            KemAlgorithm::Kyber512_90s, KemAlgorithm::Kyber768_90s, KemAlgorithm::Kyber1024_90s,
            KemAlgorithm::Ntruhps2048509, KemAlgorithm::Ntruhps2048677, KemAlgorithm::Ntruhps4096821, KemAlgorithm::Ntruhrss701]
        }

        pub fn try_from_str<R: AsRef<str>>(t: R) -> Result<Self, ParseError> {
            use std::str::FromStr;
            KemAlgorithm::from_str(t.as_ref())
        }

        pub fn names() -> Vec<String> {
            use strum::IntoEnumIterator;
            KemAlgorithm::iter().map(|r| format!("{:?}", r).to_lowercase()).collect()
        }
    }

    impl TryFrom<u8> for KemAlgorithm {
        type Error = ();

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            KemAlgorithm::from_u8(value).ok_or(())
        }
    }

    impl Into<u8> for KemAlgorithm {
        fn into(self) -> u8 {
            self as u8
        }
    }

    impl Default for KemAlgorithm {
        fn default() -> Self {
            KemAlgorithm::Firesaber
        }
    }

}

/// Used to get different algorithm types dynamically
#[typetag::serde(tag = "type")]
pub trait PostQuantumType: Send + Sync {
    /// Creates a new self for the initiating node
    fn new_alice() -> Self where Self: Sized;
    /// Creates a new self for the receiving node
    fn new_bob(public_key: &[u8]) -> Result<Self, Error> where Self: Sized;
    /// Internally creates shared key after bob sends a response back to Alice
    fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error>;
    /// Gets the public key
    fn get_public_key(&self) -> &[u8];
    /// Gets the secret key (If node is Alice type)
    fn get_secret_key(&self) -> Result<&[u8], Error>;
    /// Gets the ciphertext
    fn get_ciphertext(&self) -> Result<&[u8], Error>;
    /// Gets the shared secret
    fn get_shared_secret(&self) -> Result<&[u8], Error>;
}

macro_rules! create_struct {
    ($base_path:ident, $variant:ident, $struct_name:ident) => {
        /// Auto generated
        #[derive(Serialize, Deserialize)]
        pub(crate) struct $struct_name {
            /// The public key. Both Alice and Bob get this
            public_key: $base_path::$variant::PublicKey,
            /// Only Alice gets this one
            secret_key: Option<$base_path::$variant::SecretKey>,
            /// Both Bob and Alice get this one
            ciphertext: Option<$base_path::$variant::Ciphertext>,
            /// Both Alice and Bob get this (at the end)
            shared_secret: Option<$base_path::$variant::SharedSecret>
        }

        #[typetag::serde]
        impl PostQuantumType for $struct_name {
            fn new_alice() -> Self {
                let (public_key, secret_key) = $base_path::$variant::keypair();
                let ciphertext = None;
                let shared_secret = None;
                let secret_key = Some(secret_key);
                Self { public_key, secret_key, ciphertext, shared_secret }
            }

            fn new_bob(public_key: &[u8]) -> Result<Self, Error> {
                let public_key = $base_path::$variant::PublicKey::from_bytes(public_key)?;
                let (shared_secret, ciphertext) = $base_path::$variant::encapsulate(&public_key);
                let secret_key = None;
                let shared_secret = Some(shared_secret);
                let ciphertext = Some(ciphertext);
                Ok(Self { public_key, secret_key, ciphertext, shared_secret })
            }

            fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
                // These functions should only be called once upon response back from Bob
                debug_assert!(self.shared_secret.is_none());
                debug_assert!(self.ciphertext.is_none());
                debug_assert!(self.secret_key.is_some());

                let ciphertext = $base_path::$variant::Ciphertext::from_bytes(ciphertext)?;

                if let Some(secret_key) = self.secret_key.as_ref() {
                    let shared_secret = $base_path::$variant::decapsulate(&ciphertext, secret_key);
                    self.ciphertext = Some(ciphertext);
                    self.shared_secret = Some(shared_secret);
                    Ok(())
                } else {
                    Err(Error::BadLength {
                        name: "Unable to get secret key",
                        actual: 0,
                        expected: 0
                    })
                }
            }

            fn get_public_key(&self) -> &[u8] {
                self.public_key.as_bytes()
            }

            fn get_secret_key(&self) -> Result<&[u8], Error> {
                if let Some(secret_key) = self.secret_key.as_ref() {
                    Ok(secret_key.as_bytes())
                } else {
                    Err(get_generic_error("Unable to get secret key"))
                }
            }

            fn get_ciphertext(&self) -> Result<&[u8], Error> {
                if let Some(ciphertext) = self.ciphertext.as_ref() {
                    Ok(ciphertext.as_bytes())
                } else {
                    Err(get_generic_error("Unable to get ciphertext"))
                }
            }

            fn get_shared_secret(&self) -> Result<&[u8], Error> {
                if let Some(shared_secret) = self.shared_secret.as_ref() {
                    Ok(shared_secret.as_bytes())
                } else {
                    Err(get_generic_error("Unable to get secret key"))
                }
            }
        }
    };
}

pub(crate) mod function_pointers {
    use crate::PostQuantumType;
    use crate::algorithm_dictionary::ALGORITHM_COUNT;
    use pqcrypto_traits::Error;

    macro_rules! box_alice {
    ($constructor:expr) => {{
        #[inline(never)]
        fn alice_box_fn() -> Box<dyn PostQuantumType>{
            Box::new(($constructor)())
        }

        alice_box_fn
    }};
}

    macro_rules! box_bob {
    ($constructor:expr) => {{
        #[inline(never)]
        fn bob_box_fn(arr: &[u8]) -> Result<Box<dyn PostQuantumType>, Error> {
            Ok(Box::new(($constructor)(arr)?))
        }

        bob_box_fn
    }};
}

    pub(crate) static ALICE_FP: [fn() -> Box<dyn PostQuantumType>; ALGORITHM_COUNT as usize] = [
        box_alice!(crate::post_quantum_structs::LightsaberContainer::new_alice),
        box_alice!(crate::post_quantum_structs::SaberContainer::new_alice),
        box_alice!(crate::post_quantum_structs::FiresaberContainer::new_alice),
        box_alice!(crate::post_quantum_structs::Kyber512_90sContainer::new_alice),
        box_alice!(crate::post_quantum_structs::Kyber768_90sContainer::new_alice),
        box_alice!(crate::post_quantum_structs::Kyber1024_90sContainer::new_alice),
        box_alice!(crate::post_quantum_structs::Ntru_hps_2048_509Container::new_alice),
        box_alice!(crate::post_quantum_structs::Ntru_hps_2048_677Container::new_alice),
        box_alice!(crate::post_quantum_structs::Ntru_hps_4096_821Container::new_alice),
        box_alice!(crate::post_quantum_structs::Ntru_hrss_701Container::new_alice),
    ];

    pub(crate) static BOB_FP: [fn(&[u8]) -> Result<Box<dyn PostQuantumType>, Error>; ALGORITHM_COUNT as usize] = [
        box_bob!(crate::post_quantum_structs::LightsaberContainer::new_bob),
        box_bob!(crate::post_quantum_structs::SaberContainer::new_bob),
        box_bob!(crate::post_quantum_structs::FiresaberContainer::new_bob),
        box_bob!(crate::post_quantum_structs::Kyber512_90sContainer::new_bob),
        box_bob!(crate::post_quantum_structs::Kyber768_90sContainer::new_bob),
        box_bob!(crate::post_quantum_structs::Kyber1024_90sContainer::new_bob),
        box_bob!(crate::post_quantum_structs::Ntru_hps_2048_509Container::new_bob),
        box_bob!(crate::post_quantum_structs::Ntru_hps_2048_677Container::new_bob),
        box_bob!(crate::post_quantum_structs::Ntru_hps_4096_821Container::new_bob),
        box_bob!(crate::post_quantum_structs::Ntru_hrss_701Container::new_bob),
    ];
}

/// A set of auto generated structs corresponding to one of many possible encryption schemes
pub(crate) mod post_quantum_structs {
    use pqcrypto_traits::{Error, kem::{PublicKey, SecretKey, SharedSecret, Ciphertext}};
    use super::PostQuantumType;
    use serde::{Serialize, Deserialize};

    fn get_generic_error(text: &'static str) -> Error {
        Error::BadLength {
            name: text,
            actual: 0,
            expected: 0,
        }
    }

    create_struct!(pqcrypto_saber, lightsaber, LightsaberContainer);
    create_struct!(pqcrypto_saber, saber, SaberContainer);
    create_struct!(pqcrypto_saber, firesaber, FiresaberContainer);

    create_struct!(pqcrypto_kyber, kyber51290s, Kyber512_90sContainer);
    create_struct!(pqcrypto_kyber, kyber76890s, Kyber768_90sContainer);
    create_struct!(pqcrypto_kyber, kyber102490s, Kyber1024_90sContainer);

    create_struct!(pqcrypto_ntru, ntruhps2048509, Ntru_hps_2048_509Container);
    create_struct!(pqcrypto_ntru, ntruhps2048677, Ntru_hps_2048_677Container);
    create_struct!(pqcrypto_ntru, ntruhps4096821, Ntru_hps_4096_821Container);
    create_struct!(pqcrypto_ntru, ntruhrss701, Ntru_hrss_701Container);
}

impl Debug for PostQuantumContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PQC {:?} | {:?}", self.node, self.params)
    }
}