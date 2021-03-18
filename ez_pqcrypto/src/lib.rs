#![allow(non_camel_case_types)]

use crate::export::PostQuantumExport;
use pqcrypto_traits::{Error, kem::{PublicKey, SecretKey, SharedSecret, Ciphertext}};
use std::convert::TryFrom;
#[cfg(feature = "chacha20")]
use chacha20poly1305::{XChaCha20Poly1305 as AeadKey, aead::{NewAead, Aead, AeadInPlace, generic_array::GenericArray}};
#[cfg(not(feature = "chacha20"))]
use aes_gcm_siv::{Aes256GcmSiv as AeadKey, aead::{NewAead, Aead, AeadInPlace, generic_array::GenericArray}};
use crate::ez_error::EzError;
use crate::bytes_in_place::{InPlaceBuffer, InPlaceByteSliceMut, EzBuffer};
use std::fmt::Debug;
use std::fmt::Formatter;

#[cfg(not(feature = "unordered"))]
pub type AntiReplayAttackContainer = crate::replay_attack_container::ordered::AntiReplayAttackContainer;

#[cfg(feature = "unordered")]
pub type AntiReplayAttackContainer = crate::replay_attack_container::unordered::AntiReplayAttackContainer;

pub mod prelude {
    pub use pqcrypto_traits::Error;
    pub use crate::{PQNode, PostQuantumContainer, PostQuantumType, algorithm_dictionary};
}

#[cfg(feature = "chacha20")]
pub const NONCE_LENGTH_BYTES: usize = 24;

#[cfg(not(feature = "chacha20"))]
pub const NONCE_LENGTH_BYTES: usize = 12;

pub mod bytes_in_place;

/// For handling serialization/deserialization
pub mod export;

/// For organizing error types
pub mod ez_error;

/// For protecting against replay attacks
pub mod replay_attack_container;

/// For debug purposes
#[cfg(not(feature = "unordered"))]
pub const fn build_tag() -> &'static str {
    "ordered/single-threaded networking protocol"
}

/// For debug purposes
#[cfg(feature = "unordered")]
pub const fn build_tag() -> &'static str {
    "unordered/multi-threaded networking protocol"
}

/// Returns the approximate size of each PQC
pub const fn get_approx_bytes_per_container() -> usize {
    pqcrypto_saber::firesaber_ciphertext_bytes() +
        pqcrypto_saber::firesaber_public_key_bytes() +
        pqcrypto_saber::firesaber_secret_key_bytes() +
        pqcrypto_saber::firesaber_shared_secret_bytes()
}

/// The number of bytes in a firesaber pk
pub const FIRESABER_PK_SIZE: usize = pqcrypto_saber::firesaber_public_key_bytes();

/// Contains the public keys for Alice and Bob
pub struct PostQuantumContainer {
    pub(crate) algorithm: u8,
    pub(crate) data: FiresaberContainer,
    pub(crate) anti_replay_attack: AntiReplayAttackContainer,
    pub(crate) shared_secret: Option<AeadKey>,
    pub(crate) node: PQNode
}

/// Used to denote the local node's instance type
#[derive(PartialEq, Copy, Clone, Debug)]
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
    pub fn new_alice(algorithm: Option<u8>) -> Self {
        let algorithm = algorithm.unwrap_or(0);
        let data = Self::get_new_alice(algorithm);
        let aes_gcm_key = None;
        Self { algorithm, data, shared_secret: aes_gcm_key, anti_replay_attack: AntiReplayAttackContainer::default(), node: PQNode::Alice }
    }

    /// Creates a new [PostQuantumContainer] for Bob. This will panic if the algorithm is
    /// invalid
    pub fn new_bob(algorithm: u8, public_key: &[u8]) -> Result<Self, Error> {
        let data = Self::get_new_bob(algorithm, public_key)?;
        // We must call the below to refresh the internal state to allow get_shared_secret to function
        let ss = data.get_shared_secret().unwrap();
        let key = GenericArray::<u8, _>::from_exact_iter(ss.into_iter().cloned()).ok_or(Error::BadLength {
            name: "",
            actual: 0,
            expected: 0
        })?;

        let aes_gcm_key = Some(AeadKey::new(&key));

        Ok(Self { algorithm, shared_secret: aes_gcm_key, data, anti_replay_attack: AntiReplayAttackContainer::default(), node: PQNode::Bob })
    }

    /// Resets the counters to zero, as well as reset and additional stateful resources
    pub fn reset_counters(&self) {
        self.anti_replay_attack.reset();
    }

    /// This should always be called after deserialization
    fn load_aes_gcm_key(&mut self) {
        self.shared_secret = Some(AeadKey::new(&GenericArray::clone_from_slice(self.get_shared_secret().unwrap())))
    }

    /// Internally creates shared key after bob sends a response back to Alice
    pub fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        //debug_assert_eq!(self.node, PQNode::Alice);
        self.data.alice_on_receive_ciphertext(ciphertext)?;
        let ss = self.data.get_shared_secret().unwrap();
        self.shared_secret = Some(AeadKey::new(&GenericArray::clone_from_slice(ss)));
        Ok(())
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

    /// Returns the byte-sized representation of the algorithm used
    pub fn get_algorithm_idx(&self) -> u8 {
        self.algorithm
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, input: T, nonce: R) -> Result<Vec<u8>, EzError> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();
        let nonce = GenericArray::from_slice(nonce);

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.shared_secret.as_ref() {
            match aes_gcm_key.encrypt(nonce, input) {
                Err(_) => {
                    Err(EzError::AesGcmEncryptionFailure)
                },

                Ok(vec) => {
                    Ok(vec)
                }
            }
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    pub fn protect_packet_in_place<T: EzBuffer, R: AsRef<[u8]>>(&self, header_len: usize, full_packet: &mut T, nonce: R) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let nonce = GenericArray::from_slice(nonce);
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
        let nonce = GenericArray::from_slice(nonce);
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

        let nonce = GenericArray::from_slice(nonce);
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

        let nonce = GenericArray::from_slice(nonce);
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
    fn get_new_alice(_algorithm: u8) -> FiresaberContainer {
        FiresaberContainer::new_alice()
    }

    /// This, for now, only gets FIRESABER
    fn get_new_bob(_algorithm: u8, public_key: &[u8]) -> Result<FiresaberContainer, Error> {
        FiresaberContainer::new_bob(public_key)
    }
}

impl Clone for PostQuantumContainer {
    fn clone(&self) -> Self {
        let ser = self.serialize_to_vector().unwrap();
        PostQuantumContainer::deserialize_from_bytes(ser).unwrap()
    }
}

impl TryFrom<PostQuantumExport> for PostQuantumContainer {
    type Error = Error;

    fn try_from(export: PostQuantumExport) -> Result<Self, Self::Error> {
        // First, create the type, pretending this node is Bob since we already
        // have the public key
        let algorithm = export.algorithm;
        let node = if export.node == 0 {
            PQNode::Alice
        } else {
            PQNode::Bob
        };

        // we override all the values, so we can go with either
        let mut container = PostQuantumContainer::new_bob(algorithm, export.public_key.as_slice())?;
        container.node = node;
        container.data.set_public_key(export.public_key.as_slice())?;

        // Now, begin setting the values
        if let Some(secret_key) = export.secret_key {
            container.data.set_secret_key(secret_key.as_slice())?;
        }

        if let Some(ciphertext) = export.ciphertext {
            container.data.set_ciphertext(ciphertext.as_slice())?;
        }

        if let Some(shared_secret) = export.shared_secret {
            let shared_secret_slice = shared_secret.as_slice();
            container.data.set_shared_secret(shared_secret_slice)?;
        }

        container.anti_replay_attack = bincode2::deserialize(&export.ara).map_err(|_err| generic_err())?;

        container.load_aes_gcm_key();

        Ok(container)
    }
}

/// Used for packet transmission
#[allow(missing_docs)]
pub mod algorithm_dictionary {
    pub const ALGORITHM_COUNT: u8 = 42;

    pub const BABYBEAR: u8 = 0;
    pub const BABYBEAREPHEM: u8 = 1;

    pub const FIRESABER: u8 = 2;

    pub const FRODOKEM640AES: u8 = 3;
    pub const FRODOKEM640SHAKE: u8 = 4;
    pub const FRODOKEM976AES: u8 = 5;
    pub const FRODOKEM976SHAKE: u8 = 6;
    pub const FRODOKEM1344AES: u8 = 7;
    pub const FRODOKEM1344SHAKE: u8 = 8;

    pub const KYBER512: u8 = 9;
    pub const KYBER768: u8 = 10;
    pub const KYBER1024: u8 = 11;
    pub const KYBER51290S: u8 = 12;
    pub const KYBER76890S: u8 = 13;
    pub const KYBER102490S: u8 = 14;

    pub const LEDAKEMLT12: u8 = 15;
    pub const LEDAKEMLT32: u8 = 16;
    pub const LEDAKEMLT52: u8 = 17;

    pub const LIGHTSABER: u8 = 18;

    pub const MAMABEAR: u8 = 19;
    pub const MAMABEAREPHEM: u8 = 20;

    pub const MCELIECE348864: u8 = 21;
    pub const MCELIECE348864F: u8 = 22;
    pub const MCELIECE460896: u8 = 23;
    pub const MCELIECE460896F: u8 = 24;
    pub const MCELIECE6688128: u8 = 25;
    pub const MCELIECE6688128F: u8 = 26;
    pub const MCELIECE6960119: u8 = 27;
    pub const MCELIECE6960119F: u8 = 28;
    pub const MCELIECE8192128: u8 = 29;
    pub const MCELIECE8192128F: u8 = 30;

    pub const NEWHOPE512CCA: u8 = 31;
    pub const NEWHOPE512CPA: u8 = 32;
    pub const NEWHOPE1024CCA: u8 = 33;
    pub const NEWHOPE1024CPA: u8 = 34;

    pub const NTRUHPS2048509: u8 = 35;
    pub const NTRUHPS2048677: u8 = 36;
    pub const NTRUHPS4096821: u8 = 37;
    pub const NTRUHRSS701: u8 = 38;

    pub const PAPABEAR: u8 = 39;
    pub const PAPABEAREPHEM: u8 = 40;

    pub const SABER: u8 = 41;
}

/// Used to get different algorithm types dynamically
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
    /// Sets the secret key
    fn set_secret_key(&mut self, secret_key: &[u8]) -> Result<(), Error>;
    /// Sets the ciphertext
    fn set_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error>;
    /// Sets the shared key
    fn set_shared_secret(&mut self, shared_key: &[u8]) -> Result<(), Error>;
    /// Sets the public key
    fn set_public_key(&mut self, public_key: &[u8]) -> Result<(), Error>;
}

#[derive(Clone)]
struct FiresaberContainer {
    public_key: pqcrypto_saber::firesaber::PublicKey,
    ciphertext: Option<pqcrypto_saber::firesaber::Ciphertext>,
    secret_key: Option<pqcrypto_saber::firesaber::SecretKey>,
    shared_key: Option<pqcrypto_saber::firesaber::SharedSecret>
}

impl PostQuantumType for FiresaberContainer {
    fn new_alice() -> Self where Self: Sized {
        let (public_key, secret_key) = pqcrypto_saber::firesaber_keypair();
        Self { public_key, ciphertext: None, secret_key: Some(secret_key), shared_key: None }
    }

    fn new_bob(public_key: &[u8]) -> Result<Self, Error> where Self: Sized {
        let public_key = pqcrypto_saber::firesaber::PublicKey::from_bytes(public_key)?;
        let (shared_secret, ciphertext) = pqcrypto_saber::firesaber_encapsulate(&public_key);
        Ok(Self { public_key, ciphertext: Some(ciphertext), secret_key: None, shared_key: Some(shared_secret)})
    }

    fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        let ciphertext = pqcrypto_saber::firesaber::Ciphertext::from_bytes(ciphertext)?;
        let secret_key= self.secret_key.as_ref().unwrap();
        let ss = pqcrypto_saber::firesaber_decapsulate(&ciphertext, secret_key);
        self.shared_key = Some(ss);
        Ok(())
    }

    fn get_public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn get_secret_key(&self) -> Result<&[u8], Error> {
        self.secret_key.as_ref().map(|res| res.as_bytes())
            .ok_or(generic_err())
    }

    fn get_ciphertext(&self) -> Result<&[u8], Error> {
        self.ciphertext.as_ref().map(|res| res.as_bytes())
            .ok_or(generic_err())
    }

    fn get_shared_secret(&self) -> Result<&[u8], Error> {
        self.shared_key.as_ref().map(|res| res.as_bytes())
            .ok_or(generic_err())
    }

    fn set_secret_key(&mut self, secret_key: &[u8]) -> Result<(), Error> {
        let secret_key = pqcrypto_saber::firesaber::SecretKey::from_bytes(secret_key)?;
        self.secret_key = Some(secret_key);
        Ok(())
    }

    fn set_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        let ciphertext = pqcrypto_saber::firesaber::Ciphertext::from_bytes(ciphertext)?;
        self.ciphertext = Some(ciphertext);
        Ok(())
    }

    fn set_shared_secret(&mut self, shared_key: &[u8]) -> Result<(), Error> {
        let shared_key = pqcrypto_saber::firesaber::SharedSecret::from_bytes(shared_key)?;
        self.shared_key = Some(shared_key);
        Ok(())
    }

    fn set_public_key(&mut self, public_key: &[u8]) -> Result<(), Error> {
        let public_key = pqcrypto_saber::firesaber::PublicKey::from_bytes(public_key)?;
        self.public_key = public_key;
        Ok(())
    }
}

const fn generic_err() -> Error {
    Error::BadLength {
        name: "",
        actual: 0,
        expected: 0
    }
}

impl Debug for PostQuantumContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PQC")
    }
}