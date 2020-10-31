#![allow(non_camel_case_types)]

use crate::algorithm_dictionary::*;
use rand::Rng;
use crate::export::PostQuantumExport;
use pqcrypto::traits::Error;
use std::convert::TryFrom;
#[cfg(feature = "chacha20")]
use chacha20poly1305::{XChaCha20Poly1305 as AeadKey, aead::{NewAead, Aead, AeadInPlace, generic_array::GenericArray}};
#[cfg(not(feature = "chacha20"))]
use aes_gcm_siv::{Aes256GcmSiv as AeadKey, aead::{NewAead, Aead, AeadInPlace, generic_array::GenericArray}};
use crate::ez_error::EzError;
use nanoserde::{SerBin, DeBin};
use crate::bytes_in_place::InPlaceBytesMut;
use bytes::{BytesMut, BufMut};
use crate::replay_attack_container::ordered::AntiReplayAttackContainerOrdered;

pub mod prelude {
    pub use pqcrypto::traits::Error;
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

pub mod replay_attack_container;

/// Contains the public keys for Alice and Bob
pub struct PostQuantumContainer {
    pub(crate) algorithm: u8,
    pub(crate) data: Box<dyn PostQuantumType>,
    pub(crate) anti_replay_attack: AntiReplayAttackContainerOrdered,
    pub(crate) aes_gcm_key: Option<AeadKey>,
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
        let algorithm = algorithm.unwrap_or_else(|| {
            rand::thread_rng().gen_range(0, ALGORITHM_COUNT)
        });

        let data = Self::get_new_alice(algorithm);
        let aes_gcm_key = None;
        Self { algorithm, data, aes_gcm_key, anti_replay_attack: AntiReplayAttackContainerOrdered::default(), node: PQNode::Alice }
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

        Ok(Self { algorithm, aes_gcm_key, data, anti_replay_attack: AntiReplayAttackContainerOrdered::default(), node: PQNode::Bob })
    }

    /// This should always be called after deserialization
    fn load_aes_gcm_key(&mut self) {
        self.aes_gcm_key = Some(AeadKey::new(&GenericArray::clone_from_slice(self.get_shared_secret().unwrap())))
    }

    /// Internally creates shared key after bob sends a response back to Alice
    pub fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
        //debug_assert_eq!(self.node, PQNode::Alice);
        self.data.alice_on_receive_ciphertext(ciphertext)?;
        let ss = self.data.get_shared_secret().unwrap();
        self.aes_gcm_key = Some(AeadKey::new(&GenericArray::clone_from_slice(ss)));
        Ok(())
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
    pub fn serialize_to_vector(&self) -> Result<Vec<u8>, Error> {
        let export = PostQuantumExport::from(self);
        Ok(export.serialize_bin())
    }

    /// Attempts to deserialize the input bytesm presumed to be of type [PostQuantumExport],
    /// into a [PostQuantumContainer]
    pub fn deserialize_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, EzError> {
        //let export = bincode2::deserialize::<PostQuantumExport>(bytes.as_ref())?;
        let export = PostQuantumExport::deserialize_bin(bytes.as_ref()).map_err(|_err| EzError::Generic("Deserialization failure"))?;
        PostQuantumContainer::try_from(export).map_err(|_err| EzError::Generic("Deserialization failure"))
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
    pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, input: T, nonce: R) -> Result<Vec<u8>, EzError> where Self: Sized {
        let input = input.as_ref();
        let nonce = nonce.as_ref();
        let nonce = GenericArray::from_slice(nonce);

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.aes_gcm_key.as_ref() {
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

    pub fn protect_packet_in_place<R: AsRef<[u8]>>(&self, header_len: usize, full_packet: &mut BytesMut, nonce: R) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let nonce = GenericArray::from_slice(nonce);
        let mut payload = full_packet.split_off(header_len);
        let header = full_packet;

        // next, push the ARA-generated PID
        payload.put_u64(self.anti_replay_attack.get_next_pid());
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBytesMut::new(&mut payload, 0..payload_len).ok_or_else(|| EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.aes_gcm_key.as_ref() {
            aes_gcm_key.encrypt_in_place(nonce, &header[0..header_len], &mut in_place_payload).map_err(|_| EzError::AesGcmEncryptionFailure)?;
            header.unsplit(payload);
            Ok(())
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Validates the AAD (header) and produces the plaintext given the input of ciphertext
    pub fn validate_packet_in_place<H: AsRef<[u8]>, R: AsRef<[u8]>>(&self, header: H, mut payload: &mut BytesMut, nonce: R) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let nonce = GenericArray::from_slice(nonce);
        let header = header.as_ref();
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBytesMut::new(&mut payload, 0..payload_len).ok_or_else(|| EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.aes_gcm_key.as_ref() {
            aes_gcm_key.decrypt_in_place(nonce, header, &mut in_place_payload).map_err(|_| EzError::AesGcmDecryptionFailure)
                .and_then(|_| {
                    // get the last 8 bytes of the payload
                    let end_idx = payload.len();
                    let start_idx = end_idx.saturating_sub(8);
                    if end_idx - start_idx == 8 {
                        let mut array: [u8; 8] = Default::default();
                        array.copy_from_slice(&payload[start_idx..end_idx]);

                        if self.anti_replay_attack.on_pid_received(u64::from_be_bytes(array)) {
                            // remove the PID from the payload
                            payload.truncate(start_idx);
                            return Ok(())
                        }
                    }

                    Err(EzError::Generic("Anti-replay-attack: invalid"))
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

        if let Some(aes_gcm_key) = self.aes_gcm_key.as_ref() {
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

    /// This, for now, only gets FIRESABER
    fn get_new_alice(algorithm: u8) -> Box<dyn PostQuantumType> {
        assert!(algorithm < ALGORITHM_COUNT);
        crate::function_pointers::ALICE_FP[0]()
    }

    /// This, for now, only gets FIRESABER
    fn get_new_bob(algorithm: u8, public_key: &[u8]) -> Result<Box<dyn PostQuantumType>, Error> {
        assert!(algorithm < ALGORITHM_COUNT);
        crate::function_pointers::BOB_FP[0](public_key)
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

        let mut container = PostQuantumContainer::new_bob(algorithm, export.public_key.as_slice())?;
        container.node = node;
        container.data.set_public_key(export.public_key.as_slice()).unwrap();

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

macro_rules! create_struct {
    ($base:ident, $name:ident) => {
        /// Auto generated
        #[derive(Clone)]
        pub(crate) struct $base {
            /// The public key. Both Alice and Bob get this
            public_key: pqcrypto::kem::$name::PublicKey,
            /// Only Alice gets this one
            secret_key: Option<pqcrypto::kem::$name::SecretKey>,
            /// Both Bob and Alice get this one
            ciphertext: Option<pqcrypto::kem::$name::Ciphertext>,
            /// Both Alice and Bob get this (at the end)
            shared_secret: Option<pqcrypto::kem::$name::SharedSecret>
        }

        //unsafe impl Send for $base {}
        //unsafe impl Sync for $base {}

        impl PostQuantumType for $base {

            fn new_alice() -> Self {
                let (public_key, secret_key) = pqcrypto::kem::$name::keypair();
                let ciphertext = None;
                let shared_secret = None;
                let secret_key = Some(secret_key);

                Self { public_key, secret_key, ciphertext, shared_secret }
            }

            fn new_bob(public_key: &[u8]) -> Result<Self, Error> {
                let public_key = pqcrypto::kem::$name::PublicKey::from_bytes(public_key)?;
                let (shared_secret, ciphertext) = pqcrypto::kem::$name::encapsulate(&public_key);
                let secret_key = None;
                let shared_secret = Some(shared_secret);
                let ciphertext = Some(ciphertext);

                Ok(Self { public_key, secret_key, ciphertext, shared_secret })
            }

            fn alice_on_receive_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
                // These functions should only be called once upon response back from Bob
                assert!(self.shared_secret.is_none());
                assert!(self.ciphertext.is_none());
                assert!(self.secret_key.is_some());

                let ciphertext = pqcrypto::kem::$name::Ciphertext::from_bytes(ciphertext)?;

                if let Some(secret_key) = self.secret_key.as_ref() {
                    let shared_secret = pqcrypto::kem::$name::decapsulate(&ciphertext, secret_key);
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

            fn set_public_key(&mut self, public_key: &[u8]) -> Result<(), Error> {
                let public_key = pqcrypto::kem::$name::PublicKey::from_bytes(public_key)?;
                self.public_key = public_key;

                Ok(())
            }

            /// Sets the secret key
            fn set_secret_key(&mut self, secret_key: &[u8]) -> Result<(), Error> {
                let secret_key = pqcrypto::kem::$name::SecretKey::from_bytes(secret_key)?;
                self.secret_key = Some(secret_key);

                Ok(())
            }

            /// Sets the ciphertext
            fn set_ciphertext(&mut self, ciphertext: &[u8]) -> Result<(), Error> {
                let ciphertext = pqcrypto::kem::$name::Ciphertext::from_bytes(ciphertext)?;
                self.ciphertext = Some(ciphertext);

                Ok(())
            }

            /// Sets the shared key
            fn set_shared_secret(&mut self, shared_secret: &[u8]) -> Result<(), Error> {
                let shared_secret = pqcrypto::kem::$name::SharedSecret::from_bytes(shared_secret)?;
                self.shared_secret = Some(shared_secret);

                Ok(())
            }
        }
    };
}

pub(crate) mod function_pointers {
    use crate::PostQuantumType;
    //use crate::algorithm_dictionary::ALGORITHM_COUNT;
    use pqcrypto::traits::Error;

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

    pub(crate) static ALICE_FP: [fn() -> Box<dyn PostQuantumType>; 1] = [
        //box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_babybear::new_alice),
        //box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_babybearephem::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_firesaber::new_alice),
        /*
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem640aes::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem640shake::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem976aes::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem976shake::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem1344aes::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem1344shake::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber512::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber768::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber1024::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber51290s::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber76890s::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber102490s::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt12::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt32::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt52::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_lightsaber::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mamabear::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mamabearephem::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece348864::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece348864f::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece460896::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece460896f::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6688128::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6688128f::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6960119::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6960119f::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece8192128::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece8192128f::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope512cca::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope512cpa::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope1024cca::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope1024cpa::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps2048509::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps2048677::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps4096821::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhrss701::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_papabear::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_papabearephem::new_alice),
        box_alice!(crate::post_quantum_structs::PostQuantumAlgorithmData_saber::new_alice)*/
    ];

    pub(crate) static BOB_FP: [fn(&[u8]) -> Result<Box<dyn PostQuantumType>, Error>; 1] = [
        /*
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_babybear::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_babybearephem::new_bob),*/
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_firesaber::new_bob),
        /*
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem640aes::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem640shake::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem976aes::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem976shake::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem1344aes::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_frodokem1344shake::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber512::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber768::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber1024::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber51290s::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber76890s::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_kyber102490s::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt12::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt32::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ledakemlt52::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_lightsaber::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mamabear::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mamabearephem::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece348864::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece348864f::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece460896::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece460896f::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6688128::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6688128f::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6960119::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece6960119f::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece8192128::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_mceliece8192128f::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope512cca::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope512cpa::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope1024cca::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_newhope1024cpa::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps2048509::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps2048677::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhps4096821::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_ntruhrss701::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_papabear::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_papabearephem::new_bob),
        box_bob!(crate::post_quantum_structs::PostQuantumAlgorithmData_saber::new_bob)*/
    ];
}

/// A set of auto generated structs corresponding to one of many possible encryption schemes
pub(crate) mod post_quantum_structs {
    use pqcrypto::traits::kem::*;
    use super::PostQuantumType;
    use pqcrypto::traits::Error;

fn get_generic_error(text: &'static str) -> Error {
    Error::BadLength {
        name: text,
        actual: 0,
        expected: 0,
    }
}
    /*
create_struct!(PostQuantumAlgorithmData_babybear, babybear);
create_struct!(PostQuantumAlgorithmData_babybearephem, babybearephem);
*/
create_struct!(PostQuantumAlgorithmData_firesaber, firesaber);
/*
create_struct!(PostQuantumAlgorithmData_frodokem640aes, frodokem640aes);
create_struct!(PostQuantumAlgorithmData_frodokem640shake, frodokem640shake);
create_struct!(PostQuantumAlgorithmData_frodokem976aes, frodokem976aes);
create_struct!(PostQuantumAlgorithmData_frodokem976shake, frodokem976shake);
create_struct!(PostQuantumAlgorithmData_frodokem1344aes, frodokem1344aes);
create_struct!(PostQuantumAlgorithmData_frodokem1344shake, frodokem1344shake);

create_struct!(PostQuantumAlgorithmData_kyber512, kyber512);
create_struct!(PostQuantumAlgorithmData_kyber768, kyber768);
create_struct!(PostQuantumAlgorithmData_kyber1024, kyber1024);
create_struct!(PostQuantumAlgorithmData_kyber51290s, kyber51290s);
create_struct!(PostQuantumAlgorithmData_kyber76890s, kyber76890s);
create_struct!(PostQuantumAlgorithmData_kyber102490s, kyber102490s);

create_struct!(PostQuantumAlgorithmData_ledakemlt12, ledakemlt12);
create_struct!(PostQuantumAlgorithmData_ledakemlt32, ledakemlt32);
create_struct!(PostQuantumAlgorithmData_ledakemlt52, ledakemlt52);

create_struct!(PostQuantumAlgorithmData_lightsaber, lightsaber);

create_struct!(PostQuantumAlgorithmData_mamabear, mamabear);
create_struct!(PostQuantumAlgorithmData_mamabearephem, mamabearephem);

create_struct!(PostQuantumAlgorithmData_mceliece348864, mceliece348864);
create_struct!(PostQuantumAlgorithmData_mceliece348864f, mceliece348864f);
create_struct!(PostQuantumAlgorithmData_mceliece460896, mceliece460896);
create_struct!(PostQuantumAlgorithmData_mceliece460896f, mceliece460896f);
create_struct!(PostQuantumAlgorithmData_mceliece6688128, mceliece6688128);
create_struct!(PostQuantumAlgorithmData_mceliece6688128f, mceliece6688128f);
create_struct!(PostQuantumAlgorithmData_mceliece6960119, mceliece6960119);
create_struct!(PostQuantumAlgorithmData_mceliece6960119f, mceliece6960119f);
create_struct!(PostQuantumAlgorithmData_mceliece8192128, mceliece8192128);
create_struct!(PostQuantumAlgorithmData_mceliece8192128f, mceliece8192128f);

create_struct!(PostQuantumAlgorithmData_newhope512cca, newhope512cca);
create_struct!(PostQuantumAlgorithmData_newhope512cpa, newhope512cpa);
create_struct!(PostQuantumAlgorithmData_newhope1024cca, newhope1024cca);
create_struct!(PostQuantumAlgorithmData_newhope1024cpa, newhope1024cpa);

create_struct!(PostQuantumAlgorithmData_ntruhps2048509, ntruhps2048509);
create_struct!(PostQuantumAlgorithmData_ntruhps2048677, ntruhps2048677);
create_struct!(PostQuantumAlgorithmData_ntruhps4096821, ntruhps4096821);

create_struct!(PostQuantumAlgorithmData_ntruhrss701, ntruhrss701);

create_struct!(PostQuantumAlgorithmData_papabear, papabear);
create_struct!(PostQuantumAlgorithmData_papabearephem, papabearephem);
create_struct!(PostQuantumAlgorithmData_saber, saber);*/
}