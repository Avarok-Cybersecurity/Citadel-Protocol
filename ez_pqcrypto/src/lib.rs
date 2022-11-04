#![allow(non_camel_case_types)]
#![forbid(unsafe_code)]

use crate::algorithm_dictionary::{
    CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm,
};
use crate::bytes_in_place::{EzBuffer, InPlaceBuffer, InPlaceByteSliceMut};
use crate::constructor_opts::{ConstructorOpts, RecursiveChain};
use crate::encryption::AeadModule;
use crate::export::keys_to_aead_store;
use crate::ez_error::EzError;
use crate::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use generic_array::GenericArray;
use oqs::Error;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref INIT: () = oqs::init();
}

pub use crate::replay_attack_container::AntiReplayAttackContainer;

pub mod prelude {
    pub use crate::{algorithm_dictionary, PQNode, PostQuantumContainer, PostQuantumMetaKem};
    pub use oqs::Error;
}

pub const LARGEST_NONCE_LEN: usize = 24;

pub const CHA_CHA_NONCE_LENGTH_BYTES: usize = 24;

pub const AES_GCM_NONCE_LENGTH_BYTES: usize = 12;

pub const KYBER_NONCE_LENGTH_BYTES: usize = 32;

pub mod bytes_in_place;

/// For handling serialization/deserialization
pub mod export;

/// For organizing error types
pub mod ez_error;

/// For protecting against replay attacks
pub mod replay_attack_container;

/// For abstracting-away the use of aead
pub mod encryption;

pub mod constructor_opts;

pub mod wire;

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

/// Returns the approximate size of each PQC. This is approximately true for the core NIST round-3 algorithms, but not necessarily true for the SIKE algos
pub const fn get_approx_bytes_per_container() -> usize {
    2000
}

/// The number of bytes in a firesaber pk
//pub const FIRESABER_PK_SIZE: usize = pqcrypto_saber::firesaber_public_key_bytes();

/// Contains the public keys for Alice and Bob
#[derive(Serialize, Deserialize)]
pub struct PostQuantumContainer {
    pub params: CryptoParameters,
    pub(crate) data: PostQuantumMetaKem,
    // the first pqc won't have a chain
    pub(crate) chain: Option<RecursiveChain>,
    pub(crate) anti_replay_attack: AntiReplayAttackContainer,
    pub(crate) key_store: Option<KeyStore>,
    pub(crate) node: PQNode,
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
    /// local sk to get the shared secret, ss
    Bob,
}

pub(crate) struct KeyStore {
    alice_module: Option<Box<dyn AeadModule>>,
    bob_module: Option<Box<dyn AeadModule>>,
    alice_key: GenericArray<u8, generic_array::typenum::U32>,
    bob_key: GenericArray<u8, generic_array::typenum::U32>,
    pk_local: Arc<oqs::kem::PublicKey>,
    pk_remote: Arc<oqs::kem::PublicKey>,
    sk_local: Arc<oqs::kem::SecretKey>,
    pk_sig_remote: Arc<oqs::sig::PublicKey>,
    sk_sig_local: Arc<oqs::sig::SecretKey>,
    pk_sig_local: Arc<oqs::sig::PublicKey>,
    pq_node: PQNode,
    params: CryptoParameters,
}

impl PostQuantumContainer {
    /// Creates a new [PostQuantumContainer] for Alice. This will panic if the algorithm is
    /// invalid
    ///
    /// `algorithm`: If this is None, a random algorithm will be used
    pub fn new_alice(opts: ConstructorOpts) -> Result<Self, Error> {
        let params = opts.cryptography.unwrap_or_default();
        let previous_symmetric_key = opts.chain;
        let data = Self::create_new_alice(params.kem_algorithm, params.sig_algorithm)?;
        let aes_gcm_key = None;
        log::trace!(target: "lusna", "Success creating new ALICE container");

        Ok(Self {
            params,
            data,
            chain: previous_symmetric_key,
            key_store: aes_gcm_key,
            anti_replay_attack: AntiReplayAttackContainer::default(),
            node: PQNode::Alice,
        })
    }

    /// Creates a new [PostQuantumContainer] for Bob. This will panic if the algorithm is
    /// invalid
    pub fn new_bob(
        opts: ConstructorOpts,
        tx_params: AliceToBobTransferParameters,
    ) -> Result<Self, Error> {
        let pq_node = PQNode::Bob;
        let params = opts.cryptography.unwrap_or_default();
        let chain = opts.chain;

        let data = Self::create_new_bob(tx_params)?;
        // We must call the below to refresh the internal state to allow get_shared_secret to function
        let ss = data.get_shared_secret().unwrap().clone();
        let pk_local = data.get_public_key().clone();
        let pk_remote = data.get_public_key_remote().unwrap().clone();
        let sk_local = data.get_secret_key()?.clone();
        let pk_sig_remote = data.remote_sig_public_key.as_ref().unwrap().clone();
        let sk_sig_local = data.sig_private_key.clone();
        let pk_sig_local = data.sig_public_key.clone();

        let (chain, keys) = Self::generate_recursive_keystore(
            pq_node,
            params,
            pk_sig_remote,
            sk_sig_local,
            pk_sig_local,
            ss,
            chain.as_ref(),
            pk_local,
            pk_remote,
            sk_local,
        )?;

        let keys = Some(keys);

        log::trace!(target: "lusna", "Success creating new BOB container");
        Ok(Self {
            chain: Some(chain),
            params,
            key_store: keys,
            data,
            anti_replay_attack: AntiReplayAttackContainer::default(),
            node: PQNode::Bob,
        })
    }

    fn generate_recursive_keystore(
        pq_node: PQNode,
        params: CryptoParameters,
        pk_sig_remote: Arc<oqs::sig::PublicKey>,
        sk_sig_local: Arc<oqs::sig::SecretKey>,
        pk_sig_local: Arc<oqs::sig::PublicKey>,
        ss: Arc<oqs::kem::SharedSecret>,
        previous_chain: Option<&RecursiveChain>,
        pk_local: Arc<oqs::kem::PublicKey>,
        pk_remote: Arc<oqs::kem::PublicKey>,
        sk_local: Arc<oqs::kem::SecretKey>,
    ) -> Result<(RecursiveChain, KeyStore), Error> {
        let (chain, alice_key, bob_key) = if let Some(prev) = previous_chain {
            // prev = C_n
            // If a previous key, S_n, existed, we calculate S_(n+1)' = KDF(C_n || S_n))
            let mut hasher_temp = sha3::Sha3_512::new();
            let mut hasher_alice = sha3::Sha3_256::new();
            let mut hasher_bob = sha3::Sha3_256::new();
            hasher_temp.update(
                &prev
                    .chain
                    .iter()
                    .chain(ss.deref().as_ref().iter())
                    .cloned()
                    .collect::<Vec<u8>>()[..],
            );

            let temp_key = hasher_temp.finalize();

            let (temp_alice_key, temp_bob_key) = temp_key.as_slice().split_at(32);
            debug_assert_eq!(temp_alice_key.len(), 32);
            debug_assert_eq!(temp_bob_key.len(), 32);

            hasher_alice.update(
                &prev
                    .alice
                    .iter()
                    .zip(temp_alice_key.iter())
                    .map(|(r1, r2)| *r1 ^ *r2)
                    .collect::<Vec<u8>>()[..],
            );
            hasher_bob.update(
                &prev
                    .bob
                    .iter()
                    .zip(temp_bob_key.iter())
                    .map(|(r1, r2)| *r1 ^ *r2)
                    .collect::<Vec<u8>>()[..],
            );

            let alice_key = hasher_alice.finalize();
            let bob_key = hasher_bob.finalize();

            // create chain: C_n = KDF(A xor B)
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(
                &alice_key
                    .into_iter()
                    .zip(bob_key.into_iter())
                    .map(|(r1, r2)| r1 ^ r2)
                    .collect::<Vec<u8>>()[..],
            );
            let chain = hasher.finalize();

            let chain = RecursiveChain::new(chain.as_slice(), alice_key, bob_key, false)
                .ok_or(Error::InvalidLength)?;

            //log::trace!(target: "lusna", "Alice, Bob keys: {:?} || {:?}", alice_key, bob_key);

            let alice_key =
                aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                    alice_key.as_slice().iter().cloned(),
                )
                .ok_or(Error::InvalidLength)?;

            let bob_key = aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.as_slice().iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

            (chain, alice_key, bob_key)
        } else {
            // The first key, S_0', = KDF(S_0)
            let mut hasher_temp = sha3::Sha3_512::new();
            hasher_temp.update(ss.deref());
            let temp_key = hasher_temp.finalize();
            let (alice_key, bob_key) = temp_key.as_slice().split_at(32);

            let mut hasher = sha3::Sha3_256::new();
            hasher.update(
                &alice_key
                    .iter()
                    .zip(bob_key.iter())
                    .map(|(r1, r2)| *r1 ^ *r2)
                    .collect::<Vec<u8>>()[..],
            );
            let chain = hasher.finalize();
            let chain = RecursiveChain::new(chain.as_slice(), alice_key, bob_key, true)
                .ok_or(Error::InvalidLength)?;

            let alice_key =
                aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                    alice_key.iter().cloned(),
                )
                .ok_or(Error::InvalidLength)?;

            let bob_key = aes_gcm_siv::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

            (chain, alice_key, bob_key)
        };

        let (alice_symmetric_key, bob_symmetric_key) = keys_to_aead_store(
            &alice_key,
            &bob_key,
            pk_local.clone(),
            pk_remote.clone(),
            sk_local.clone(),
            params,
            pk_sig_remote.clone(),
            sk_sig_local.clone(),
            pk_sig_local.clone(),
            pq_node,
        );

        Ok((
            chain,
            KeyStore {
                alice_module: alice_symmetric_key,
                bob_module: bob_symmetric_key,
                alice_key,
                bob_key,
                pk_local,
                pk_remote,
                sk_local,
                pk_sig_remote,
                sk_sig_local,
                pk_sig_local,
                pq_node,
                params,
            },
        ))
    }

    fn get_encryption_key(&self) -> Option<&Box<dyn AeadModule>> {
        match self.node {
            PQNode::Alice => Some(self.key_store.as_ref()?.alice_module.as_ref()?),
            PQNode::Bob => Some(self.key_store.as_ref()?.bob_module.as_ref()?),
        }
    }

    fn get_decryption_key(&self) -> Option<&Box<dyn AeadModule>> {
        if let EncryptionAlgorithm::Kyber = self.params.encryption_algorithm {
            // use multi-modal asymmetric + symmetric ratcheted encryption
            // alices key is in alice, bob's key is in bob. Thus, use encryption key
            self.get_encryption_key()
        } else {
            // use symmetric encryption only (NOT post quantum, only quantum-resistant, but faster)
            match self.node {
                PQNode::Alice => Some(self.key_store.as_ref()?.bob_module.as_ref()?),
                PQNode::Bob => Some(self.key_store.as_ref()?.alice_module.as_ref()?),
            }
        }
    }

    /// Resets the counters to zero, as well as reset any additional stateful resources
    pub fn reset_counters(&self) {
        self.anti_replay_attack.reset();
    }

    /// This should always be called after deserialization
    fn load_symmetric_keys(&mut self) -> Result<(), Error> {
        let pq_node = self.node;
        let params = self.params;
        let pk_sig_remote = self.data.remote_sig_public_key.clone().unwrap();
        let sk_sig_local = self.data.sig_private_key.clone();
        let pk_sig_local = self.data.sig_public_key.clone();
        let ss = self.get_shared_secret()?.clone();
        let pk_local = self.get_public_key().clone();
        let pk_remote = self.get_public_key_remote().clone();
        let sk_local = self.get_secret_key()?.clone();
        let prev_symmetric_key = self.chain.as_ref();

        let (chain, key) = Self::generate_recursive_keystore(
            pq_node,
            params,
            pk_sig_remote,
            sk_sig_local,
            pk_sig_local,
            ss,
            prev_symmetric_key,
            pk_local,
            pk_remote,
            sk_local,
        )?;

        self.key_store = Some(key);
        self.chain = Some(chain);

        Ok(())
    }

    /// Internally creates shared key after bob sends a response back to Alice
    pub fn alice_on_receive_ciphertext(
        &mut self,
        params: BobToAliceTransferParameters,
    ) -> Result<(), Error> {
        self.data.alice_on_receive_ciphertext(params)?;
        let _ss = self.data.get_shared_secret()?; // call once to load internally
        self.load_symmetric_keys()
    }

    /// Returns true if either Tx/Rx Anti-replay attack counters have been engaged (useful for determining
    /// if resetting the state is necessary)
    pub fn has_verified_packets(&self) -> bool {
        self.anti_replay_attack.has_tracked_packets()
    }

    /// Returns the previous symmetric chain key. If this is the first in the series, then returns the shared
    pub fn get_chain(&self) -> Result<&RecursiveChain, Error> {
        if let Some(ref chain) = self.chain {
            Ok(chain)
        } else {
            // chain won't be loaded for alice until she builds hers
            Err(Error::InvalidLength)
        }
    }

    pub fn get_public_key_remote(&self) -> &Arc<oqs::kem::PublicKey> {
        self.data.get_public_key_remote().unwrap()
    }

    /// Gets the public key
    pub fn get_public_key(&self) -> &Arc<oqs::kem::PublicKey> {
        self.data.get_public_key()
    }
    /// Gets the secret key (If node is Alice type)
    pub fn get_secret_key(&self) -> Result<&Arc<oqs::kem::SecretKey>, Error> {
        self.data.get_secret_key()
    }
    /// Gets the ciphertext
    pub fn get_ciphertext(&self) -> Result<&Arc<oqs::kem::Ciphertext>, Error> {
        self.data.get_ciphertext()
    }
    /// Gets the shared secret
    pub fn get_shared_secret(&self) -> Result<&Arc<oqs::kem::SharedSecret>, Error> {
        self.data.get_shared_secret()
    }

    /// Serializes the entire package to a vector
    pub fn serialize_to_vector(&self) -> Result<Vec<u8>, EzError> {
        bincode2::serialize(self).map_err(|_err| EzError::Generic("Deserialization failure"))
    }

    /// Attempts to deserialize the input bytes presumed to be of type [PostQuantumExport],
    /// into a [PostQuantumContainer]
    pub fn deserialize_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, EzError> {
        bincode2::deserialize::<PostQuantumContainer>(bytes.as_ref())
            .map_err(|_err| EzError::Generic("Deserialization failure"))
    }

    /// Returns either Alice or Bob
    pub fn get_node_type(&self) -> PQNode {
        self.node
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        input: T,
        nonce: R,
    ) -> Result<Vec<u8>, EzError> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.get_encryption_key() {
            aes_gcm_key.encrypt(nonce, input)
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    pub fn protect_packet_in_place<T: EzBuffer, R: AsRef<[u8]>>(
        &self,
        header_len: usize,
        full_packet: &mut T,
        nonce: R,
    ) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let mut payload = full_packet.split_off(header_len);
        let header = full_packet;

        // next, push the ARA-generated PID
        payload.put_u64(self.anti_replay_attack.get_next_pid());
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(&mut payload, 0..payload_len)
            .ok_or(EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.get_encryption_key() {
            aes_gcm_key
                .encrypt_in_place(nonce, header.subset(0..header_len), &mut in_place_payload)
                .map_err(|_| EzError::EncryptionFailure)?;
            header.unsplit(payload);
            Ok(())
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Validates the AAD (header) and produces the plaintext given the input of ciphertext
    pub fn validate_packet_in_place<T: EzBuffer, H: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        header: H,
        payload: &mut T,
        nonce: R,
    ) -> Result<(), EzError> {
        let nonce = nonce.as_ref();
        let header = header.as_ref();
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(payload, 0..payload_len)
            .ok_or(EzError::Generic("Bad window range"))?;
        if let Some(aes_gcm_key) = self.get_decryption_key() {
            aes_gcm_key
                .decrypt_in_place(nonce, header, &mut in_place_payload)
                .map_err(|_| EzError::DecryptionFailure)
                .and_then(|_| {
                    // get the last 8 bytes of the payload
                    let end_idx = payload.len();
                    let start_idx = end_idx.saturating_sub(8);
                    if end_idx - start_idx == 8 {
                        let mut array: [u8; 8] = Default::default();
                        array.copy_from_slice(payload.subset(start_idx..end_idx));
                        if self
                            .anti_replay_attack
                            .on_pid_received(u64::from_be_bytes(array))
                        {
                            // remove the PID from the payload
                            payload.truncate(start_idx);
                            Ok(())
                        } else {
                            Err(EzError::Generic("Anti-replay-attack: invalid"))
                        }
                    } else {
                        Err(EzError::Generic(
                            "Anti-replay-attack: Invalid inscription length",
                        ))
                    }
                })
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        input: T,
        nonce: R,
    ) -> Result<Vec<u8>, EzError>
    where
        Self: Sized,
    {
        let input = input.as_ref();
        let nonce = nonce.as_ref();
        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.get_decryption_key() {
            aes_gcm_key.decrypt(nonce, input)
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn decrypt_in_place<T: AsMut<[u8]>, R: AsRef<[u8]>>(
        &self,
        mut input: T,
        nonce: R,
    ) -> Result<usize, EzError>
    where
        Self: Sized,
    {
        let input = input.as_mut();
        let mut buf = InPlaceByteSliceMut::from(input);
        let nonce = nonce.as_ref();
        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(aes_gcm_key) = self.get_decryption_key() {
            match aes_gcm_key.decrypt_in_place(nonce, &[], &mut buf) {
                Err(_) => Err(EzError::DecryptionFailure),

                Ok(_) => Ok(buf.get_finished_len()),
            }
        } else {
            Err(EzError::SharedSecretNotLoaded)
        }
    }

    /// This, for now, only gets FIRESABER
    fn create_new_alice(
        kem_algorithm: KemAlgorithm,
        sig_algorithm: SigAlgorithm,
    ) -> Result<PostQuantumMetaKem, Error> {
        PostQuantumMetaKem::new_alice(kem_algorithm.into(), sig_algorithm.into())
    }

    fn create_new_bob(
        alice_to_bob_transfer_params: AliceToBobTransferParameters,
    ) -> Result<PostQuantumMetaKem, Error> {
        PostQuantumMetaKem::new_bob(alice_to_bob_transfer_params)
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
    use crate::{
        EzError, AES_GCM_NONCE_LENGTH_BYTES, CHA_CHA_NONCE_LENGTH_BYTES, KYBER_NONCE_LENGTH_BYTES,
    };
    use enum_primitive::*;
    use serde::{Deserialize, Serialize};
    use std::convert::{TryFrom, TryInto};
    use std::ops::Add;
    use strum::EnumCount;
    use strum::ParseError;

    pub const KEM_ALGORITHM_COUNT: u8 = KemAlgorithm::COUNT as u8;

    #[derive(Default, Serialize, Deserialize, Copy, Clone, Debug)]
    pub struct CryptoParameters {
        pub encryption_algorithm: EncryptionAlgorithm,
        pub kem_algorithm: KemAlgorithm,
        pub sig_algorithm: SigAlgorithm,
    }

    impl Into<u8> for CryptoParameters {
        fn into(self) -> u8 {
            self.encryption_algorithm as u8 + self.kem_algorithm as u8
        }
    }

    impl TryFrom<u8> for CryptoParameters {
        type Error = crate::ez_error::EzError;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                x if x >= EncryptionAlgorithm::AES_GCM_256_SIV.into()
                    && x < KEM_ALGORITHM_COUNT =>
                {
                    let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
                    let kem_algorithm = (x % KEM_ALGORITHM_COUNT)
                        .try_into()
                        .map_err(|_| EzError::Generic("Bad CryptoParameter for kem alg"))?;
                    Ok(Self {
                        encryption_algorithm,
                        kem_algorithm,
                        sig_algorithm: Default::default(),
                    })
                }

                x if x >= u8::from(EncryptionAlgorithm::Xchacha20Poly_1305)
                    && x < (u8::from(EncryptionAlgorithm::Xchacha20Poly_1305)
                        + KEM_ALGORITHM_COUNT) =>
                {
                    let encryption_algorithm = EncryptionAlgorithm::Xchacha20Poly_1305;
                    let kem_algorithm = (x % KEM_ALGORITHM_COUNT)
                        .try_into()
                        .map_err(|_| EzError::Generic("Bad CryptoPArameter for kem alg"))?;
                    Ok(Self {
                        encryption_algorithm,
                        kem_algorithm,
                        sig_algorithm: Default::default(),
                    })
                }

                x if x >= u8::from(EncryptionAlgorithm::Kyber)
                    && x < (u8::from(EncryptionAlgorithm::Kyber) + KEM_ALGORITHM_COUNT) =>
                {
                    let encryption_algorithm = EncryptionAlgorithm::Xchacha20Poly_1305;
                    let kem_algorithm = (x % KEM_ALGORITHM_COUNT)
                        .try_into()
                        .map_err(|_| EzError::Generic("Bad CryptoParameter for kem alg"))?;

                    if !matches!(
                        kem_algorithm,
                        KemAlgorithm::Kyber512 | KemAlgorithm::Kyber768 | KemAlgorithm::Kyber1024,
                    ) {
                        return Err(EzError::Generic(
                            "Kyber encryption is only compatible with Kyber keys",
                        ));
                    }

                    Ok(Self {
                        encryption_algorithm,
                        kem_algorithm,
                        sig_algorithm: Default::default(),
                    })
                }

                _ => Err(EzError::Generic(
                    "Cryptoparameters not found for supplied combination",
                )),
            }
        }
    }

    impl Add<EncryptionAlgorithm> for KemAlgorithm {
        type Output = CryptoParameters;

        fn add(self, rhs: EncryptionAlgorithm) -> Self::Output {
            CryptoParameters {
                kem_algorithm: self,
                encryption_algorithm: rhs,
                sig_algorithm: Default::default(),
            }
        }
    }

    impl Add<KemAlgorithm> for EncryptionAlgorithm {
        type Output = CryptoParameters;

        fn add(self, rhs: KemAlgorithm) -> Self::Output {
            CryptoParameters {
                kem_algorithm: rhs,
                encryption_algorithm: self,
                sig_algorithm: Default::default(),
            }
        }
    }

    enum_from_primitive! {
        #[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, strum::EnumIter)]
        pub enum EncryptionAlgorithm {
            AES_GCM_256_SIV = 0,
            Xchacha20Poly_1305 = KEM_ALGORITHM_COUNT as isize,
            #[default]
            Kyber = (2*KEM_ALGORITHM_COUNT) as isize
        }
    }

    impl EncryptionAlgorithm {
        pub fn nonce_len(&self) -> usize {
            match self {
                Self::AES_GCM_256_SIV => AES_GCM_NONCE_LENGTH_BYTES,
                Self::Xchacha20Poly_1305 => CHA_CHA_NONCE_LENGTH_BYTES,
                Self::Kyber => KYBER_NONCE_LENGTH_BYTES,
            }
        }

        pub fn list() -> Vec<EncryptionAlgorithm> {
            use strum::IntoEnumIterator;
            EncryptionAlgorithm::iter().collect()
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

    enum_from_primitive! {
        #[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, strum::EnumString, strum::EnumIter, strum::EnumCount)]
        pub enum KemAlgorithm {
            #[strum(ascii_case_insensitive)]
            Lightsaber = 0,
            #[strum(ascii_case_insensitive)]
            Saber = 1,
            #[strum(ascii_case_insensitive)]
            Firesaber = 2,
            #[strum(ascii_case_insensitive)]
            Kyber512 = 3,
            #[strum(ascii_case_insensitive)]
            Kyber768 = 4,
            #[strum(ascii_case_insensitive)]
            #[default]
            Kyber1024 = 5,
            #[strum(ascii_case_insensitive)]
            NtruHps2048509 = 6,
            #[strum(ascii_case_insensitive)]
            NtruHps2048677 = 7,
            #[strum(ascii_case_insensitive)]
            NtruHps4096821 = 8,
            #[strum(ascii_case_insensitive)]
            NtruHrss701 = 9,
        }
    }

    #[derive(Default, Serialize, Deserialize, Copy, Clone, Debug)]
    pub enum SigAlgorithm {
        #[default]
        Falcon1024,
    }

    impl From<SigAlgorithm> for oqs::sig::Algorithm {
        fn from(this: SigAlgorithm) -> Self {
            match this {
                SigAlgorithm::Falcon1024 => oqs::sig::Algorithm::Falcon1024,
            }
        }
    }

    impl KemAlgorithm {
        pub fn list() -> Vec<KemAlgorithm> {
            use strum::IntoEnumIterator;
            KemAlgorithm::iter().collect()
        }

        pub fn try_from_str<R: AsRef<str>>(t: R) -> Result<Self, ParseError> {
            use std::str::FromStr;
            KemAlgorithm::from_str(t.as_ref())
        }

        pub fn names() -> Vec<String> {
            use strum::IntoEnumIterator;
            KemAlgorithm::iter()
                .map(|r| format!("{:?}", r).to_lowercase())
                .collect()
        }
    }

    impl TryFrom<u8> for KemAlgorithm {
        type Error = ();

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            KemAlgorithm::from_u8(value).ok_or(())
        }
    }

    impl From<KemAlgorithm> for oqs::kem::Algorithm {
        fn from(val: KemAlgorithm) -> Self {
            match val {
                KemAlgorithm::Lightsaber => oqs::kem::Algorithm::Lightsaber,
                KemAlgorithm::Saber => oqs::kem::Algorithm::Saber,
                KemAlgorithm::Firesaber => oqs::kem::Algorithm::Firesaber,
                KemAlgorithm::Kyber512 => oqs::kem::Algorithm::Kyber512,
                KemAlgorithm::Kyber768 => oqs::kem::Algorithm::Kyber768,
                KemAlgorithm::Kyber1024 => oqs::kem::Algorithm::Kyber1024,
                KemAlgorithm::NtruHps2048509 => oqs::kem::Algorithm::NtruHps2048509,
                KemAlgorithm::NtruHps2048677 => oqs::kem::Algorithm::NtruHps2048677,
                KemAlgorithm::NtruHps4096821 => oqs::kem::Algorithm::NtruHps4096821,
                KemAlgorithm::NtruHrss701 => oqs::kem::Algorithm::NtruHrss701,
            }
        }
    }

    impl Into<u8> for KemAlgorithm {
        fn into(self) -> u8 {
            self as u8
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PostQuantumMetaKem {
    sig_public_key: Arc<oqs::sig::PublicKey>,
    sig_private_key: Arc<oqs::sig::SecretKey>,
    remote_sig_public_key: Option<Arc<oqs::sig::PublicKey>>,
    /// The public key of remote
    remote_public_key: Option<Arc<oqs::kem::PublicKey>>,
    /// The public key. Both Alice and Bob get this
    public_key: Arc<oqs::kem::PublicKey>,
    /// Only Alice gets this one
    secret_key: Option<Arc<oqs::kem::SecretKey>>,
    /// Both Bob and Alice get this one
    ciphertext: Option<Arc<oqs::kem::Ciphertext>>,
    /// Both Alice and Bob get this (at the end)
    shared_secret: Option<Arc<oqs::kem::SharedSecret>>,
    /// the kem algorithm
    kem_alg: oqs::kem::Algorithm,
    /// the sig alg
    sig_alg: oqs::sig::Algorithm,
}

impl PostQuantumMetaKem {
    fn new_alice(
        kem_alg: oqs::kem::Algorithm,
        sig_alg: oqs::sig::Algorithm,
    ) -> Result<Self, Error> {
        log::trace!(target: "lusna", "About to generate keypair for {:?}", kem_alg);
        let kem_alg = oqs::kem::Kem::new(kem_alg)?;
        let sig_alg = oqs::sig::Sig::new(sig_alg)?;

        let (sig_public_key, sig_private_key) = sig_alg.keypair()?;
        let (public_key, secret_key) = kem_alg.keypair()?;
        let ciphertext = None;
        let shared_secret = None;
        let remote_sig_public_key = None;
        let secret_key = Some(Arc::new(secret_key));
        Ok(Self {
            sig_public_key: Arc::new(sig_public_key),
            sig_private_key: Arc::new(sig_private_key),
            remote_public_key: None,
            remote_sig_public_key,
            public_key: Arc::new(public_key),
            secret_key,
            ciphertext,
            shared_secret,
            kem_alg: kem_alg.algorithm(),
            sig_alg: sig_alg.algorithm(),
        })
    }

    fn new_bob(params: AliceToBobTransferParameters) -> Result<Self, Error> {
        let kem_alg = oqs::kem::Kem::new(params.kem_scheme)?;
        let sig_alg = oqs::sig::Sig::new(params.sig_scheme)?;
        let (kem_pk_bob, kem_sk_bob) = kem_alg.keypair()?;
        let (sig_pk_bob, sig_sk_bob) = sig_alg.keypair()?;

        let public_key_alice = params.alice_pk;

        sig_alg.verify(
            params.alice_pk.deref().as_ref(),
            &params.alice_sig,
            params.alice_pk_sig.as_ref(),
        )?;

        let (ciphertext, shared_secret) = kem_alg.encapsulate(&*public_key_alice)?;

        let public_key = Arc::new(kem_pk_bob);
        let secret_key = Some(Arc::new(kem_sk_bob));
        let shared_secret = Some(Arc::new(shared_secret));
        let ciphertext = Some(Arc::new(ciphertext));
        let remote_sig_public_key = Some(params.alice_pk_sig);

        Ok(Self {
            sig_public_key: Arc::new(sig_pk_bob),
            sig_private_key: Arc::new(sig_sk_bob),
            remote_public_key: Some(public_key_alice),
            remote_sig_public_key,
            public_key,
            secret_key,
            ciphertext,
            shared_secret,
            kem_alg: kem_alg.algorithm(),
            sig_alg: sig_alg.algorithm(),
        })
    }

    fn alice_on_receive_ciphertext(
        &mut self,
        params: BobToAliceTransferParameters,
    ) -> Result<(), Error> {
        // These functions should only be called once upon response back from Bob
        debug_assert!(self.shared_secret.is_none());
        debug_assert!(self.ciphertext.is_none());
        debug_assert!(self.secret_key.is_some());

        let kem_alg = oqs::kem::Kem::new(self.kem_alg)?;
        let sig_alg = oqs::sig::Sig::new(self.sig_alg)?;

        if let Some(secret_key) = self.secret_key.as_ref() {
            sig_alg.verify(
                params.bob_ciphertext.deref().as_ref(),
                &params.bob_signature,
                params.bob_pk_sig.as_ref(),
            )?;

            let shared_secret = kem_alg.decapsulate(&**secret_key, &*params.bob_ciphertext)?;
            self.ciphertext = Some(params.bob_ciphertext);
            self.shared_secret = Some(Arc::new(shared_secret));
            self.remote_public_key = Some(params.bob_pk);
            self.remote_sig_public_key = Some(params.bob_pk_sig);
            Ok(())
        } else {
            Err(oqs::Error::Error)
        }
    }

    fn generate_alice_to_bob_transfer(&self) -> Result<AliceToBobTransferParameters, Error> {
        let sig_alg = oqs::sig::Sig::new(self.sig_alg)?;
        let alice_pk = self.public_key.clone();
        let alice_pk_sig = self.sig_public_key.clone();
        let alice_sig = sig_alg.sign(alice_pk.deref().as_ref(), self.sig_private_key.as_ref())?;
        let sig_scheme = self.sig_alg;
        let kem_scheme = self.kem_alg;

        Ok(AliceToBobTransferParameters {
            alice_pk,
            alice_pk_sig,
            alice_sig,
            sig_scheme,
            kem_scheme,
        })
    }

    fn generate_bob_to_alice_transfer(&self) -> Result<BobToAliceTransferParameters, Error> {
        let sig_alg = oqs::sig::Sig::new(self.sig_alg)?;
        let bob_ciphertext = self.ciphertext.clone().ok_or(Error::Error)?;
        let bob_signature = sig_alg.sign(
            bob_ciphertext.deref().as_ref(),
            self.sig_private_key.as_ref(),
        )?;
        let bob_pk_sig = self.sig_public_key.clone();
        let bob_pk = self.public_key.clone();

        Ok(BobToAliceTransferParameters {
            bob_ciphertext,
            bob_signature,
            bob_pk_sig,
            bob_pk,
        })
    }

    fn get_public_key_remote(&self) -> Option<&Arc<oqs::kem::PublicKey>> {
        self.remote_public_key.as_ref()
    }

    fn get_public_key(&self) -> &Arc<oqs::kem::PublicKey> {
        &self.public_key
    }

    fn get_secret_key(&self) -> Result<&Arc<oqs::kem::SecretKey>, Error> {
        if let Some(secret_key) = self.secret_key.as_ref() {
            Ok(secret_key)
        } else {
            Err(get_generic_error("Unable to get secret key"))
        }
    }

    fn get_ciphertext(&self) -> Result<&Arc<oqs::kem::Ciphertext>, Error> {
        if let Some(ciphertext) = self.ciphertext.as_ref() {
            Ok(ciphertext)
        } else {
            Err(get_generic_error("Unable to get ciphertext"))
        }
    }

    fn get_shared_secret(&self) -> Result<&Arc<oqs::kem::SharedSecret>, Error> {
        if let Some(shared_secret) = self.shared_secret.as_ref() {
            Ok(shared_secret)
        } else {
            Err(get_generic_error("Unable to get secret key"))
        }
    }
}

fn get_generic_error(_text: &'static str) -> Error {
    Error::Error
}

impl Debug for PostQuantumContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PQC {:?} | {:?}", self.node, self.params)
    }
}
