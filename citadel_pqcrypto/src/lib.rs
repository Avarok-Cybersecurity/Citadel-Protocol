#![allow(non_camel_case_types, deprecated)]
#![forbid(unsafe_code)]
//! Post-quantum cryptographic library for secure communication.
//!
//! This crate provides a comprehensive implementation of post-quantum cryptographic
//! primitives and protocols, designed to be resistant to attacks from both classical
//! and quantum computers. It supports various encryption algorithms, key exchange
//! mechanisms, and signature schemes.
//!
//! # Features
//! - Post-quantum key exchange using NIST Round 3 algorithms
//! - Hybrid classical/post-quantum encryption
//! - Authenticated encryption with associated data (AEAD)
//! - Anti-replay attack protection
//! - Zero-knowledge proofs
//! - Secure serialization and deserialization
//!
//! # Security Considerations
//! - All sensitive data is wrapped in `Zeroizing` to ensure secure cleanup
//! - No unsafe code is allowed (enforced by `forbid(unsafe_code)`)
//! - Anti-replay attack protection is enabled by default
//! - Cryptographic operations are constant-time where possible
//!
//! # Examples
//! ```
//! use citadel_pqcrypto::prelude::*;
//! use citadel_pqcrypto::constructor_opts::ConstructorOpts;
//! use citadel_types::crypto::{KemAlgorithm, SigAlgorithm};
//!
//! // Define the cryptographic parameters
//! let opts = ConstructorOpts::default();
//!
//! // Create a new Alice instance
//! let mut alice = PostQuantumContainer::new_alice(
//!     opts.clone(),
//! ).unwrap();
//!
//! // Create a new Bob instance using Alice's parameters
//! let params = alice.generate_alice_to_bob_transfer().unwrap();
//! let bob = PostQuantumContainer::new_bob(opts, params, &[b"my-psk"]).unwrap();
//!
//! // Complete the key exchange
//! let bob_params = bob.generate_bob_to_alice_transfer().unwrap();
//! alice.alice_on_receive_ciphertext(bob_params, &[b"my-psk"]).unwrap();
//!
//! // Now both parties can communicate securely
//! ```

use crate::bytes_in_place::{EzBuffer, InPlaceBuffer};
use crate::constructor_opts::{ConstructorOpts, RecursiveChain};
use crate::encryption::AeadModule;
use crate::export::keys_to_aead_store;
use crate::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use citadel_io::ThreadRng;
use citadel_types::crypto::{
    CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm, AES_GCM_NONCE_LENGTH_BYTES,
    ASCON_NONCE_LENGTH_BYTES, CHA_CHA_NONCE_LENGTH_BYTES, KYBER_NONCE_LENGTH_BYTES,
};
use citadel_types::errors::Error;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::sync::Arc;
use zeroize::Zeroizing;

pub use crate::replay_attack_container::AntiReplayAttackContainer;

pub mod prelude {
    pub use crate::{EncryptionAlgorithmExt, PQNode, PostQuantumContainer, PostQuantumMeta};
}

pub mod bytes_in_place;

/// For handling serialization/deserialization
pub mod export;

/// For protecting against replay attacks
pub mod replay_attack_container;

/// For abstracting-away the use of aead
pub mod encryption;

pub mod constructor_opts;

pub mod wire;

pub const fn build_tag() -> &'static str {
    "ordered"
}

/// Returns the approximate size of each PQC. This is approximately true for the core NIST round-3 algorithms, but not necessarily true for the SIKE algos
pub const fn get_approx_bytes_per_container() -> usize {
    2000
}

pub(crate) mod functions {
    use citadel_types::crypto::SigAlgorithm;
    use citadel_types::errors::Error;
    use zeroize::Zeroizing;

    pub type SecretKeyType = Zeroizing<Vec<u8>>;
    pub type PublicKeyType = Zeroizing<Vec<u8>>;

    pub fn signature_sign(
        message: impl AsRef<[u8]>,
        secret_key: impl AsRef<[u8]>,
        sig_alg: SigAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        match sig_alg {
            SigAlgorithm::MlDsa65 => ml_dsa_sign(message, secret_key),
            SigAlgorithm::FnDsa512 => falcon_sign(message, secret_key),
            SigAlgorithm::None => {
                Err(citadel_io::error!(citadel_io::ErrorCode::SigNoneSelected))
            }
        }
    }

    pub fn signature_verify(
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
        sig_alg: SigAlgorithm,
    ) -> Result<(), Error> {
        match sig_alg {
            SigAlgorithm::MlDsa65 => ml_dsa_verify(message, signature, public_key),
            SigAlgorithm::FnDsa512 => falcon_verify(message, signature, public_key),
            SigAlgorithm::None => {
                Err(citadel_io::error!(citadel_io::ErrorCode::SigNoneSelected))
            }
        }
    }

    pub fn signature_keypair(
        sig_alg: SigAlgorithm,
    ) -> Result<(PublicKeyType, SecretKeyType), Error> {
        match sig_alg {
            SigAlgorithm::MlDsa65 => ml_dsa_keypair(),
            SigAlgorithm::FnDsa512 => falcon_keypair(),
            SigAlgorithm::None => {
                Err(citadel_io::error!(citadel_io::ErrorCode::SigNoneSelected))
            }
        }
    }

    pub fn signature_bytes(sig_alg: SigAlgorithm) -> usize {
        match sig_alg {
            SigAlgorithm::MlDsa65 => {
                std::mem::size_of::<ml_dsa::EncodedSignature<ml_dsa::MlDsa65>>()
            }
            // FN-DSA-512 signature size
            SigAlgorithm::FnDsa512 => fn_dsa::signature_size(fn_dsa::FN_DSA_LOGN_512),
            SigAlgorithm::None => 0,
        }
    }

    // --- ML-DSA-65 implementation ---

    fn ml_dsa_sign(
        message: impl AsRef<[u8]>,
        secret_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        use ml_dsa::signature::Signer;
        use ml_dsa::{EncodedSigningKey, MlDsa65, Signature, SigningKey};

        let sk_bytes = secret_key.as_ref();
        let encoded_sk = EncodedSigningKey::<MlDsa65>::try_from(sk_bytes).map_err(|_| {
            citadel_io::error!(
                citadel_io::ErrorCode::SigKeyDeserializeFailed,
                "ML-DSA",
                "secret key"
            )
        })?;
        let sk = SigningKey::decode(&encoded_sk);
        let sig: Signature<MlDsa65> = sk.sign(message.as_ref());
        Ok(sig.encode().as_slice().to_vec())
    }

    fn ml_dsa_verify(
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        use ml_dsa::signature::Verifier;
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

        let encoded_pk =
            EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_ref()).map_err(|_| {
                citadel_io::error!(
                    citadel_io::ErrorCode::SigKeyDeserializeFailed,
                    "ML-DSA",
                    "public key"
                )
            })?;
        let pk = VerifyingKey::<MlDsa65>::decode(&encoded_pk);
        let encoded_sig =
            EncodedSignature::<MlDsa65>::try_from(signature.as_ref()).map_err(|_| {
                citadel_io::error!(
                    citadel_io::ErrorCode::SigKeyDeserializeFailed,
                    "ML-DSA",
                    "signature"
                )
            })?;
        let sig = Signature::decode(&encoded_sig).ok_or(citadel_io::error!(
            citadel_io::ErrorCode::SigDecodeFailed,
            "ML-DSA",
            "signature"
        ))?;
        pk.verify(message.as_ref(), &sig).map_err(|_| {
            citadel_io::error!(citadel_io::ErrorCode::SigVerificationFailed, "ML-DSA")
        })
    }

    fn ml_dsa_keypair() -> Result<(PublicKeyType, SecretKeyType), Error> {
        use ml_dsa::{KeyGen, MlDsa65};

        let mut rng = citadel_io::ThreadRng::default();
        let kp = MlDsa65::key_gen(&mut rng);
        let pk_bytes = kp.verifying_key().encode().as_slice().to_vec();
        let sk_bytes = kp.signing_key().encode().as_slice().to_vec();
        Ok((Zeroizing::new(pk_bytes), Zeroizing::new(sk_bytes)))
    }

    // --- Falcon (FN-DSA-512) implementation ---

    fn falcon_sign(
        message: impl AsRef<[u8]>,
        secret_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        use fn_dsa::{
            sign_key_size, signature_size, SigningKey as _, SigningKey512, DOMAIN_NONE,
            FN_DSA_LOGN_512, HASH_ID_RAW,
        };

        let sk_bytes = secret_key.as_ref();
        let expected_len = sign_key_size(FN_DSA_LOGN_512);
        if sk_bytes.len() != expected_len {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::FalconKeyLengthInvalid
            ));
        }
        let mut sk = SigningKey512::decode(sk_bytes).ok_or(citadel_io::error!(
            citadel_io::ErrorCode::SigDecodeFailed,
            "Falcon",
            "signing key"
        ))?;

        let mut sig_buf = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        let mut rng = rand::thread_rng();
        sk.sign(
            &mut rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message.as_ref(),
            &mut sig_buf,
        );
        Ok(sig_buf)
    }

    fn falcon_verify(
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        use fn_dsa::{VerifyingKey as _, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};

        let pk = VerifyingKey512::decode(public_key.as_ref()).ok_or(citadel_io::error!(
            citadel_io::ErrorCode::SigDecodeFailed,
            "Falcon",
            "verifying key"
        ))?;
        if pk.verify(
            signature.as_ref(),
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message.as_ref(),
        ) {
            Ok(())
        } else {
            Err(citadel_io::error!(
                citadel_io::ErrorCode::SigVerificationFailed,
                "Falcon"
            ))
        }
    }

    fn falcon_keypair() -> Result<(PublicKeyType, SecretKeyType), Error> {
        use fn_dsa::{
            sign_key_size, vrfy_key_size, KeyPairGenerator as _, KeyPairGenerator512,
            FN_DSA_LOGN_512,
        };

        let mut rng = rand::thread_rng();
        let mut sk_buf = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
        let mut pk_buf = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
        let mut kgen = KeyPairGenerator512::default();
        kgen.keygen(FN_DSA_LOGN_512, &mut rng, &mut sk_buf, &mut pk_buf);
        Ok((Zeroizing::new(pk_buf), Zeroizing::new(sk_buf)))
    }
}

/// Contains the public keys for Alice and Bob
#[derive(Serialize, Deserialize)]
pub struct PostQuantumContainer {
    pub params: CryptoParameters,
    pub(crate) data: PostQuantumMeta,
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
    kex: PostQuantumMetaKex,
    sig: Option<PostQuantumMetaSig>,
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
        citadel_types::utils::validate_crypto_params(&params)?;
        let previous_symmetric_key = opts.chain;
        let data = Self::create_new_alice(params.kem_algorithm, params.sig_algorithm)
            .map_err(|err| Error::generic(err.to_string()))?;
        let key_store = None;
        log::trace!(target: "citadel", "Success creating new ALICE container");

        Ok(Self {
            params,
            data,
            chain: previous_symmetric_key,
            key_store,
            anti_replay_attack: AntiReplayAttackContainer::default(),
            node: PQNode::Alice,
        })
    }

    pub fn generate_alice_to_bob_transfer(&self) -> Result<AliceToBobTransferParameters, Error> {
        self.data.generate_alice_to_bob_transfer()
    }

    pub fn generate_bob_to_alice_transfer(&self) -> Result<BobToAliceTransferParameters, Error> {
        self.data.generate_bob_to_alice_transfer()
    }

    /// Creates a new [PostQuantumContainer] for Bob. This will panic if the algorithm is
    /// invalid
    pub fn new_bob<T: AsRef<[u8]>>(
        opts: ConstructorOpts,
        tx_params: AliceToBobTransferParameters,
        psks: &[T],
    ) -> Result<Self, Error> {
        let pq_node = PQNode::Bob;
        let params = opts.cryptography.unwrap_or_default();
        citadel_types::utils::validate_crypto_params(&params)?;

        let chain = opts.chain;

        let data =
            Self::create_new_bob(tx_params).map_err(|err| Error::generic(err.to_string()))?;
        // We must call the below to refresh the internal state to allow get_shared_secret to function
        let ss = data.get_shared_secret().unwrap().clone();
        let kex = data.kex().clone();
        let sig = data.sig().cloned();

        let (chain, keys) =
            Self::generate_recursive_keystore(pq_node, params, sig, ss, chain.as_ref(), kex, psks)
                .map_err(|err| {
                    citadel_io::error!(
                        citadel_io::ErrorCode::RecursiveKeystoreFailed,
                        err.to_string()
                    )
                })?;

        let keys = Some(keys);

        log::trace!(target: "citadel", "Success creating new BOB container");
        Ok(Self {
            chain: Some(chain),
            params,
            key_store: keys,
            data,
            anti_replay_attack: AntiReplayAttackContainer::default(),
            node: PQNode::Bob,
        })
    }

    /// `psks`: Pre-shared keys
    fn generate_recursive_keystore<T: AsRef<[u8]>>(
        pq_node: PQNode,
        params: CryptoParameters,
        sig: Option<PostQuantumMetaSig>,
        ss: Arc<Zeroizing<Vec<u8>>>,
        previous_chain: Option<&RecursiveChain>,
        kex: PostQuantumMetaKex,
        psks: &[T],
    ) -> Result<(RecursiveChain, KeyStore), Error> {
        let (chain, alice_key, bob_key) = if let Some(prev) = previous_chain {
            // prev = C_n
            // If a previous key, S_n, existed, we calculate S_(n+1)' = KDF(C_n || S_n || psks))
            let mut hasher_temp = sha3::Sha3_512::new();
            let mut hasher_alice = sha3::Sha3_256::new();
            let mut hasher_bob = sha3::Sha3_256::new();
            hasher_temp.update(
                &prev
                    .chain
                    .iter()
                    .chain(ss.iter())
                    .chain(psks.iter().flat_map(|r| r.as_ref()))
                    .copied()
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
                    .zip(bob_key)
                    .map(|(r1, r2)| r1 ^ r2)
                    .collect::<Vec<u8>>()[..],
            );
            let chain = hasher.finalize();

            let chain = RecursiveChain::new(chain.as_slice(), alice_key, bob_key, false)
                .ok_or(Error::invalid_length())?;

            //log::trace!(target: "citadel", "Alice, Bob keys: {:?} || {:?}", alice_key, bob_key);

            let alice_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                alice_key.as_slice().iter().cloned(),
            )
            .ok_or(Error::invalid_length())?;

            let bob_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.as_slice().iter().cloned(),
            )
            .ok_or(Error::invalid_length())?;

            (chain, alice_key, bob_key)
        } else {
            // The first key, S_0', = KDF(S_0)
            let mut hasher_temp = sha3::Sha3_512::new();
            hasher_temp.update(
                ss.iter()
                    .chain(psks.iter().flat_map(|r| r.as_ref()))
                    .copied()
                    .collect::<Vec<u8>>(),
            );
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
                .ok_or(Error::invalid_length())?;

            let alice_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                alice_key.iter().cloned(),
            )
            .ok_or(Error::invalid_length())?;

            let bob_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.iter().cloned(),
            )
            .ok_or(Error::invalid_length())?;

            (chain, alice_key, bob_key)
        };

        let (alice_symmetric_key, bob_symmetric_key) =
            keys_to_aead_store(&alice_key, &bob_key, &kex, params, sig.as_ref(), pq_node);

        Ok((
            chain,
            KeyStore {
                alice_module: alice_symmetric_key,
                bob_module: bob_symmetric_key,
                alice_key,
                bob_key,
                sig,
                kex,
                pq_node,
                params,
            },
        ))
    }

    fn get_encryption_key(&self) -> Option<&dyn AeadModule> {
        match self.node {
            PQNode::Alice => Some(self.key_store.as_ref()?.alice_module.as_deref()?),
            PQNode::Bob => Some(self.key_store.as_ref()?.bob_module.as_deref()?),
        }
    }

    fn get_decryption_key(&self) -> Option<&dyn AeadModule> {
        if let EncryptionAlgorithm::MlKemHybrid = self.params.encryption_algorithm {
            // use multi-modal asymmetric + symmetric ratcheted encryption
            // alice's key is in alice, bob's key is in bob. Thus, use encryption key
            self.get_encryption_key()
        } else {
            // use symmetric encryption only (NOT post quantum, only quantum-resistant, but faster)
            match self.node {
                PQNode::Alice => Some(self.key_store.as_ref()?.bob_module.as_deref()?),
                PQNode::Bob => Some(self.key_store.as_ref()?.alice_module.as_deref()?),
            }
        }
    }

    /// Resets the counters to zero, as well as reset any additional stateful resources
    pub fn reset_counters(&self) {
        self.anti_replay_attack.reset();
    }

    /// This should always be called after deserialization
    fn load_symmetric_keys<T: AsRef<[u8]>>(&mut self, psks: &[T]) -> Result<(), Error> {
        let pq_node = self.node;
        let params = self.params;
        let sig = self.data.sig().cloned();
        let ss = self.get_shared_secret()?.clone();
        let kex = self.data.kex().clone();
        let prev_symmetric_key = self.chain.as_ref();

        let (chain, key) = Self::generate_recursive_keystore(
            pq_node,
            params,
            sig,
            ss,
            prev_symmetric_key,
            kex,
            psks,
        )?;

        self.key_store = Some(key);
        self.chain = Some(chain);

        Ok(())
    }

    /// Internally creates shared key after bob sends a response back to Alice
    pub fn alice_on_receive_ciphertext<T: AsRef<[u8]>>(
        &mut self,
        params: BobToAliceTransferParameters,
        psks: &[T],
    ) -> Result<(), Error> {
        self.data.alice_on_receive_ciphertext(params)?;
        let _ss = self.data.get_shared_secret()?; // call once to load internally
        self.load_symmetric_keys(psks)
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
            Err(Error::invalid_length())
        }
    }

    pub fn get_public_key_remote(&self) -> &Arc<Zeroizing<Vec<u8>>> {
        self.data.get_public_key_remote().unwrap()
    }

    /// Gets the public key
    pub fn get_public_key(&self) -> &Arc<Zeroizing<Vec<u8>>> {
        self.data.get_public_key()
    }
    /// Gets the secret key (If node is Alice type)
    pub fn get_secret_key(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        self.data.get_secret_key()
    }
    /// Gets the ciphertext
    pub fn get_ciphertext(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        self.data.get_ciphertext()
    }
    /// Gets the shared secret
    pub fn get_shared_secret(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        self.data.get_shared_secret()
    }

    /// Serializes the entire package to a vector
    pub fn serialize_to_vector(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(self)
            .map_err(|_err| citadel_io::error!(citadel_io::ErrorCode::ContainerSerdeFailed))
    }

    /// Attempts to deserialize the input bytes presumed to be of type [PostQuantumExport],
    /// into a [PostQuantumContainer]
    pub fn deserialize_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        bincode::deserialize::<PostQuantumContainer>(bytes.as_ref())
            .map_err(|_err| citadel_io::error!(citadel_io::ErrorCode::ContainerSerdeFailed))
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
    ) -> Result<Vec<u8>, Error> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key.encrypt(nonce, input)
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Encrypts the data using the local public key. This implies
    /// only local's private key may be used for decryption.
    pub fn local_encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        input: T,
        nonce: R,
    ) -> Result<Vec<u8>, Error> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key.local_user_encrypt(nonce, input)
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Encrypts the data using the local public key. This implies
    /// only local's private key may be used for decryption.
    pub fn local_decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        input: T,
        nonce: R,
    ) -> Result<Vec<u8>, Error> {
        let input = input.as_ref();
        let nonce = nonce.as_ref();

        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key.local_user_decrypt(nonce, input)
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    pub fn protect_packet_in_place<T: EzBuffer, R: AsRef<[u8]>>(
        &self,
        header_len: usize,
        full_packet: &mut T,
        nonce: R,
    ) -> Result<(), Error> {
        let nonce = nonce.as_ref();
        let mut payload = full_packet.split_off(header_len);
        let header = full_packet;

        // next, push the ARA-generated PID
        payload.put_u64(self.anti_replay_attack.get_next_pid());
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(&mut payload, 0..payload_len)
            .ok_or(citadel_io::error!(citadel_io::ErrorCode::BadWindowRange))?;
        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key
                .encrypt_in_place(nonce, header.subset(0..header_len), &mut in_place_payload)
                .map_err(|_| Error::encryption_failure())?;
            header.unsplit(payload);
            Ok(())
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Validates the AAD (header) and produces the plaintext given the input of ciphertext
    pub fn validate_packet_in_place<T: EzBuffer, H: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        header: H,
        payload: &mut T,
        nonce: R,
    ) -> Result<(), Error> {
        let nonce = nonce.as_ref();
        let header = header.as_ref();
        let payload_len = payload.len();

        let mut in_place_payload = InPlaceBuffer::new(payload, 0..payload_len)
            .ok_or(citadel_io::error!(citadel_io::ErrorCode::BadWindowRange))?;
        if let Some(symmetric_key) = self.get_decryption_key() {
            symmetric_key
                .decrypt_in_place(nonce, header, &mut in_place_payload)
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
                            Err(citadel_io::error!(
                                citadel_io::ErrorCode::AntiReplayInvalid
                            ))
                        }
                    } else {
                        Err(citadel_io::error!(
                            citadel_io::ErrorCode::AntiReplayBadLength
                        ))
                    }
                })
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Raw in-place AEAD encrypt with NO header AAD and NO anti-replay PID — byte-for-byte
    /// compatible with the output of [`Self::encrypt`]. Encrypts the whole buffer in place and
    /// appends the authentication tag, avoiding the fresh `Vec` allocation `encrypt` performs.
    /// Used by the scramble/group path (which encrypts a whole wave with no per-packet PID).
    pub fn encrypt_in_place<T: EzBuffer, R: AsRef<[u8]>>(
        &self,
        buf: &mut T,
        nonce: R,
    ) -> Result<(), Error> {
        let nonce = nonce.as_ref();
        let len = buf.len();
        let mut in_place =
            InPlaceBuffer::new(buf, 0..len)
                .ok_or(citadel_io::error!(citadel_io::ErrorCode::BadWindowRange))?;
        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key
                .encrypt_in_place(nonce, &[], &mut in_place)
                .map_err(|_| Error::encryption_failure())
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Raw in-place AEAD decrypt matching [`Self::encrypt_in_place`] / [`Self::encrypt`] (no header
    /// AAD, no anti-replay PID). Decrypts the buffer in place and removes the authentication tag,
    /// avoiding the fresh `Vec` allocation `decrypt` performs.
    pub fn decrypt_in_place<T: EzBuffer, R: AsRef<[u8]>>(
        &self,
        buf: &mut T,
        nonce: R,
    ) -> Result<(), Error> {
        let nonce = nonce.as_ref();
        let len = buf.len();
        let mut in_place =
            InPlaceBuffer::new(buf, 0..len)
                .ok_or(citadel_io::error!(citadel_io::ErrorCode::BadWindowRange))?;
        if let Some(symmetric_key) = self.get_decryption_key() {
            symmetric_key
                .decrypt_in_place(nonce, &[], &mut in_place)
                .map_err(|_| Error::decryption_failure())
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    /// Encrypts the data. This will return an error if the internal shared secret is not set
    pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        &self,
        input: T,
        nonce: R,
    ) -> Result<Vec<u8>, Error>
    where
        Self: Sized,
    {
        let input = input.as_ref();
        let nonce = nonce.as_ref();
        // if the shared secret is loaded, the AES GCM abstraction should too.

        if let Some(symmetric_key) = self.get_decryption_key() {
            symmetric_key.decrypt(nonce, input)
        } else {
            Err(Error::shared_secret_not_loaded())
        }
    }

    fn create_new_alice(
        kem_algorithm: KemAlgorithm,
        sig_algorithm: SigAlgorithm,
    ) -> Result<PostQuantumMeta, Error> {
        PostQuantumMeta::new_alice(kem_algorithm, sig_algorithm)
    }

    fn create_new_bob(
        alice_to_bob_transfer_params: AliceToBobTransferParameters,
    ) -> Result<PostQuantumMeta, Error> {
        PostQuantumMeta::new_bob(alice_to_bob_transfer_params)
    }
}

impl Clone for PostQuantumContainer {
    fn clone(&self) -> Self {
        let ser = self.serialize_to_vector().unwrap();
        PostQuantumContainer::deserialize_from_bytes(ser).unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PostQuantumMetaKex {
    /// The public key of remote
    remote_public_key: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// The public key. Both Alice and Bob get this
    public_key: Arc<Zeroizing<Vec<u8>>>,
    /// secret key pair of the public key
    secret_key: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// Both Bob and Alice get this one
    ciphertext: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// Both Alice and Bob get this (at the end)
    shared_secret: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// the kem algorithm
    kem_alg: KemAlgorithm,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PostQuantumMetaSig {
    sig_public_key: Arc<crate::functions::PublicKeyType>,
    sig_private_key: Arc<crate::functions::SecretKeyType>,
    remote_sig_public_key: Option<Arc<crate::functions::PublicKeyType>>,
    /// the sig alg
    sig_alg: SigAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub enum PostQuantumMeta {
    /// a light, fast, and quantum-resistant protocol setup for performing
    /// ratcheted symmetric encryption of plaintext (e.g., AES-GCM)
    PureSymmetricEncryption { kex: PostQuantumMetaKex },
    /// A heavier, more secure, and post-quantum protocol setup for performing
    /// a mixed use of asymmetric and ratcheted symmetric encryption of plaintext
    /// Note: since this uses Kyber, every 32 bytes of input plaintext is mapped to
    /// ~1100 bytes of ciphertext. Using this for encryption is only recommended for
    /// Small to medium sized messages, not large files.
    MixedAsymmetric {
        kex: PostQuantumMetaKex,
        sig: PostQuantumMetaSig,
    },
}

impl PostQuantumMeta {
    fn new_alice(kem_alg: KemAlgorithm, sig_alg: SigAlgorithm) -> Result<Self, Error> {
        log::trace!(target: "citadel", "About to generate keypair for {kem_alg:?}");
        let (public_key, secret_key) = match kem_alg {
            KemAlgorithm::MlKem => {
                let pk_alice =
                    kyber_pke::kem_keypair().map_err(|err| Error::generic(err.to_string()))?;
                (pk_alice.public.to_vec(), pk_alice.secret.to_vec())
            }
        };

        let ciphertext = None;
        let shared_secret = None;
        let remote_sig_public_key = None;
        let secret_key = Some(Arc::new(secret_key.into()));

        let kex = PostQuantumMetaKex {
            public_key: Arc::new(public_key.into()),
            secret_key,
            ciphertext,
            shared_secret,
            kem_alg,
            remote_public_key: None,
        };

        match sig_alg {
            SigAlgorithm::MlDsa65 | SigAlgorithm::FnDsa512 => {
                let (sig_public_key, sig_private_key) =
                    crate::functions::signature_keypair(sig_alg)?;
                let sig = PostQuantumMetaSig {
                    sig_public_key: Arc::new(sig_public_key),
                    sig_private_key: Arc::new(sig_private_key),
                    remote_sig_public_key,
                    sig_alg,
                };

                Ok(Self::MixedAsymmetric { kex, sig })
            }

            SigAlgorithm::None => Ok(Self::PureSymmetricEncryption { kex }),
        }
    }

    fn new_bob(params: AliceToBobTransferParameters) -> Result<Self, Error> {
        let (kem_scheme, pk_alice) = match &params {
            AliceToBobTransferParameters::MixedAsymmetric {
                kem_scheme,
                alice_pk,
                ..
            }
            | AliceToBobTransferParameters::PureSymmetric {
                kem_scheme,
                alice_pk,
                ..
            } => (*kem_scheme, alice_pk),
        };

        let (kem_pk_bob, kem_sk_bob) = match kem_scheme {
            KemAlgorithm::MlKem => {
                let pk_bob =
                    kyber_pke::kem_keypair().map_err(|err| Error::generic(err.to_string()))?;
                (pk_bob.public.to_vec(), pk_bob.secret.to_vec())
            }
        };

        let (ciphertext, shared_secret) = match kem_scheme {
            KemAlgorithm::MlKem => {
                let (ciphertext, shared_secret) =
                    kyber_pke::encapsulate(pk_alice, &mut ThreadRng::default())
                        .map_err(|_err| {
                            citadel_io::error!(citadel_io::ErrorCode::EncapsulateFailed)
                        })?;
                (ciphertext.to_vec(), shared_secret.to_vec())
            }
        };

        let public_key = Arc::new(kem_pk_bob.into());
        let secret_key = Some(Arc::new(kem_sk_bob.into()));
        let shared_secret = Some(Arc::new(shared_secret.into()));
        let ciphertext = Some(Arc::new(ciphertext.into()));

        match params {
            AliceToBobTransferParameters::MixedAsymmetric {
                alice_pk,
                alice_pk_sig,
                alice_public_key_signature,
                sig_scheme,
                kem_scheme,
            } => {
                let (sig_pk_bob, sig_sk_bob) = crate::functions::signature_keypair(sig_scheme)?;
                let public_key_alice = alice_pk;

                crate::functions::signature_verify(
                    public_key_alice.as_slice(),
                    alice_public_key_signature.as_slice(),
                    alice_pk_sig.as_slice(),
                    sig_scheme,
                )?;

                let remote_sig_public_key = Some(alice_pk_sig);

                let kex = PostQuantumMetaKex {
                    remote_public_key: Some(public_key_alice),
                    public_key,
                    secret_key,
                    ciphertext,
                    shared_secret,
                    kem_alg: kem_scheme,
                };

                let sig = PostQuantumMetaSig {
                    sig_public_key: Arc::new(sig_pk_bob),
                    sig_private_key: Arc::new(sig_sk_bob),
                    remote_sig_public_key,
                    sig_alg: sig_scheme,
                };

                Ok(Self::MixedAsymmetric { kex, sig })
            }
            AliceToBobTransferParameters::PureSymmetric {
                alice_pk,
                kem_scheme,
            } => {
                let public_key_alice = alice_pk;
                let kex = PostQuantumMetaKex {
                    remote_public_key: Some(public_key_alice),
                    public_key,
                    secret_key,
                    ciphertext,
                    shared_secret,
                    kem_alg: kem_scheme,
                };

                Ok(Self::PureSymmetricEncryption { kex })
            }
        }
    }

    fn alice_on_receive_ciphertext(
        &mut self,
        params: BobToAliceTransferParameters,
    ) -> Result<(), Error> {
        // These functions should only be called once upon response back from Bob
        let bob_ciphertext = match &params {
            BobToAliceTransferParameters::PureSymmetric { bob_ciphertext, .. } => {
                bob_ciphertext.clone()
            }
            BobToAliceTransferParameters::MixedAsymmetric {
                bob_ciphertext_signature,
                bob_pk_sig,
                bob_ciphertext,
                ..
            } => {
                let sig_alg = self.sig().map(|s| s.sig_alg).unwrap_or(SigAlgorithm::None);
                crate::functions::signature_verify(
                    bob_ciphertext.as_slice(),
                    bob_ciphertext_signature.as_slice(),
                    bob_pk_sig.as_slice(),
                    sig_alg,
                )?;
                bob_ciphertext.clone()
            }
        };

        let secret_key = self.get_secret_key()?;

        let shared_secret = match self.kex().kem_alg {
            KemAlgorithm::MlKem => kyber_pke::decapsulate(&bob_ciphertext, secret_key)
                .map_err(|err| Error::generic(err.to_string()))?
                .to_vec(),
        };

        self.get_kex_mut().shared_secret = Some(Arc::new(shared_secret.into()));
        self.get_kex_mut().ciphertext = Some(bob_ciphertext);

        match params {
            BobToAliceTransferParameters::MixedAsymmetric {
                bob_pk_sig, bob_pk, ..
            } => {
                self.get_kex_mut().remote_public_key = Some(bob_pk);
                self.get_sig_mut().unwrap().remote_sig_public_key = Some(bob_pk_sig);
                Ok(())
            }
            BobToAliceTransferParameters::PureSymmetric { bob_pk, .. } => {
                self.get_kex_mut().remote_public_key = Some(bob_pk);
                Ok(())
            }
        }
    }

    fn generate_alice_to_bob_transfer(&self) -> Result<AliceToBobTransferParameters, Error> {
        match self {
            Self::MixedAsymmetric { kex, sig } => {
                let alice_pk = kex.public_key.clone();
                let alice_pk_sig = sig.sig_public_key.clone();
                let alice_public_key_signature = crate::functions::signature_sign(
                    alice_pk.as_slice(),
                    sig.sig_private_key.as_slice(),
                    sig.sig_alg,
                )?
                .into();
                let sig_scheme = sig.sig_alg;
                let kem_scheme = kex.kem_alg;

                Ok(AliceToBobTransferParameters::MixedAsymmetric {
                    alice_pk,
                    alice_pk_sig,
                    alice_public_key_signature,
                    sig_scheme,
                    kem_scheme,
                })
            }
            PostQuantumMeta::PureSymmetricEncryption { kex } => {
                let alice_pk = kex.public_key.clone();
                let kem_scheme = kex.kem_alg;

                Ok(AliceToBobTransferParameters::PureSymmetric {
                    alice_pk,
                    kem_scheme,
                })
            }
        }
    }

    fn generate_bob_to_alice_transfer(&self) -> Result<BobToAliceTransferParameters, Error> {
        let bob_ciphertext = self.get_ciphertext().cloned()?;
        let bob_pk = self.get_public_key().clone();
        match self {
            PostQuantumMeta::PureSymmetricEncryption { .. } => {
                Ok(BobToAliceTransferParameters::PureSymmetric {
                    bob_ciphertext,
                    bob_pk,
                })
            }
            PostQuantumMeta::MixedAsymmetric { sig, .. } => {
                let bob_signed_ciphertext = crate::functions::signature_sign(
                    bob_ciphertext.as_slice(),
                    sig.sig_private_key.as_slice(),
                    sig.sig_alg,
                )?
                .into();
                let bob_pk_sig = sig.sig_public_key.clone();

                Ok(BobToAliceTransferParameters::MixedAsymmetric {
                    bob_ciphertext_signature: Arc::new(bob_signed_ciphertext),
                    bob_ciphertext,
                    bob_pk_sig,
                    bob_pk,
                })
            }
        }
    }

    #[allow(dead_code)]
    fn get_sig_algorithm(&self) -> Option<SigAlgorithm> {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { .. } => None,
            PostQuantumMeta::MixedAsymmetric { sig, .. } => Some(sig.sig_alg),
        }
    }

    fn kex(&self) -> &PostQuantumMetaKex {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => kex,
        }
    }

    fn sig(&self) -> Option<&PostQuantumMetaSig> {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { .. } => None,
            PostQuantumMeta::MixedAsymmetric { sig, .. } => Some(sig),
        }
    }

    fn get_kex_mut(&mut self) -> &mut PostQuantumMetaKex {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => kex,
        }
    }

    fn get_sig_mut(&mut self) -> Option<&mut PostQuantumMetaSig> {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { .. } => None,
            PostQuantumMeta::MixedAsymmetric { sig, .. } => Some(sig),
        }
    }

    fn get_public_key_remote(&self) -> Option<&Arc<Zeroizing<Vec<u8>>>> {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => kex.remote_public_key.as_ref(),
        }
    }

    fn get_public_key(&self) -> &Arc<Zeroizing<Vec<u8>>> {
        match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => &kex.public_key,
        }
    }

    fn get_secret_key(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        let sk = match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => &kex.secret_key,
        };

        if let Some(secret_key) = sk {
            Ok(secret_key)
        } else {
            Err(citadel_io::error!(
                citadel_io::ErrorCode::SecretKeyUnavailable
            ))
        }
    }

    fn get_ciphertext(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        let ct = match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => &kex.ciphertext,
        };

        if let Some(ciphertext) = ct {
            Ok(ciphertext)
        } else {
            Err(citadel_io::error!(
                citadel_io::ErrorCode::CiphertextUnavailable
            ))
        }
    }

    fn get_shared_secret(&self) -> Result<&Arc<Zeroizing<Vec<u8>>>, Error> {
        let ss = match self {
            PostQuantumMeta::PureSymmetricEncryption { kex }
            | PostQuantumMeta::MixedAsymmetric { kex, .. } => &kex.shared_secret,
        };

        if let Some(shared_secret) = ss {
            Ok(shared_secret)
        } else {
            Err(citadel_io::error!(
                citadel_io::ErrorCode::SecretKeyUnavailable
            ))
        }
    }
}


impl Debug for PostQuantumContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PQC {:?} | {:?}", self.node, self.params)
    }
}

pub trait EncryptionAlgorithmExt {
    fn nonce_len(&self) -> usize;
    fn max_ciphertext_len(&self, plaintext_length: usize, sig_alg: SigAlgorithm) -> usize;
    fn plaintext_length(&self, ciphertext: &[u8]) -> Option<usize>;
}

impl EncryptionAlgorithmExt for EncryptionAlgorithm {
    fn nonce_len(&self) -> usize {
        match self {
            Self::AES_GCM_256 => AES_GCM_NONCE_LENGTH_BYTES,
            Self::ChaCha20Poly_1305 => CHA_CHA_NONCE_LENGTH_BYTES,
            Self::MlKemHybrid => KYBER_NONCE_LENGTH_BYTES,
            Self::Ascon80pq => ASCON_NONCE_LENGTH_BYTES,
        }
    }

    // calculates the max ciphertext len given an input plaintext length
    fn max_ciphertext_len(&self, plaintext_length: usize, sig_alg: SigAlgorithm) -> usize {
        const SYMMETRIC_CIPHER_OVERHEAD: usize = 16;
        match self {
            Self::AES_GCM_256 => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            // plaintext len + 128 bit tag
            Self::ChaCha20Poly_1305 => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            Self::Ascon80pq => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            // Add 32 for internal apendees
            Self::MlKemHybrid => {
                const LENGTH_FIELD: usize = 8;
                let signature_len = functions::signature_bytes(sig_alg);

                let aes_input_len = signature_len + LENGTH_FIELD;
                let aes_output_len = aes_input_len + SYMMETRIC_CIPHER_OVERHEAD;
                let kyber_input_len = 32 + LENGTH_FIELD; // the size of the mapping + encoded len
                let kyber_output_len = kyber_pke::ct_len(kyber_input_len);

                // add 8 for the length encoding
                aes_output_len + kyber_output_len + LENGTH_FIELD
            }
        }
    }

    fn plaintext_length(&self, ciphertext: &[u8]) -> Option<usize> {
        if ciphertext.len() < 16 {
            return None;
        }

        match self {
            Self::AES_GCM_256 => Some(ciphertext.len() - 16),
            Self::ChaCha20Poly_1305 => Some(ciphertext.len() - 16),
            Self::Ascon80pq => Some(ciphertext.len() - 16),
            Self::MlKemHybrid => kyber_pke::plaintext_len(ciphertext),
        }
    }
}

#[macro_export]
macro_rules! impl_basic_aead_module {
    ($val:ty, $nonce_len:expr) => {
        impl AeadModule for $val {
            fn encrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                // Take only the required nonce length, handling cases where provided nonce is longer
                let nonce_slice = if nonce.len() >= $nonce_len {
                    &nonce[..$nonce_len]
                } else {
                    return Err(citadel_io::error!(citadel_io::ErrorCode::NonceTooShort));
                };

                self.aead
                    .encrypt_in_place(GenericArray::from_slice(nonce_slice), ad, input)
                    .map_err(|err| {
                        log::error!(target: "citadel", "AEAD encrypt_in_place failed: {:?}", err);
                        Error::encryption_failure()
                    })
            }

            fn decrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                // Take only the required nonce length, handling cases where provided nonce is longer
                let nonce_slice = if nonce.len() >= $nonce_len {
                    &nonce[..$nonce_len]
                } else {
                    return Err(citadel_io::error!(citadel_io::ErrorCode::NonceTooShort));
                };

                self.aead
                    .decrypt_in_place(GenericArray::from_slice(nonce_slice), ad, input)
                    .map_err(|err| {
                        log::error!(target: "citadel", "AEAD decrypt_in_place failed: {:?}", err);
                        Error::encryption_failure()
                    })
            }

            fn local_user_encrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                // For non-Kyber algorithms, local encryption is just regular encryption
                // Only KyberModule should use the special PKE-based local encryption
                self.encrypt_in_place(nonce, ad, input)
            }

            fn local_user_decrypt_in_place(
                &self,
                nonce: &[u8],
                ad: &[u8],
                input: &mut dyn Buffer,
            ) -> Result<(), Error> {
                // For non-Kyber algorithms, local decryption is just regular decryption
                // Only KyberModule should use the special PKE-based local decryption
                self.decrypt_in_place(nonce, ad, input)
            }
        }
    };
}

#[cfg(test)]
mod in_place_aead_tests {
    use super::PostQuantumContainer;
    use crate::constructor_opts::ConstructorOpts;
    use bytes::BytesMut;

    // AEAD keys are directional (a container's tx key differs from its rx key), mirroring the
    // protocol's sender/receiver split. So encrypt on alice (tx) is decrypted on bob (rx).
    fn keyed_pair() -> (PostQuantumContainer, PostQuantumContainer) {
        let opts = ConstructorOpts::default();
        let mut alice = PostQuantumContainer::new_alice(opts.clone()).unwrap();
        let a2b = alice.generate_alice_to_bob_transfer().unwrap();
        let bob = PostQuantumContainer::new_bob(opts, a2b, &[b"psk"]).unwrap();
        let b2a = bob.generate_bob_to_alice_transfer().unwrap();
        alice.alice_on_receive_ciphertext(b2a, &[b"psk"]).unwrap();
        (alice, bob)
    }

    // The raw in-place AEAD primitives must round-trip and be byte-compatible with the existing
    // Vec-allocating encrypt/decrypt (no header AAD, no anti-replay PID), so the scramble/group
    // path can switch to them without a wire-format change.
    #[test]
    fn in_place_roundtrip_matches_vec_path() {
        let (alice, bob) = keyed_pair();
        let nonce = [0x5Au8; 32];
        let plaintext = b"in-place AEAD must round-trip and match the Vec path".to_vec();

        // encrypt_in_place (alice/tx) -> decrypt_in_place (bob/rx)
        let mut buf = BytesMut::from(&plaintext[..]);
        alice.encrypt_in_place(&mut buf, nonce).unwrap();
        assert_ne!(
            &buf[..],
            &plaintext[..],
            "ciphertext must differ from plaintext"
        );
        bob.decrypt_in_place(&mut buf, nonce).unwrap();
        assert_eq!(&buf[..], &plaintext[..], "in-place round-trip failed");

        // Vec encrypt (alice) -> in-place decrypt (bob): byte-compatible formats.
        let ct = alice.encrypt(&plaintext, nonce).unwrap();
        let mut buf2 = BytesMut::from(&ct[..]);
        bob.decrypt_in_place(&mut buf2, nonce).unwrap();
        assert_eq!(
            &buf2[..],
            &plaintext[..],
            "Vec-encrypt -> in-place-decrypt mismatch"
        );

        // in-place encrypt (alice) -> Vec decrypt (bob): byte-compatible formats.
        let mut buf3 = BytesMut::from(&plaintext[..]);
        alice.encrypt_in_place(&mut buf3, nonce).unwrap();
        let pt = bob.decrypt(&buf3[..], nonce).unwrap();
        assert_eq!(
            &pt[..],
            &plaintext[..],
            "in-place-encrypt -> Vec-decrypt mismatch"
        );
    }
}
