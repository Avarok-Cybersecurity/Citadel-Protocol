#![allow(non_camel_case_types)]
#![forbid(unsafe_code)]

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

#[cfg(target_family = "wasm")]
use crate::functions::AsSlice;

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

#[cfg(not(target_family = "wasm"))]
pub(crate) mod functions {
    use citadel_types::errors::Error;
    use oqs::sig::Sig;
    use zeroize::Zeroizing;

    pub type SecretKeyType = Zeroizing<Vec<u8>>;
    pub type PublicKeyType = Zeroizing<Vec<u8>>;
    const ALG: oqs::sig::Algorithm = oqs::sig::Algorithm::Falcon1024;

    pub fn signature_sign(
        message: impl AsRef<[u8]>,
        secret_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let sig = get_sig()?;
        let secret_key = sig
            .secret_key_from_bytes(secret_key.as_ref())
            .ok_or(Error::Generic("Bad secret key length"))?;
        sig.sign(message.as_ref(), secret_key)
            .map(|r| r.into_vec())
            .map_err(|err| Error::Other(err.to_string()))
    }

    pub fn signature_verify(
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let sig = get_sig()?;
        let signature = sig
            .signature_from_bytes(signature.as_ref())
            .ok_or(Error::Generic("Bad signature length"))?;
        let public_key = sig
            .public_key_from_bytes(public_key.as_ref())
            .ok_or(Error::Generic("Bad public key length"))?;

        sig.verify(message.as_ref(), signature, public_key)
            .map_err(|err| Error::Other(err.to_string()))
    }

    pub fn signature_keypair() -> Result<(PublicKeyType, SecretKeyType), Error> {
        get_sig()?
            .keypair()
            .map_err(|err| Error::Other(err.to_string()))
            .map(|(l, r)| (l.into_vec().into(), r.into_vec().into()))
    }

    pub fn signature_bytes() -> usize {
        get_sig().unwrap().length_signature()
    }

    fn get_sig() -> Result<Sig, Error> {
        oqs::sig::Sig::new(ALG).map_err(|err| Error::Other(err.to_string()))
    }
}

#[cfg(target_family = "wasm")]
pub(crate) mod functions {
    use citadel_types::errors::Error;
    use pqcrypto_falcon_wasi::falcon1024;
    use pqcrypto_falcon_wasi::falcon1024::DetachedSignature;
    use pqcrypto_traits_wasi::sign::PublicKey as PublicKeyTrait;
    use pqcrypto_traits_wasi::sign::{DetachedSignature as DetachedSignatureTrait, SecretKey};

    pub trait AsSlice {
        fn as_slice(&self) -> &[u8];
    }

    pub type SecretKeyType = falcon1024::SecretKey;
    pub type PublicKeyType = falcon1024::PublicKey;

    impl AsSlice for SecretKeyType {
        fn as_slice(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    impl AsSlice for DetachedSignature {
        fn as_slice(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    impl AsSlice for PublicKeyType {
        fn as_slice(&self) -> &[u8] {
            use pqcrypto_traits_wasi::sign::PublicKey;
            self.as_bytes()
        }
    }

    pub fn signature_sign(
        message: impl AsRef<[u8]>,
        secret_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let secret_key = falcon1024::SecretKey::from_bytes(secret_key.as_ref())
            .map_err(|err| Error::Other(err.to_string()))?;
        Ok(falcon1024::detached_sign(message.as_ref(), &secret_key)
            .as_bytes()
            .to_vec())
    }

    pub fn signature_verify(
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let signature = deserialize::<falcon1024::DetachedSignature>(signature.as_ref())?;
        let public_key = falcon1024::PublicKey::from_bytes(public_key.as_ref())
            .map_err(|err| Error::Other(err.to_string()))?;
        falcon1024::verify_detached_signature(&signature, message.as_ref(), &public_key)
            .map_err(|err| Error::Other(err.to_string()))
    }

    pub fn signature_keypair() -> Result<(PublicKeyType, SecretKeyType), Error> {
        Ok(falcon1024::keypair())
    }

    pub fn signature_bytes() -> usize {
        pqcrypto_falcon_wasi::falcon1024::signature_bytes()
    }

    fn deserialize<T: DetachedSignatureTrait>(bytes: &[u8]) -> Result<T, Error> {
        T::from_bytes(bytes).map_err(|err| Error::Other(err.to_string()))
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
            .map_err(|err| Error::Other(err.to_string()))?;
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
    pub fn new_bob(
        opts: ConstructorOpts,
        tx_params: AliceToBobTransferParameters,
        psks: &[Vec<u8>],
    ) -> Result<Self, Error> {
        let pq_node = PQNode::Bob;
        let params = opts.cryptography.unwrap_or_default();
        citadel_types::utils::validate_crypto_params(&params)?;

        let chain = opts.chain;

        let data = Self::create_new_bob(tx_params).map_err(|err| Error::Other(err.to_string()))?;
        // We must call the below to refresh the internal state to allow get_shared_secret to function
        let ss = data.get_shared_secret().unwrap().clone();
        let kex = data.kex().clone();
        let sig = data.sig().cloned();

        let (chain, keys) =
            Self::generate_recursive_keystore(pq_node, params, sig, ss, chain.as_ref(), kex, psks)
                .map_err(|err| {
                    Error::Other(format!("Error while calculating recursive keystore: {err}",))
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
    fn generate_recursive_keystore(
        pq_node: PQNode,
        params: CryptoParameters,
        sig: Option<PostQuantumMetaSig>,
        ss: Arc<Zeroizing<Vec<u8>>>,
        previous_chain: Option<&RecursiveChain>,
        kex: PostQuantumMetaKex,
        psks: &[Vec<u8>],
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
                    .chain(psks.iter().flatten())
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
                .ok_or(Error::InvalidLength)?;

            //log::trace!(target: "citadel", "Alice, Bob keys: {:?} || {:?}", alice_key, bob_key);

            let alice_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                alice_key.as_slice().iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

            let bob_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.as_slice().iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

            (chain, alice_key, bob_key)
        } else {
            // The first key, S_0', = KDF(S_0)
            let mut hasher_temp = sha3::Sha3_512::new();
            hasher_temp.update(
                ss.iter()
                    .chain(psks.iter().flatten())
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
                .ok_or(Error::InvalidLength)?;

            let alice_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                alice_key.iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

            let bob_key = aes_gcm::aead::generic_array::GenericArray::<u8, _>::from_exact_iter(
                bob_key.iter().cloned(),
            )
            .ok_or(Error::InvalidLength)?;

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
        if let EncryptionAlgorithm::Kyber = self.params.encryption_algorithm {
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
    fn load_symmetric_keys(&mut self, psks: &[Vec<u8>]) -> Result<(), Error> {
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
    pub fn alice_on_receive_ciphertext(
        &mut self,
        params: BobToAliceTransferParameters,
        psks: &[Vec<u8>],
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
            Err(Error::InvalidLength)
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
        bincode::serialize(self).map_err(|_err| Error::Generic("Deserialization failure"))
    }

    /// Attempts to deserialize the input bytes presumed to be of type [PostQuantumExport],
    /// into a [PostQuantumContainer]
    pub fn deserialize_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        bincode::deserialize::<PostQuantumContainer>(bytes.as_ref())
            .map_err(|_err| Error::Generic("Deserialization failure"))
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
            Err(Error::SharedSecretNotLoaded)
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
            Err(Error::SharedSecretNotLoaded)
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
            Err(Error::SharedSecretNotLoaded)
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
            .ok_or(Error::Generic("Bad window range"))?;
        if let Some(symmetric_key) = self.get_encryption_key() {
            symmetric_key
                .encrypt_in_place(nonce, header.subset(0..header_len), &mut in_place_payload)
                .map_err(|_| Error::EncryptionFailure)?;
            header.unsplit(payload);
            Ok(())
        } else {
            Err(Error::SharedSecretNotLoaded)
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
            .ok_or(Error::Generic("Bad window range"))?;
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
                            Err(Error::Generic("Anti-replay-attack: invalid"))
                        }
                    } else {
                        Err(Error::Generic(
                            "Anti-replay-attack: Invalid inscription length",
                        ))
                    }
                })
        } else {
            Err(Error::SharedSecretNotLoaded)
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
            Err(Error::SharedSecretNotLoaded)
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
        log::trace!(target: "citadel", "About to generate keypair for {:?}", kem_alg);
        let (public_key, secret_key) = match kem_alg {
            KemAlgorithm::Kyber => {
                let pk_alice =
                    kyber_pke::kem_keypair().map_err(|err| Error::Other(err.to_string()))?;
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
            SigAlgorithm::Falcon1024 => {
                let (sig_public_key, sig_private_key) = crate::functions::signature_keypair()?;
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
            KemAlgorithm::Kyber => {
                let pk_bob =
                    kyber_pke::kem_keypair().map_err(|err| Error::Other(err.to_string()))?;
                (pk_bob.public.to_vec(), pk_bob.secret.to_vec())
            }
        };

        let (ciphertext, shared_secret) = match kem_scheme {
            KemAlgorithm::Kyber => {
                let (ciphertext, shared_secret) =
                    kyber_pke::encapsulate(pk_alice, &mut ThreadRng::default())
                        .map_err(|_err| get_generic_error("Failed encapsulate step"))?;
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
                let (sig_pk_bob, sig_sk_bob) = crate::functions::signature_keypair()?;
                let public_key_alice = alice_pk;

                crate::functions::signature_verify(
                    public_key_alice.as_slice(),
                    alice_public_key_signature.as_slice(),
                    alice_pk_sig.as_slice(),
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
                crate::functions::signature_verify(
                    bob_ciphertext.as_slice(),
                    bob_ciphertext_signature.as_slice(),
                    bob_pk_sig.as_slice(),
                )?;
                bob_ciphertext.clone()
            }
        };

        let secret_key = self.get_secret_key()?;

        let shared_secret = match self.kex().kem_alg {
            KemAlgorithm::Kyber => kyber_pke::decapsulate(&bob_ciphertext, secret_key)
                .map_err(|err| Error::Other(err.to_string()))?
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
            Err(get_generic_error("Unable to get secret key"))
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
            Err(get_generic_error("Unable to get ciphertext"))
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
            Err(get_generic_error("Unable to get secret key"))
        }
    }
}

fn get_generic_error(text: &'static str) -> Error {
    Error::Generic(text)
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
            Self::Kyber => KYBER_NONCE_LENGTH_BYTES,
            Self::Ascon80pq => ASCON_NONCE_LENGTH_BYTES,
        }
    }

    // calculates the max ciphertext len given an input plaintext length
    fn max_ciphertext_len(&self, plaintext_length: usize, _sig_alg: SigAlgorithm) -> usize {
        const SYMMETRIC_CIPHER_OVERHEAD: usize = 16;
        match self {
            Self::AES_GCM_256 => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            // plaintext len + 128 bit tag
            Self::ChaCha20Poly_1305 => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            Self::Ascon80pq => plaintext_length + SYMMETRIC_CIPHER_OVERHEAD,
            // Add 32 for internal apendees
            Self::Kyber => {
                const LENGTH_FIELD: usize = 8;
                let signature_len = functions::signature_bytes();

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
            Self::Kyber => kyber_pke::plaintext_len(ciphertext),
        }
    }
}
