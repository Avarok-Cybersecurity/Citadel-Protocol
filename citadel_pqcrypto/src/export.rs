/// Module for handling key store serialization and deserialization.
///
/// This module provides functionality for exporting and importing key stores,
/// which contain cryptographic keys and parameters used in the post-quantum
/// cryptographic protocol. It includes:
///
/// - Secure serialization of key material
/// - Custom serialization implementations
/// - Key conversion utilities
/// - AEAD module generation
///
/// # Security Considerations
///
/// - All sensitive key material is automatically zeroized when dropped
/// - Serialized data should be protected at rest (e.g., encrypted)
/// - Key stores should be regenerated periodically
/// - Node types (Alice/Bob) must be preserved during serialization
/// - Cryptographic parameters must match during deserialization
/// - AEAD modules are generated with appropriate key separation
/// - Local-user keys provide additional endpoint privacy
use crate::encryption::aes_impl::AesModule;
use crate::encryption::ascon_impl::AsconModule;
use crate::encryption::chacha_impl::ChaChaModule;
use crate::encryption::kyber_module::KyberModule;
use crate::encryption::AeadModule;
use crate::{KeyStore, PQNode, PostQuantumMetaKex, PostQuantumMetaSig};
use aes_gcm::KeyInit;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};

/// Intermediate structure for serializing and deserializing key stores.
///
/// This structure acts as a bridge between the in-memory representation of
/// a key store and its serialized form. It contains all the necessary
/// cryptographic parameters and keys.
///
/// # Fields
/// * `alice_key` - Alice's 32-byte key
/// * `bob_key` - Bob's 32-byte key
/// * `kex` - Post-quantum key exchange parameters
/// * `sig` - Optional post-quantum signature parameters
/// * `pq_node` - Node type (Alice or Bob)
/// * `params` - Cryptographic parameters
#[derive(Serialize, Deserialize)]
struct KeyStoreIntermediate {
    alice_key: GenericArray<u8, generic_array::typenum::U32>,
    bob_key: GenericArray<u8, generic_array::typenum::U32>,
    kex: PostQuantumMetaKex,
    sig: Option<PostQuantumMetaSig>,
    pq_node: PQNode,
    params: CryptoParameters,
}

pub(crate) mod custom_serde {
    use crate::export::KeyStoreIntermediate;
    use crate::KeyStore;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Custom serialization implementation for KeyStore.
    ///
    /// This implementation converts the KeyStore into an intermediate form
    /// that can be safely serialized and deserialized.
    impl Serialize for KeyStore {
        fn serialize<S>(&self, s: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
        {
            let intermediate_form = KeyStoreIntermediate {
                alice_key: self.alice_key,
                bob_key: self.bob_key,
                kex: self.kex.clone(),
                sig: self.sig.clone(),
                pq_node: self.pq_node,
                params: self.params,
            };
            KeyStoreIntermediate::serialize(&intermediate_form, s)
        }
    }

    /// Custom deserialization implementation for KeyStore.
    ///
    /// This implementation converts the intermediate form back into a
    /// fully functional KeyStore.
    impl<'de> Deserialize<'de> for KeyStore {
        fn deserialize<D>(d: D) -> Result<Self, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(KeyStore::from(
                KeyStoreIntermediate::deserialize(d)
                    .map_err(|_| serde::de::Error::custom("PQExport Deser err"))?,
            ))
        }
    }
}

/// Conversion implementation from KeyStoreIntermediate to KeyStore.
///
/// This implementation handles the conversion of the intermediate form
/// back into a fully functional KeyStore, including the creation of
/// appropriate AEAD modules based on the cryptographic parameters.
impl From<KeyStoreIntermediate> for KeyStore {
    fn from(int: KeyStoreIntermediate) -> Self {
        let (alice_symmetric_key, bob_symmetric_key) = keys_to_aead_store(
            &int.alice_key,
            &int.bob_key,
            &int.kex,
            int.params,
            int.sig.as_ref(),
            int.pq_node,
        );

        KeyStore {
            alice_module: alice_symmetric_key,
            bob_module: bob_symmetric_key,
            alice_key: int.alice_key,
            bob_key: int.bob_key,
            kex: int.kex,
            sig: int.sig,
            pq_node: int.pq_node,
            params: int.params,
        }
    }
}

/// Type alias for a pair of optional AEAD modules.
///
/// The first module is typically used for standard encryption/decryption,
/// while the second module is used for local-user-only operations.
pub type AeadStore = (Option<Box<dyn AeadModule>>, Option<Box<dyn AeadModule>>);

/// Converts keys and parameters into AEAD modules.
///
/// # Arguments
/// * `alice` - Alice's 32-byte key
/// * `bob` - Bob's 32-byte key
/// * `kex` - Post-quantum key exchange parameters
/// * `params` - Cryptographic parameters
/// * `sig` - Optional post-quantum signature parameters
/// * `pq_node` - Node type (Alice or Bob)
///
/// # Returns
/// A pair of optional AEAD modules for standard and local-user-only operations
pub(crate) fn keys_to_aead_store(
    alice: &GenericArray<u8, generic_array::typenum::U32>,
    bob: &GenericArray<u8, generic_array::typenum::U32>,
    kex: &PostQuantumMetaKex,
    params: CryptoParameters,
    sig: Option<&PostQuantumMetaSig>,
    pq_node: PQNode,
) -> AeadStore {
    match params.encryption_algorithm {
        EncryptionAlgorithm::AES_GCM_256 => {
            let symmetric_key_local = Box::new(AesModule {
                aead: aes_gcm::Aes256Gcm::new(alice),
                kex: kex.clone(),
            });

            let symmetric_key_remote = Box::new(AesModule {
                aead: aes_gcm::Aes256Gcm::new(bob),
                kex: kex.clone(),
            });

            (Some(symmetric_key_local), Some(symmetric_key_remote))
        }
        EncryptionAlgorithm::ChaCha20Poly_1305 => (
            Some(Box::new(ChaChaModule {
                aead: chacha20poly1305::ChaCha20Poly1305::new(alice),
                kex: kex.clone(),
            })),
            Some(Box::new(ChaChaModule {
                aead: chacha20poly1305::ChaCha20Poly1305::new(bob),
                kex: kex.clone(),
            })),
        ),
        EncryptionAlgorithm::Ascon80pq => {
            let alice_key = ascon_aead::Key::<ascon_aead::Ascon80pq>::from_slice(&alice[..20]);
            let bob_key = ascon_aead::Key::<ascon_aead::Ascon80pq>::from_slice(&bob[..20]);
            (
                Some(Box::new(AsconModule {
                    aead: ascon_aead::Ascon80pq::new(alice_key),
                    kex: kex.clone(),
                })),
                Some(Box::new(AsconModule {
                    aead: ascon_aead::Ascon80pq::new(bob_key),
                    kex: kex.clone(),
                })),
            )
        }

        EncryptionAlgorithm::KyberHybrid => {
            let kem_alg = params.kem_algorithm;
            let sig_alg = params.sig_algorithm;

            let (symmetric_key_local, symmetric_key_remote) =
                generate_symmetric_aes_module(pq_node, alice, bob, kex);

            let keys = Box::new(KyberModule {
                kem_alg,
                sig_alg,
                kex: kex.clone(),
                sig: sig.cloned().unwrap(),
                symmetric_key_local,
                symmetric_key_remote,
            }) as Box<dyn AeadModule>;

            match pq_node {
                PQNode::Alice => (Some(keys), None),
                PQNode::Bob => (None, Some(keys)),
            }
        }
    }
}

/// Generates symmetric AES modules for encryption/decryption.
///
/// # Arguments
/// * `pq_node` - Node type (Alice or Bob)
/// * `alice` - Alice's 32-byte key
/// * `bob` - Bob's 32-byte key
/// * `kex` - Post-quantum key exchange parameters
///
/// # Returns
/// A pair of AES modules for standard and local-user-only operations
fn generate_symmetric_aes_module(
    pq_node: PQNode,
    alice: &GenericArray<u8, generic_array::typenum::U32>,
    bob: &GenericArray<u8, generic_array::typenum::U32>,
    kex: &PostQuantumMetaKex,
) -> (Box<dyn AeadModule>, Box<dyn AeadModule>) {
    let symmetric_key_local = match pq_node {
        PQNode::Alice => Box::new(AesModule {
            aead: aes_gcm::Aes256Gcm::new(alice),
            kex: kex.clone(),
        }),
        PQNode::Bob => Box::new(AesModule {
            aead: aes_gcm::Aes256Gcm::new(bob),
            kex: kex.clone(),
        }),
    };

    let symmetric_key_remote = match pq_node {
        PQNode::Alice => Box::new(AesModule {
            aead: aes_gcm::Aes256Gcm::new(bob),
            kex: kex.clone(),
        }),
        PQNode::Bob => Box::new(AesModule {
            aead: aes_gcm::Aes256Gcm::new(alice),
            kex: kex.clone(),
        }),
    };

    (symmetric_key_local, symmetric_key_remote)
}
