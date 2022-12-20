use crate::algorithm_dictionary::EncryptionAlgorithm;
use crate::encryption::kyber_module::KyberModule;
use crate::encryption::AeadModule;
use crate::{CryptoParameters, KeyStore, PQNode, PostQuantumMetaKex, PostQuantumMetaSig};
use aes_gcm_siv::KeyInit;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};

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

    impl<'de> Deserialize<'de> for KeyStore {
        fn deserialize<D>(d: D) -> Result<Self, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(KeyStore::from(
                KeyStoreIntermediate::deserialize(d)
                    .map_err(|_| serde::de::Error::custom("PQExport Deser err"))?
                    as KeyStoreIntermediate,
            ))
        }
    }
}

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
            pq_node: PQNode::Alice,
            params: int.params,
        }
    }
}

pub(crate) fn keys_to_aead_store(
    alice: &GenericArray<u8, generic_array::typenum::U32>,
    bob: &GenericArray<u8, generic_array::typenum::U32>,
    kex: &PostQuantumMetaKex,
    params: CryptoParameters,
    sig: Option<&PostQuantumMetaSig>,
    pq_node: PQNode,
) -> (Option<Box<dyn AeadModule>>, Option<Box<dyn AeadModule>>) {
    match params.encryption_algorithm {
        EncryptionAlgorithm::AES_GCM_256_SIV => (
            Some(Box::new(aes_gcm_siv::Aes256GcmSiv::new(alice))),
            Some(Box::new(aes_gcm_siv::Aes256GcmSiv::new(bob))),
        ),

        EncryptionAlgorithm::Xchacha20Poly_1305 => (
            Some(Box::new(chacha20poly1305::XChaCha20Poly1305::new(alice))),
            Some(Box::new(chacha20poly1305::XChaCha20Poly1305::new(bob))),
        ),

        EncryptionAlgorithm::Kyber => {
            let kem_alg = params.kem_algorithm;
            let sig_alg = params.sig_algorithm;

            let symmetric_key_local = match pq_node {
                PQNode::Alice => Box::new(aes_gcm_siv::Aes256GcmSiv::new(alice)),
                PQNode::Bob => Box::new(aes_gcm_siv::Aes256GcmSiv::new(bob)),
            };

            let symmetric_key_remote = match pq_node {
                PQNode::Alice => Box::new(aes_gcm_siv::Aes256GcmSiv::new(bob)),
                PQNode::Bob => Box::new(aes_gcm_siv::Aes256GcmSiv::new(alice)),
            };

            let keys = Box::new(KyberModule {
                kem_alg,
                sig_alg,
                kex: kex.clone(),
                sig: sig.cloned().unwrap(),
                symmetric_key_local,
                symmetric_key_remote,
            }) as Box<dyn AeadModule>;

            // TODO: multi-modal ratcheted encryption
            match pq_node {
                PQNode::Alice => (Some(keys), None),
                PQNode::Bob => (None, Some(keys)),
            }
        }
    }
}
