use crate::algorithm_dictionary::EncryptionAlgorithm;
use crate::encryption::kyber_module::KyberModule;
use crate::encryption::AeadModule;
use crate::{CryptoParameters, KeyStore, PQNode};
use aes_gcm_siv::KeyInit;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct KeyStoreIntermediate {
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
                pk_local: self.pk_local.clone(),
                pk_remote: self.pk_remote.clone(),
                sk_local: self.sk_local.clone(),
                pk_sig_remote: self.pk_sig_remote.clone(),
                sk_sig_local: self.sk_sig_local.clone(),
                pk_sig_local: self.pk_sig_local.clone(),
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
            int.pk_local.clone(),
            int.pk_remote.clone(),
            int.sk_local.clone(),
            int.params,
            int.pk_sig_remote.clone(),
            int.sk_sig_local.clone(),
            int.pk_sig_local.clone(),
            int.pq_node,
        );

        KeyStore {
            alice_module: alice_symmetric_key,
            bob_module: bob_symmetric_key,
            alice_key: int.alice_key,
            bob_key: int.bob_key,
            pk_local: int.pk_local,
            pk_remote: int.pk_remote,
            sk_local: int.sk_local,
            pk_sig_remote: int.pk_sig_remote,
            sk_sig_local: int.sk_sig_local,
            pk_sig_local: int.pk_sig_local,
            pq_node: PQNode::Alice,
            params: int.params,
        }
    }
}

pub(crate) fn keys_to_aead_store(
    alice: &GenericArray<u8, generic_array::typenum::U32>,
    bob: &GenericArray<u8, generic_array::typenum::U32>,
    pk_local: Arc<oqs::kem::PublicKey>,
    pk_remote: Arc<oqs::kem::PublicKey>,
    sk_local: Arc<oqs::kem::SecretKey>,
    params: CryptoParameters,
    pk_sig_remote: Arc<oqs::sig::PublicKey>,
    sk_sig_local: Arc<oqs::sig::SecretKey>,
    pk_sig_local: Arc<oqs::sig::PublicKey>,
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

            let keys = Box::new(KyberModule {
                kem_alg,
                sig_alg,
                pk_kem_remote: pk_remote,
                pk_kem_local: pk_local,
                sk_kem_local: sk_local,
                pk_sig_remote,
                sk_sig_local,
                pk_sig_local,
            }) as Box<dyn AeadModule>;

            // TODO: multi-modal ratcheted encryption
            match pq_node {
                PQNode::Alice => (Some(keys), None),
                PQNode::Bob => (None, Some(keys)),
            }
        }
    }
}
