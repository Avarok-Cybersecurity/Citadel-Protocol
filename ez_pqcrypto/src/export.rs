use crate::algorithm_dictionary::EncryptionAlgorithm;
use crate::encryption::AeadModule;
use crate::KeyStore;
use chacha20poly1305::aead::NewAead;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct KeyStoreIntermediate {
    alice_key: GenericArray<u8, generic_array::typenum::U32>,
    bob_key: GenericArray<u8, generic_array::typenum::U32>,
    enx: EncryptionAlgorithm,
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
                enx: self.encryption_algorithm,
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
        let (alice_symmetric_key, bob_symmetric_key) =
            generic_array_to_key(&int.alice_key, &int.bob_key, int.enx);

        KeyStore {
            alice_symmetric_key,
            bob_symmetric_key,
            alice_key: int.alice_key,
            bob_key: int.bob_key,
            encryption_algorithm: int.enx,
        }
    }
}

pub(crate) fn generic_array_to_key(
    alice: &GenericArray<u8, generic_array::typenum::U32>,
    bob: &GenericArray<u8, generic_array::typenum::U32>,
    encryption_algorithm: EncryptionAlgorithm,
) -> (Box<dyn AeadModule>, Box<dyn AeadModule>) {
    match encryption_algorithm {
        EncryptionAlgorithm::AES_GCM_256_SIV => (
            Box::new(aes_gcm_siv::Aes256GcmSiv::new(alice)),
            Box::new(aes_gcm_siv::Aes256GcmSiv::new(bob)),
        ),

        EncryptionAlgorithm::Xchacha20Poly_1305 => (
            Box::new(chacha20poly1305::XChaCha20Poly1305::new(alice)),
            Box::new(chacha20poly1305::XChaCha20Poly1305::new(bob)),
        ),
    }
}
