use crate::{PostQuantumContainer, PQNode};
use serde::{Serialize, Deserialize};
use crate::algorithm_dictionary::CryptoParameters;

/// The default type to store data from a [PostQuantumContainer]
#[derive(Serialize, Deserialize)]
pub struct PostQuantumExport {
    pub(super) params: CryptoParameters,
    pub(super) public_key: Vec<u8>,
    pub(super) secret_key: Option<Vec<u8>>,
    pub(super) ciphertext: Option<Vec<u8>>,
    pub(super) shared_secret: Option<Vec<u8>>,
    pub(super) ara: Vec<u8>,
    pub(super) node: PQNode
}

impl From<&'_ PostQuantumContainer> for PostQuantumExport {
    fn from(container: &PostQuantumContainer) -> Self {
        let params = container.params;
        let node = container.node;

        let public_key = container.get_public_key().to_vec();
        let secret_key = container.get_secret_key().map(|res| res.to_vec()).ok();
        let ciphertext = container.get_ciphertext().map(|res| res.to_vec()).ok();
        let shared_secret = container.get_shared_secret().map(|res| res.to_vec()).ok();
        let ara = bincode2::serialize(&container.anti_replay_attack).unwrap();

        Self { params, public_key, secret_key, ciphertext, shared_secret, ara, node }
    }
}

pub(crate) mod custom_serde {
    use crate::PostQuantumContainer;
    use serde::{Serializer, Serialize, Deserializer, Deserialize};
    use crate::export::PostQuantumExport;
    use std::convert::TryFrom;

    impl Serialize for PostQuantumContainer {
        fn serialize<S>(&self, s: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {
            let intermediate_form = PostQuantumExport::from(self);
            PostQuantumExport::serialize(&intermediate_form, s)
        }
    }

    impl<'de> Deserialize<'de> for PostQuantumContainer {
        fn deserialize<D>(d: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
            D: Deserializer<'de> {
            Ok(PostQuantumContainer::try_from(PostQuantumExport::deserialize(d).map_err(|_| serde::de::Error::custom("Deser err"))? as PostQuantumExport).map_err(|_| serde::de::Error::custom("Deser err"))?)
        }
    }
}