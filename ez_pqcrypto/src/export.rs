use crate::{PostQuantumContainer, PQNode};
use serde::{Serialize, Deserialize};

/// The default type to store data from a [PostQuantumContainer]
#[derive(Serialize, Deserialize)]
pub struct PostQuantumExport {
    pub(super) algorithm: u8,
    pub(super) public_key: Vec<u8>,
    pub(super) secret_key: Option<Vec<u8>>,
    pub(super) ciphertext: Option<Vec<u8>>,
    pub(super) shared_secret: Option<Vec<u8>>,
    pub(super) ara: Vec<u8>,
    pub(super) node: u8
}

impl From<&'_ PostQuantumContainer> for PostQuantumExport {
    fn from(container: &PostQuantumContainer) -> Self {
        let algorithm = container.algorithm;
        let node = if container.node == PQNode::Alice {
            0u8
        } else {
            1u8
        };

        let public_key = container.get_public_key().to_vec();
        let secret_key = container.get_secret_key().map(|res| res.to_vec()).ok();
        let ciphertext = container.get_ciphertext().map(|res| res.to_vec()).ok();
        let shared_secret = container.get_shared_secret().map(|res| res.to_vec()).ok();
        let ara = bincode2::serialize(&container.anti_replay_attack).unwrap();

        Self { algorithm, public_key, secret_key, ciphertext, shared_secret, ara, node }
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