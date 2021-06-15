use crate::{PostQuantumContainer, PQNode, AntiReplayAttackContainer, PostQuantumType};
use serde::{Deserialize, Deserializer, Serialize};
use crate::algorithm_dictionary::CryptoParameters;
use crate::encryption::AeadModule;

#[derive(Serialize, Deserialize)]
struct PostQuantumExport {
    pub params: CryptoParameters,
    pub(crate) data: Box<dyn PostQuantumType>,
    pub(crate) anti_replay_attack: AntiReplayAttackContainer,
    #[serde(skip)]
    pub(crate) shared_secret: Option<Box<dyn AeadModule>>,
    pub(crate) node: PQNode
}

impl From<PostQuantumExport> for PostQuantumContainer {
    fn from(this: PostQuantumExport) -> Self {
        Self {
            params: this.params,
            data: this.data,
            anti_replay_attack: this.anti_replay_attack,
            shared_secret: this.shared_secret,
            node: this.node
        }
    }
}

impl<'de> Deserialize<'de> for PostQuantumContainer {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {

        let mut intermediate = PostQuantumExport::deserialize(deserializer)?;

        // shared secret may not be loaded yet
        if let Ok(ss) = intermediate.data.get_shared_secret() {
            intermediate.shared_secret = Some(PostQuantumContainer::get_aes_gcm_key(intermediate.params.encryption_algorithm, ss).map_err(|err| serde::de::Error::custom(err.to_string()))?)
        }

        Ok(PostQuantumContainer::from(intermediate))
    }
}

/*
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
            Ok(PostQuantumContainer::try_from(PostQuantumExport::deserialize(d).map_err(|_| serde::de::Error::custom("PQExport Deser err"))? as PostQuantumExport).map_err(|_| serde::de::Error::custom("PQC Deser err"))?)
        }
    }
}*/