use serde::{Serialize, Deserialize};
use hyxe_user::client_account::ClientNetworkAccount;

/// This will be interpreted via JSON deserialization. All binary must be in base64
///
/// We place u64's in Strings to ensure that different programming languages can fit the values. E.g., dart does not have u64's
#[derive(Serialize, Deserialize)]
pub struct FCMMessagePayload {
    #[serde(with = "string")]
    pub session_cid: u64,
    #[serde(with = "string")]
    pub target_cid: u64,
    #[serde(with = "string")]
    pub group_id: u64,
    #[serde(with = "string")]
    pub drill_version: u32,
    #[serde(with = "base64_string")]
    pub encrypted_message: Vec<u8>,
    #[serde(with = "base64_string")]
    pub re_key_bin: Vec<u8>
}

impl FCMMessagePayload {
    pub fn new(session_cid: u64, target_cid: u64, group_id: u64, drill_version: u32, encrypted_message: Vec<u8>, re_key_bin: Vec<u8>) -> Self {
        Self {
            session_cid,
            target_cid,
            group_id,
            drill_version,
            encrypted_message,
            re_key_bin
        }
    }

    /// Supply the CNAC of the target cid here, not the session CID
    pub fn decrypt_message(&self, cnac: &ClientNetworkAccount) -> Option<Vec<u8>> {
        if cnac.get_cid() == self.target_cid {
            cnac.visit(|inner| {
                let endpoint_container = inner.fcm_crypt_container.get(&self.session_cid)?;
                let fcm_hr = endpoint_container.get_hyper_ratchet(Some(self.drill_version))?;
                fcm_hr.decrypt_custom(0, self.group_id, &self.encrypted_message).ok()
            })
        } else {
            log::warn!("[FCM] CNAC CID != target cid");
            None
        }
    }

    pub fn serialize_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_str<T: AsRef<str>>(input: T) -> Option<FCMMessagePayload> {
        serde_json::from_str(input.as_ref()).ok()
    }
}

mod string {
    use std::fmt::Display;
    use serde::{Serializer, Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where T: Display,
              S: Serializer
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D, T>(value: D) -> Result<T, D::Error> where D: Deserializer<'de>, T: FromStr {
        T::from_str(&String::deserialize(value).map_err(|_| serde::de::Error::custom("Deser err"))?).map_err(|_| serde::de::Error::custom("Deser err"))
    }
}


mod base64_string {
    use serde::{Serializer, Deserializer, Deserialize};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where T: AsRef<[u8]>,
              S: Serializer
    {
        serializer.collect_str(&base64::encode(value))
    }

    pub fn deserialize<'de, D>(value: D) -> Result<Vec<u8>, D::Error> where D: Deserializer<'de> {
        base64::decode(String::deserialize(value).map_err(|_| serde::de::Error::custom("Deser err"))?).map_err(|_| serde::de::Error::custom("Deser err"))
    }
}
