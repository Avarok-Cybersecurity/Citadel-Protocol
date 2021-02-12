use std::fmt::Display;
use serde::{Serialize, Deserialize, Serializer};

/// This will be interpreted via JSON deserialization. All binary must be in base64
///
/// We place u64's in Strings to ensure that different programming languages can fit the values. E.g., dart does not have u64's
#[derive(Serialize, Deserialize)]
pub struct FCMMessagePayload {
    #[serde(serialize_with = "string")]
    session_cid: u64,
    #[serde(serialize_with = "string")]
    target_cid: u64,
    drill_version: u32,
    #[serde(serialize_with = "base64_string")]
    encrypted_message: String,
    #[serde(serialize_with = "base64_string")]
    re_key_bin: String
}

impl FCMMessagePayload {
    pub fn new<T: AsRef<[u8]>, R: AsRef<[u8]>>(session_cid: u64, target_cid: u64, drill_version: u32, encrypted_message: T, re_key_bin: R) -> Self {
        Self {
            session_cid,
            target_cid,
            drill_version,
            encrypted_message: base64::encode(encrypted_message),
            re_key_bin: base64::encode(re_key_bin)
        }
    }

    pub fn serialize_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_str<T: AsRef<str>>(input: T) -> Option<FCMMessagePayload> {
        serde_json::from_str(input.as_ref()).ok()
    }
}

pub fn string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: Display,
          S: Serializer
{
    serializer.collect_str(value)
}

pub fn base64_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: AsRef<[u8]>,
          S: Serializer
{
    serializer.collect_str(&base64::encode(value))
}