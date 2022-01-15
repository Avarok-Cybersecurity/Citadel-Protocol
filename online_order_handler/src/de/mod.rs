use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::ops::{Deref, DerefMut};
use std::fmt::{Debug, Formatter};

pub struct GithubString {
    inner: String
}

impl Deref for GithubString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for GithubString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for GithubString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl<'de> Deserialize<'de> for GithubString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let output = serde_json::Value::deserialize(deserializer)?;
        let inner = match output {
            Value::Null => {
                "Null".to_string()
            }
            Value::Bool(val) => {
                val.to_string()
            }
            Value::Number(val) => { val.to_string() }
            Value::String(val) => { val }
            _ => {
                return Err(serde::de::Error::custom("List/Map inputs cannot be mapped to a String"))
            }
        };

        Ok(GithubString { inner })
    }
}