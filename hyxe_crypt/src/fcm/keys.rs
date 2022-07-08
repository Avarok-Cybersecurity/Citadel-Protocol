use serde::__private::Formatter;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct FcmKeys {
    inner: Arc<FcmKeysInner>,
}

impl FcmKeys {
    pub fn new<T: Into<String>, R: Into<String>>(api_key: T, client_id: R) -> Self {
        Self {
            inner: Arc::new(FcmKeysInner {
                client_id: client_id.into(),
                api_key: api_key.into(),
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FcmKeysInner {
    pub client_id: String,
    pub api_key: String,
}

impl Deref for FcmKeys {
    type Target = FcmKeysInner;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl std::fmt::Debug for FcmKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "api key: {} || client ID: : {}",
            &self.api_key, &self.client_id
        )
    }
}
