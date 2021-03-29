use std::pin::Pin;
use futures::Future;
use tokio::task::{JoinHandle, JoinError};
use std::task::{Context, Poll};
use serde::{Serialize, Deserialize};
use argon2::Config;
use std::sync::Arc;
use crate::prelude::SecBuffer;
use std::ops::Deref;
use crate::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use rand::rngs::ThreadRng;
use rand::Rng;

// A wrapper that allows asynchronous hashing and verification
pub struct AsyncArgon {
    task: JoinHandle<ArgonStatus>
}

impl AsyncArgon {
    pub fn hash(password: SecBuffer, settings: ArgonSettings) -> Self {
        let task = tokio::task::spawn_blocking(move || {
            match argon2::hash_raw(password.as_ref(), settings.inner.salt.as_slice(), &settings.as_argon_config()) {
                Ok(hashed) => ArgonStatus::HashSuccess(SecBuffer::from(hashed)),
                Err(err) => ArgonStatus::HashFailed(err.to_string())
            }
        });

        Self { task }
    }

    pub fn verify(proposed_password: SecBuffer, settings: ServerArgonContainer) -> Self {
        let task = tokio::task::spawn_blocking( move || {
            match argon2::verify_raw(proposed_password.as_ref(), settings.settings.inner.salt.as_slice(), settings.hashed_password.as_ref(), &settings.settings.as_argon_config()) {
                Ok(true) => {
                    ArgonStatus::VerificationSuccess
                }

                Ok(false) => {
                    ArgonStatus::VerificationFailed(None)
                }

                Err(err) => {
                    ArgonStatus::VerificationFailed(Some(err.to_string()))
                }
            }
        });

        Self { task }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ArgonSettings {
    inner: Arc<ArgonSettingsInner>
}

impl ArgonSettings {
    pub fn new(ad: Vec<u8>, salt: Vec<u8>, lanes: u32, hash_length: u32, mem_cost: u32, time_cost: u32, secret: Vec<u8>) -> Self {
        Self { inner: Arc::new(ArgonSettingsInner {
            ad,
            salt,
            lanes,
            hash_length,
            mem_cost,
            time_cost,
            secret
        })}
    }

    pub fn new_defaults(ad: Vec<u8>) -> Self {
        #[cfg(debug_assertions)]
            {
                Self::new_gen_salt(ad, 8, 32, 1024 * 64, 1, vec![])
            }

        #[cfg(not(debug_assertions))]
            {
                Self::new_gen_salt(ad, 8, 32, 1024 * 64, 10, vec![])
            }
    }

    pub fn new_gen_salt(ad: Vec<u8>, lanes: u32, hash_length: u32, mem_cost: u32, time_cost: u32, secret: Vec<u8>) -> Self {
        Self::new(ad, Self::generate_salt().to_vec(), lanes, hash_length, mem_cost, time_cost, secret)
    }

    fn generate_salt() -> [u8; AES_GCM_NONCE_LEN_BYTES] {
        let mut rng = ThreadRng::default();
        let mut salt: [u8; AES_GCM_NONCE_LEN_BYTES] = Default::default();
        rng.fill(&mut salt);
        salt
    }
}

impl Deref for ArgonSettings {
    type Target = ArgonSettingsInner;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ArgonSettingsInner {
    pub ad: Vec<u8>,
    pub salt: Vec<u8>,
    pub lanes: u32,
    pub hash_length: u32,
    pub mem_cost: u32,
    pub time_cost: u32,
    pub secret: Vec<u8>
}

impl ArgonSettings {
    /// Converts to an acceptable struct for argon2
    pub fn as_argon_config(&self) -> Config {
        Config {
            ad: self.inner.ad.as_slice(),
            hash_length: self.inner.hash_length,
            lanes: self.inner.lanes,
            mem_cost: self.inner.mem_cost,
            secret: self.inner.secret.as_slice(),
            thread_mode: argon2::ThreadMode::Parallel,
            time_cost: self.inner.time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientArgonContainer {
    pub settings: ArgonSettings
}

impl From<ArgonSettings> for ClientArgonContainer {
    fn from(settings: ArgonSettings) -> Self {
        Self { settings }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerArgonContainer {
    settings: ArgonSettings,
    hashed_password: SecBuffer
}

impl ServerArgonContainer {
    pub fn new(settings: ArgonSettings, hashed_password: SecBuffer) -> Self {
        Self { settings, hashed_password }
    }
}

#[derive(Debug)]
pub enum ArgonStatus {
    HashSuccess(SecBuffer),
    HashFailed(String),
    VerificationSuccess,
    VerificationFailed(Option<String>)
}

#[derive(Clone, Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum ArgonContainerType {
    Client(ClientArgonContainer),
    Server(ServerArgonContainer)
}

impl Future for AsyncArgon {
    type Output = Result<ArgonStatus, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}