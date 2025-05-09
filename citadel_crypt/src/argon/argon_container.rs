//! # Argon2 Password Hashing Container
//!
//! This module provides a secure, asynchronous wrapper around the Argon2 password hashing
//! algorithm. It implements both client-side and server-side password handling with
//! configurable parameters and secure memory management.
//!
//! ## Features
//! - Asynchronous password hashing and verification
//! - Configurable Argon2id parameters (memory, time, parallelism)
//! - Secure memory handling with SecBuffer
//! - Automatic salt generation
//! - Support for associated data and secret keys
//! - Client and server container types
//!
//! ## Usage Example
//! ```rust
//! use citadel_crypt::argon::argon_container::{ServerArgonContainer, ArgonSettings, ClientArgonContainer, AsyncArgon};
//! use citadel_types::crypto::SecBuffer;
//!
//! async fn hash_password() {
//!     // Create settings with default parameters
//!     let settings = ArgonSettings::new_defaults(vec![1, 2, 3]); // Associated data
//!     
//!     // Create client container
//!     let client = ClientArgonContainer::from(settings);
//!     
//!     // Hash a password
//!     let password = SecBuffer::from("my_secure_password");
//!     let hashed = client.hash_insecure_input(password).await.unwrap();
//!     
//!     // Verify a password (server-side)
//!     let server_container = ServerArgonContainer::new(
//!         client.settings.clone(),
//!         hashed
//!     );
//!     
//!     let verify_result = AsyncArgon::verify(
//!         SecBuffer::from("my_secure_password"),
//!         server_container
//!     ).await.unwrap();
//! }
//! ```
//!
//! ## Important Notes
//! - Uses Argon2id variant for optimal security
//! - Memory-hard algorithm with configurable cost parameters
//! - Handles password hashing on blocking threads
//! - Provides secure memory zeroing through SecBuffer
//! - Supports custom associated data for domain separation
//!
//! ## Related Components
//! - [`SecBuffer`](citadel_types::crypto::SecBuffer): Secure memory management
//! - [`AsyncArgon`]: Asynchronous hashing interface
//! - [`ArgonSettings`]: Configuration parameters
//! - Argon2 password hashing algorithm

use argon2::Config;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use futures::Future;
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::task::{JoinError, JoinHandle};

const ARGON_SALT_LENGTH: usize = 16;

// A wrapper that allows asynchronous hashing and verification
pub struct AsyncArgon {
    /// for access to the handle as required
    pub task: JoinHandle<ArgonStatus>,
}

impl AsyncArgon {
    pub fn hash(password: SecBuffer, settings: ArgonSettings) -> Self {
        let task = tokio::task::spawn_blocking(move || {
            match argon2::hash_raw(
                password.as_ref(),
                settings.inner.salt.as_slice(),
                &settings.as_argon_config(),
            ) {
                Ok(hashed) => ArgonStatus::HashSuccess(SecBuffer::from(hashed)),
                Err(err) => ArgonStatus::HashFailed(err.to_string()),
            }
        });

        Self { task }
    }

    pub fn verify(proposed_password: SecBuffer, settings: ServerArgonContainer) -> Self {
        let task = tokio::task::spawn_blocking(move || {
            match argon2::verify_raw(
                proposed_password.as_ref(),
                settings.settings.inner.salt.as_slice(),
                settings.hashed_password.as_ref(),
                &settings.settings.as_argon_config(),
            ) {
                Ok(true) => ArgonStatus::VerificationSuccess,

                Ok(false) => ArgonStatus::VerificationFailed(None),

                Err(err) => ArgonStatus::VerificationFailed(Some(err.to_string())),
            }
        });

        Self { task }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ArgonSettings {
    inner: Arc<ArgonSettingsInner>,
}

impl ArgonSettings {
    pub fn new(
        ad: Vec<u8>,
        salt: Vec<u8>,
        lanes: u32,
        hash_length: u32,
        mem_cost: u32,
        time_cost: u32,
        secret: Vec<u8>,
    ) -> Self {
        Self {
            inner: Arc::new(ArgonSettingsInner {
                ad,
                salt,
                lanes,
                hash_length,
                mem_cost,
                time_cost,
                secret,
            }),
        }
    }

    /// Creates a new instance with default values and no secret
    pub fn new_defaults(ad: Vec<u8>) -> Self {
        Self::new_defaults_with_static_secret(ad, vec![])
    }

    /// Creates a new instance with default values and custom secret
    pub fn new_defaults_with_static_secret(ad: Vec<u8>, secret: Vec<u8>) -> Self {
        Self::new_gen_salt(
            ad,
            DEFAULT_LANES,
            DEFAULT_HASH_LENGTH,
            DEFAULT_MEM_COST,
            DEFAULT_TIME_COST,
            secret,
        )
    }

    /// Takes the internal config, then
    pub fn derive_new_with_custom_ad(&self, ad: Vec<u8>) -> Self {
        Self::new_gen_salt(
            ad,
            self.lanes,
            self.hash_length,
            self.mem_cost,
            self.time_cost,
            self.secret.clone(),
        )
    }

    pub fn new_gen_salt(
        ad: Vec<u8>,
        lanes: u32,
        hash_length: u32,
        mem_cost: u32,
        time_cost: u32,
        secret: Vec<u8>,
    ) -> Self {
        Self::new(
            ad,
            Self::generate_salt().to_vec(),
            lanes,
            hash_length,
            mem_cost,
            time_cost,
            secret,
        )
    }

    fn generate_salt() -> [u8; ARGON_SALT_LENGTH] {
        let mut rng = ThreadRng::default();
        let mut salt: [u8; ARGON_SALT_LENGTH] = Default::default();
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
    pub secret: Vec<u8>,
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
            time_cost: self.inner.time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        }
    }
}

impl Default for ArgonSettings {
    fn default() -> Self {
        ArgonSettings::new_defaults(vec![])
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ClientArgonContainer {
    pub settings: ArgonSettings,
}

impl From<ArgonSettings> for ClientArgonContainer {
    fn from(settings: ArgonSettings) -> Self {
        Self { settings }
    }
}

impl ClientArgonContainer {
    pub async fn hash_insecure_input(&self, input: SecBuffer) -> Option<SecBuffer> {
        match AsyncArgon::hash(input, self.settings.clone()).await.ok()? {
            ArgonStatus::HashSuccess(ret) => Some(ret),
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerArgonContainer {
    settings: ArgonSettings,
    hashed_password: SecBuffer,
}

impl ServerArgonContainer {
    pub fn new(settings: ArgonSettings, hashed_password: SecBuffer) -> Self {
        Self {
            settings,
            hashed_password,
        }
    }
}

#[derive(Debug)]
pub enum ArgonStatus {
    HashSuccess(SecBuffer),
    HashFailed(String),
    VerificationSuccess,
    VerificationFailed(Option<String>),
}

#[derive(Clone, Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum ArgonContainerType {
    Client(ClientArgonContainer),
    Server(ServerArgonContainer),
}

impl ArgonContainerType {
    pub fn client(&self) -> Option<&ClientArgonContainer> {
        match self {
            Self::Client(cl) => Some(cl),
            _ => None,
        }
    }

    pub fn server(&self) -> Option<&ServerArgonContainer> {
        match self {
            Self::Server(sv) => Some(sv),
            _ => None,
        }
    }

    pub fn settings(&self) -> &ArgonSettings {
        match self {
            Self::Client(cl) => &cl.settings,
            Self::Server(sv) => &sv.settings,
        }
    }
}

impl Future for AsyncArgon {
    type Output = Result<ArgonStatus, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

const DEFAULT_LANES: u32 = 8;
pub const DEFAULT_HASH_LENGTH: u32 = 32;
#[cfg(not(debug_assertions))]
const DEFAULT_MEM_COST: u32 = 1024 * 64;
#[cfg(debug_assertions)]
const DEFAULT_MEM_COST: u32 = 1024;
#[cfg(not(debug_assertions))]
const DEFAULT_TIME_COST: u32 = 10;
#[cfg(debug_assertions)]
const DEFAULT_TIME_COST: u32 = 1;

#[derive(Debug, Clone)]
pub struct ArgonDefaultServerSettings {
    pub lanes: u32,
    pub hash_length: u32,
    pub mem_cost: u32,
    pub time_cost: u32,
    pub secret: Vec<u8>,
}

impl From<ArgonDefaultServerSettings> for ArgonSettings {
    fn from(settings: ArgonDefaultServerSettings) -> Self {
        // AD gets created when deriving a new settings container for the specific user during registration
        Self::new_gen_salt(
            vec![],
            settings.lanes,
            settings.hash_length,
            settings.mem_cost,
            settings.time_cost,
            settings.secret,
        )
    }
}

impl Default for ArgonDefaultServerSettings {
    fn default() -> Self {
        Self {
            lanes: DEFAULT_LANES,
            hash_length: DEFAULT_HASH_LENGTH,
            mem_cost: DEFAULT_MEM_COST,
            time_cost: DEFAULT_TIME_COST,
            secret: vec![],
        }
    }
}
