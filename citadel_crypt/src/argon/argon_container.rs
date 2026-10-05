//! # Argon2id key stretching
//!
//! An asynchronous wrapper around Argon2id for the client's password factor
//! (`citadel_user::auth::pq::client::ksf`). Hashing runs on a blocking thread natively, and inline
//! on wasm32, which has no blocking pool.
//!
//! There is no verifier: a server proves a password factor by ML-KEM encapsulation, never by
//! comparing a hash, so nothing here checks a password.

use argon2::Config;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use futures::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::task::JoinError;
#[cfg(not(target_family = "wasm"))]
use tokio::task::JoinHandle;

/// Argon2id hashing off the caller's task.
pub struct AsyncArgon {
    /// for access to the handle as required
    #[cfg(not(target_family = "wasm"))]
    pub task: JoinHandle<ArgonStatus>,
    /// wasm32 has no blocking pool to hand the work to (and `spawn_blocking` panics without a
    /// tokio runtime), so the hash is computed when the future is created and handed back ready.
    #[cfg(target_family = "wasm")]
    status: Option<ArgonStatus>,
}

impl AsyncArgon {
    #[cfg(not(target_family = "wasm"))]
    fn run(work: impl FnOnce() -> ArgonStatus + Send + 'static) -> Self {
        Self {
            task: tokio::task::spawn_blocking(work),
        }
    }

    #[cfg(target_family = "wasm")]
    fn run(work: impl FnOnce() -> ArgonStatus) -> Self {
        Self {
            status: Some(work()),
        }
    }

    pub fn hash(password: SecBuffer, settings: ArgonSettings) -> Self {
        Self::run(move || {
            match argon2::hash_raw(
                password.as_ref(),
                settings.inner.salt.as_slice(),
                &settings.as_argon_config(),
            ) {
                Ok(hashed) => ArgonStatus::HashSuccess(SecBuffer::from(hashed)),
                Err(err) => ArgonStatus::HashFailed(err.to_string()),
            }
        })
    }
}

#[derive(Clone, Debug)]
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
}

impl Deref for ArgonSettings {
    type Target = ArgonSettingsInner;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

#[derive(Debug)]
pub struct ArgonSettingsInner {
    pub ad: Vec<u8>,
    pub salt: Vec<u8>,
    pub lanes: u32,
    pub hash_length: u32,
    pub mem_cost: u32,
    pub time_cost: u32,
    pub secret: Vec<u8>,
}

#[cfg(feature = "std")]
const THREAD_MODE: argon2::ThreadMode = argon2::ThreadMode::Parallel;

#[cfg(not(feature = "std"))]
const THREAD_MODE: argon2::ThreadMode = argon2::ThreadMode::Sequential;

impl ArgonSettings {
    /// Converts to an acceptable struct for argon2
    pub fn as_argon_config(&self) -> Config<'_> {
        Config {
            ad: self.inner.ad.as_slice(),
            hash_length: self.inner.hash_length,
            lanes: self.inner.lanes,
            mem_cost: self.inner.mem_cost,
            secret: self.inner.secret.as_slice(),
            time_cost: self.inner.time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            thread_mode: THREAD_MODE,
        }
    }
}

#[derive(Debug)]
pub enum ArgonStatus {
    HashSuccess(SecBuffer),
    HashFailed(String),
}

impl Future for AsyncArgon {
    type Output = Result<ArgonStatus, JoinError>;

    #[cfg(not(target_family = "wasm"))]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }

    #[cfg(target_family = "wasm")]
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(self
            .status
            .take()
            .expect("AsyncArgon polled after completion")))
    }
}
