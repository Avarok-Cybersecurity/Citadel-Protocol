//! The system's trusted roots: the whole store, or a named error.
//!
//! The OS can fail to read part of its store and still hand back the rest. On macOS, under heavy
//! I/O contention, `SecTrustSettingsCopyCertificates` failed with `errSecIO` (-36) for every trust
//! domain (#391). A store missing a domain verifies some servers and refuses others for no reason
//! a user could see, so a store read with errors is refused, by code, as is an empty one. Apple
//! does not document `errSecIO` as transient, so it is not retried.
//!
//! The OS store is read once per process ([`native_roots`]): every node in a process shares that
//! read, and its first error. Each node used to read it again at start-up, and many nodes starting
//! together in one process were what drove the store into `errSecIO`.

use crate::exports::Certificate;
use citadel_io::ErrorCode;
use std::io;
use std::sync::{LazyLock, OnceLock};

/// What one read of a root source produced: the certificates it gave, and every error it met.
#[derive(Clone, Debug, Default)]
pub struct LoadedRoots {
    pub certs: Vec<Certificate<'static>>,
    pub errors: Vec<String>,
}

/// Where the trusted roots come from.
pub trait RootSource {
    fn load(&self) -> LoadedRoots;
}

/// The operating system's store.
pub struct NativeRoots;

impl RootSource for NativeRoots {
    fn load(&self) -> LoadedRoots {
        let loaded = rustls_native_certs::load_native_certs();
        LoadedRoots {
            certs: loaded.certs,
            errors: loaded.errors.iter().map(ToString::to_string).collect(),
        }
    }
}

/// `source`, read once: every later read returns what the first one gave, errors included.
pub struct ReadOnce<S> {
    source: S,
    read: OnceLock<LoadedRoots>,
}

impl<S: RootSource> ReadOnce<S> {
    pub const fn new(source: S) -> Self {
        Self {
            source,
            read: OnceLock::new(),
        }
    }
}

impl<S: RootSource> RootSource for ReadOnce<S> {
    fn load(&self) -> LoadedRoots {
        self.read.get_or_init(|| self.source.load()).clone()
    }
}

/// The operating system's store, read once per process.
pub fn native_roots() -> &'static ReadOnce<NativeRoots> {
    static NATIVE: LazyLock<ReadOnce<NativeRoots>> = LazyLock::new(|| ReadOnce::new(NativeRoots));
    &NATIVE
}

/// The roots `source` gave, if it gave all of them.
pub fn trust_store(source: &impl RootSource) -> io::Result<Vec<Certificate<'static>>> {
    let loaded = source.load();
    let why = if !loaded.errors.is_empty() {
        loaded.errors.join("; ")
    } else if loaded.certs.is_empty() {
        "it holds no certificates".to_string()
    } else {
        return Ok(loaded.certs);
    };
    Err(io::Error::other(citadel_io::error!(
        ErrorCode::TrustStoreUnavailable,
        why
    )))
}

#[cfg(test)]
#[path = "trust_store_tests.rs"]
mod tests;
