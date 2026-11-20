//! The system's trusted roots: the whole store, or a named error.
//!
//! The OS can fail to read part of its store and still hand back the rest. On macOS, under heavy
//! I/O contention, `SecTrustSettingsCopyCertificates` failed with `errSecIO` (-36) for every trust
//! domain (#391). A store missing a domain verifies some servers and refuses others for no reason
//! a user could see, so a store read with errors is refused, by code, as is an empty one. Apple
//! does not document `errSecIO` as transient, so it is not retried.

use crate::exports::Certificate;
use citadel_io::ErrorCode;
use std::io;

/// What one read of a root source produced: the certificates it gave, and every error it met.
#[derive(Debug, Default)]
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
