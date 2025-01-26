//! Certificate Format Conversion Utilities
//!
//! This module provides utilities for converting between different certificate
//! and key formats, particularly focusing on PKCS#12 to QUIC-compatible formats.
//! It handles the complexities of certificate chain management and private key
//! conversion.
//!
//! ## Example
//!
//! ```rust,no_run
//! use citadel_wire::misc;
//! use anyhow::Result;
//! use std::path::Path;
//!
//! async fn example() -> Result<()> {
//!     // Read PKCS#12 file and convert to QUIC keys
//!     let (certs, key) = misc::read_pkcs_12_der_to_quinn_keys(
//!         "cert.p12",
//!         "password"
//!     )?;
//!
//!     // Convert individual DER files
//!     let cert_der = std::fs::read("cert.der")?;
//!     let key_der = std::fs::read("key.der")?;
//!     let (cert, key) = misc::cert_and_priv_key_der_to_quic_keys(
//!         &cert_der,
//!         &key_der
//!     )?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - PKCS#12 DER file parsing
//! - Certificate chain extraction
//! - Private key conversion
//! - QUIC-compatible format generation
//! - OpenSSL to Rustls conversion
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::misc;
//!
//! fn convert_certificates() -> Result<(), anyhow::Error> {
//!     // Read PKCS#12 file and convert to QUIC keys
//!     let (certs, key) = misc::read_pkcs_12_der_to_quinn_keys(
//!         "cert.p12",
//!         "password"
//!     )?;
//!
//!     // Convert individual DER files
//!     let cert_der = std::fs::read("cert.der")?;
//!     let key_der = std::fs::read("key.der")?;
//!     let (cert, key) = misc::cert_and_priv_key_der_to_quic_keys(
//!         &cert_der,
//!         &key_der
//!     )?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - PKCS#12 passwords must be UTF-8
//! - Certificate chains are preserved
//! - DER format is required for input
//! - Memory safety is maintained
//! - OpenSSL types are used internally
//!
//! # Related Components
//!
//! - [`crate::standard::tls`] - TLS configuration
//! - [`crate::standard::quic`] - QUIC protocol support
//! - [`crate::exports::Certificate`] - Certificate types
//! - [`crate::exports::PrivateKey`] - Key management
//!

use crate::exports::{Certificate, PrivateKey};
use openssl::pkcs12::ParsedPkcs12_2 as ParsedPkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;
use std::path::Path;

pub fn read_pkcs_12_der_to_quinn_keys<P: AsRef<Path>>(
    path: P,
    password: &str,
) -> Result<(Vec<Certificate<'static>>, PrivateKey<'static>), anyhow::Error> {
    let der = std::fs::read(path)?;
    pkcs12_to_quinn_keys(&der, password)
}

pub type Pkcs12Decomposed = (Option<Stack<X509>>, X509, PKey<Private>);

pub fn pkcs12_to_components(
    pkcs12_der: &[u8],
    password: &str,
) -> Result<Pkcs12Decomposed, anyhow::Error> {
    let openssl_pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12_der)?;
    let ParsedPkcs12 { ca, cert, pkey } = openssl_pkcs12.parse2(password)?;
    Ok((
        ca,
        cert.ok_or_else(|| anyhow::Error::msg("Certificate missing from Pkcs12"))?,
        pkey.ok_or_else(|| anyhow::Error::msg("Private key missing from Pkcs12"))?,
    ))
}

pub fn pkcs12_to_quinn_keys(
    pkcs12_der: &[u8],
    password: &str,
) -> Result<(Vec<Certificate<'static>>, PrivateKey<'static>), anyhow::Error> {
    let (chain, cert, pkey) = pkcs12_to_components(pkcs12_der, password)?;
    pkcs_12_components_to_quic_keys(chain.as_ref(), &cert, &pkey)
}

pub fn pkcs_12_components_to_quic_keys(
    chain: Option<&Stack<X509>>,
    cert: &X509,
    pkey: &PKey<Private>,
) -> Result<(Vec<Certificate<'static>>, PrivateKey<'static>), anyhow::Error> {
    let (cert, key) =
        cert_and_priv_key_der_to_quic_keys(&cert.to_der()?, &pkey.private_key_to_der()?)?;

    let mut certs = Vec::new();
    certs.push(cert);

    if let Some(chain) = chain {
        for cert in chain {
            certs.push(Certificate::from(cert.to_der()?));
        }
    }

    Ok((certs, key))
}

pub fn cert_and_priv_key_der_to_quic_keys(
    cert_der: &[u8],
    priv_key_der: &[u8],
) -> Result<(Certificate<'static>, PrivateKey<'static>), anyhow::Error> {
    let key = PrivateKey::try_from(priv_key_der.to_vec()).map_err(|err| {
        anyhow::Error::msg(format!(
            "Failed to convert private key to PrivateKey: {err}"
        ))
    })?;
    let cert = Certificate::from(cert_der.to_vec());
    Ok((cert, key))
}
