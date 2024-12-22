//! TLS Configuration and Certificate Management
//!
//! This module provides TLS (Transport Layer Security) configuration utilities with
//! support for both traditional TLS and QUIC protocols. It handles certificate
//! management, validation, and secure connection establishment with flexible
//! security options.
//!
//! # Features
//!
//! - TLS and QUIC configuration interoperability
//! - Self-signed certificate generation
//! - PKCS#12 certificate support
//! - Native system certificate loading
//! - Custom certificate validation
//! - Async/await support with Tokio
//! - Rustls-based implementation
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::tls;
//!
//! async fn setup_tls() -> Result<(), anyhow::Error> {
//!     // Create self-signed server config
//!     let server_config = tls::create_server_self_signed_config()?;
//!     
//!     // Load system certificates
//!     let certs = tls::load_native_certs_async().await?;
//!     
//!     // Create secure client config
//!     let client_config = tls::create_client_config(&certs).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Native cert loading is expensive (~200ms)
//! - Self-signed certs use 'localhost' domain
//! - PKCS#12 passwords must be UTF-8
//! - Supports TLS 1.2 and 1.3
//! - Certificate chain validation is configurable
//!
//! # Related Components
//!
//! - [`crate::quic`] - QUIC protocol support
//! - [`crate::exports::Certificate`] - Certificate types
//! - [`crate::exports::PrivateKey`] - Key management
//! - [`crate::socket_helpers`] - Socket utilities
//!

use crate::exports::{Certificate, PrivateKey};
use crate::quic::generate_self_signed_cert;
use rustls::{ClientConfig, RootCertStore};
use std::io::Error;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Useful for allowing migration from a TLS config to a QUIC config in the citadel_proto crate
pub struct TLSQUICInterop {
    pub tls_acceptor: TlsAcceptor,
    pub quic_chain: Vec<Certificate<'static>>,
    pub quic_priv_key: PrivateKey<'static>,
}

impl Clone for TLSQUICInterop {
    fn clone(&self) -> Self {
        TLSQUICInterop {
            tls_acceptor: self.tls_acceptor.clone(),
            quic_chain: self.quic_chain.clone(),
            quic_priv_key: self.quic_priv_key.clone_key(),
        }
    }
}

pub fn create_client_dangerous_config() -> TlsConnector {
    TlsConnector::from(Arc::new(crate::quic::insecure::rustls_client_config()))
}

pub async fn create_client_self_signed_config() -> Result<ClientConfig, anyhow::Error> {
    let native_certs = load_native_certs_async().await?;
    create_rustls_client_config(&native_certs)
}

pub fn create_rustls_client_config<T: AsRef<[u8]>>(
    allowed_certs: &[T],
) -> Result<ClientConfig, anyhow::Error> {
    cert_vec_to_secure_client_config(
        &allowed_certs
            .iter()
            .map(|r| crate::exports::Certificate::from(r.as_ref().to_vec()))
            .collect(),
    )
}

pub fn cert_vec_to_secure_client_config(
    certs: &Vec<Certificate>,
) -> Result<ClientConfig, anyhow::Error> {
    if certs.is_empty() {
        return Err(anyhow::Error::msg(
            "Allowed certs is empty. Load native certs instead",
        ));
    }

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(cert.clone())?;
    }

    Ok(crate::quic::secure::client_config(root_store))
}

pub async fn create_client_config<T: AsRef<[u8]>>(
    allowed_certs: &[T],
) -> Result<TlsConnector, anyhow::Error> {
    Ok(client_config_to_tls_connector(Arc::new(
        create_rustls_client_config(allowed_certs)?,
    )))
}

pub fn client_config_to_tls_connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

pub fn create_server_self_signed_config() -> Result<TLSQUICInterop, anyhow::Error> {
    let (cert_der, priv_key_der) = generate_self_signed_cert()?;
    let (quic_chain, quic_priv_key) =
        crate::misc::cert_and_priv_key_der_to_quic_keys(&cert_der, &priv_key_der)?;
    let quic_chain = vec![quic_chain];

    let rustls_server_config =
        create_rustls_config_from_keys(quic_chain.clone(), quic_priv_key.clone_key())?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(rustls_server_config)),
        quic_chain,
        quic_priv_key,
    };

    Ok(ret)
}

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;

fn create_rustls_config_from_keys(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
) -> Result<RustlsServerConfig, anyhow::Error> {
    // Create a new RustlsServerConfig
    let rustls_config =
        RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)?;

    Ok(rustls_config)
}

pub fn create_server_config(
    pkcs12_der: &[u8],
    password: &str,
) -> Result<TLSQUICInterop, anyhow::Error> {
    let (certs_stack, cert, priv_key) = crate::misc::pkcs12_to_components(pkcs12_der, password)?;
    let (quic_chain, quic_priv_key) =
        crate::misc::pkcs_12_components_to_quic_keys(certs_stack.as_ref(), &cert, &priv_key)?;

    let server_config =
        create_rustls_config_from_keys(quic_chain.clone(), quic_priv_key.clone_key())?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
        quic_chain,
        quic_priv_key,
    };

    Ok(ret)
}

/// This can be an expensive operation, empirically lasting upwards of 200ms on some systems
/// This should only be called once, preferably at init of the protocol
pub async fn load_native_certs_async() -> Result<Vec<Certificate<'static>>, Error> {
    citadel_io::tokio::task::spawn_blocking(load_native_certs)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("{err:?}")))?
}

/// Loads native certs. This is an expensive operation, and should be called once per node
pub fn load_native_certs() -> Result<Vec<Certificate<'static>>, Error> {
    Ok(rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .map(Certificate::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::standard::tls::create_server_self_signed_config;

    #[test]
    fn main() {
        let _ = create_server_self_signed_config().unwrap();
    }
}
