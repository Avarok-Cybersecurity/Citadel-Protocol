use rustls::{ClientConfig, ServerConfig, AllowAnyAnonymousOrAuthenticatedClient, RootCertStore, Certificate, PrivateKey};
use crate::quic::{SkipServerVerification, generate_self_signed_cert};
use std::sync::Arc;
use tokio_rustls::{TlsConnector, TlsAcceptor};
use quinn::CertificateChain;

/// Useful for allowing migration from a TLS config to a QUIC config in the hyxe_net crate
#[derive(Clone)]
pub struct TLSQUICInterop {
    pub tls_acceptor: TlsAcceptor,
    pub quic_chain: CertificateChain,
    pub quic_priv_key: quinn::PrivateKey
}

pub fn create_client_dangerous_config() -> TlsConnector {
    let mut default = ClientConfig::default();
    default.enable_sni = true;
    default.dangerous().set_certificate_verifier(SkipServerVerification::new());
    TlsConnector::from(Arc::new(default))
}

pub fn create_client_config() -> TlsConnector {
    let mut default = ClientConfig::default();
    default.enable_sni = true;
    TlsConnector::from(Arc::new(default))
}

pub fn create_server_self_signed_config() -> Result<TLSQUICInterop, anyhow::Error> {
    let (cert_der, priv_key_der) = generate_self_signed_cert()?;
    let (quic_chain, quic_priv_key) = crate::misc::cert_and_priv_key_der_to_quic_keys(&cert_der, &priv_key_der)?;
    let client_verifier = AllowAnyAnonymousOrAuthenticatedClient::new(RootCertStore::empty());
    let mut server_config = ServerConfig::new(client_verifier);
    server_config.set_single_cert(vec![Certificate(cert_der)], PrivateKey(priv_key_der))?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
        quic_chain: CertificateChain::from_certs(vec![quic_chain]),
        quic_priv_key
    };

    Ok(ret)
}

pub fn create_server_config(pkcs12_der: &[u8], password: &str) -> Result<TLSQUICInterop, anyhow::Error> {
    let (certs_stack, cert, priv_key) = crate::misc::pkcs12_to_components(pkcs12_der, password)?;
    let (quic_chain, quic_priv_key) = crate::misc::pkcs_12_components_to_quic_keys(certs_stack.as_ref(), &cert, &priv_key)?;

    let client_verifier = AllowAnyAnonymousOrAuthenticatedClient::new(RootCertStore::empty());
    let mut server_config = ServerConfig::new(client_verifier);

    let mut certs = Vec::new();
    certs.push(Certificate(cert.to_der()?));

    if let Some(certs_stack) = certs_stack {
        for certificate in certs_stack {
            certs.push(Certificate(certificate.to_der()?));
        }
    }

    server_config.set_single_cert(certs, PrivateKey(priv_key.private_key_to_der()?))?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
        quic_chain,
        quic_priv_key
    };

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::tls::create_server_self_signed_config;

    #[test]
    fn main() {
        let _ = create_server_self_signed_config().unwrap();
    }
}