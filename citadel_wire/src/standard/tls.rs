use crate::quic::generate_self_signed_cert;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore};
use std::io::Error;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Useful for allowing migration from a TLS config to a QUIC config in the citadel_proto crate
#[derive(Clone)]
pub struct TLSQUICInterop {
    pub tls_acceptor: TlsAcceptor,
    pub quic_chain: Vec<Certificate>,
    pub quic_priv_key: PrivateKey,
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
            .map(|r| rustls::Certificate(r.as_ref().to_vec()))
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
        root_store.add(cert)?;
    }

    Ok(crate::quic::secure::client_config(root_store))
}

pub async fn create_client_config(allowed_certs: &[&[u8]]) -> Result<TlsConnector, anyhow::Error> {
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

    // the server won't verify clients. The clients verify the server
    let server_config =
        crate::quic::secure::server_config(quic_chain.clone(), quic_priv_key.clone())?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
        quic_chain,
        quic_priv_key,
    };

    Ok(ret)
}

pub fn create_server_config(
    pkcs12_der: &[u8],
    password: &str,
) -> Result<TLSQUICInterop, anyhow::Error> {
    let (certs_stack, cert, priv_key) = crate::misc::pkcs12_to_components(pkcs12_der, password)?;
    let (quic_chain, quic_priv_key) =
        crate::misc::pkcs_12_components_to_quic_keys(certs_stack.as_ref(), &cert, &priv_key)?;

    let server_config =
        crate::quic::secure::server_config(quic_chain.clone(), quic_priv_key.clone())?;

    let ret = TLSQUICInterop {
        tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
        quic_chain,
        quic_priv_key,
    };

    Ok(ret)
}

/// This can be an expensive operation, empirically lasting upwards of 200ms on some systems
/// This should only be called once, preferably at init of the protocol
pub async fn load_native_certs_async() -> Result<Vec<Certificate>, Error> {
    citadel_io::spawn_blocking(load_native_certs)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("{err:?}")))?
}

/// Loads native certs. This is an expensive operation, and should be called once per node
pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    rustls_native_certs::load_native_certs()
        .map(|r| r.into_iter().map(|cert| Certificate(cert.0)).collect())
}

#[cfg(test)]
mod tests {
    use crate::standard::tls::create_server_self_signed_config;

    #[test]
    fn main() {
        let _ = create_server_self_signed_config().unwrap();
    }
}
