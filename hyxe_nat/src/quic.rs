use quinn::{Endpoint, SendStream, RecvStream, Incoming, ClientConfig, ServerConfig, ClientConfigBuilder, ServerConfigBuilder, NewConnection};
use futures::StreamExt;

use quinn::{Certificate, CertificateChain, PrivateKey, TransportConfig};
use std::sync::Arc;
use rustls::{ServerCertVerifier, ServerCertVerified, RootCertStore};
use quinn::crypto::rustls::TLSError;
use std::time::Duration;
use std::path::Path;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use async_trait::async_trait;

/// Used in the protocol especially to receive bidirectional connections
pub struct QuicServer;

/// Used in the protocol to facilitate bidirectional connections
pub struct QuicClient;

pub struct QuicNode {
    pub endpoint: Endpoint,
    pub listener: Incoming
}

#[async_trait]
pub trait QuicEndpointConnector {
    fn endpoint(&self) -> &Endpoint;

    async fn connect_biconn(&self, addr: SocketAddr, tls_domain: &str) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        log::info!("RD0");
        let connecting = self.endpoint().connect(&addr, tls_domain)?;
        log::info!("RD1");
        let conn = connecting.await?;
        log::info!("RD2");
        let (mut sink, stream) = conn.connection.open_bi().await?;
        log::info!("RD3");
        // must send some data before the adjacent node can receive a bidirectional connection
        sink.write(&[]).await?;
        log::info!("RD4");

        Ok((conn, sink, stream))
    }
}

#[async_trait]
pub trait QuicEndpointListener {
    fn listener(&mut self) -> &mut Incoming;
    async fn next_connection(&mut self) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        log::info!("NC0");
        let connecting = self.listener().next().await.ok_or_else(|| anyhow::Error::msg("No QUIC connections available"))?;
        log::info!("NC1");
        let mut conn = connecting.await?;
        log::info!("NC2");
        let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
        log::info!("NC3");
        Ok((conn, sink, stream))
    }
}

impl QuicEndpointConnector for QuicNode {
    fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl QuicEndpointConnector for Endpoint {
    fn endpoint(&self) -> &Endpoint {
        self
    }
}

impl QuicEndpointListener for QuicNode {
    fn listener(&mut self) -> &mut Incoming {
        &mut self.listener
    }
}

impl QuicClient {
    /// - trusted_certs: If None, won't verify certs
    pub fn new(socket: UdpSocket, trusted_certs: Option<&[&[u8]]>) -> Result<QuicNode, anyhow::Error> {
        let (endpoint, listener) = make_client_endpoint(socket.into_std()?, trusted_certs)?;
        Ok(QuicNode { endpoint, listener })
    }

    /// This client will not verify the certificates of outgoing connection
    pub fn new_no_verify(socket: UdpSocket) -> Result<QuicNode, anyhow::Error> {
        Self::new(socket, None)
    }

    /// Creates a new client that verifies certificates
    pub fn new_verify(socket: UdpSocket, trusted_certs: &[&[u8]]) -> Result<QuicNode, anyhow::Error> {
        Self::new(socket, Some(trusted_certs))
    }
}

impl QuicServer {
    pub fn new(socket: UdpSocket, crypt: Option<(CertificateChain, PrivateKey)>) -> Result<QuicNode, anyhow::Error> {
        let (endpoint, listener) = make_server_endpoint(socket.into_std()?, crypt)?;
        Ok(QuicNode { endpoint, listener })
    }

    pub fn new_self_signed(socket: UdpSocket) -> Result<QuicNode, anyhow::Error> {
        Self::new(socket, None)
    }

    pub fn new_from_pkcs_12_der_path<P: AsRef<Path>>(socket: UdpSocket, path: P, password: &str) -> Result<QuicNode, anyhow::Error> {
        let (chain, pkey) = crate::misc::read_pkcs_12_der_to_quinn_keys(path, password)?;
        Self::new(socket, Some((chain, pkey)))
    }

    pub fn new_from_pkcs_12_der(socket: UdpSocket, der: &[u8], password: &str) -> Result<QuicNode, anyhow::Error> {
        let (chain, pkey) = crate::misc::pkcs12_to_quinn_keys(der, password)?;
        Self::new(socket, Some((chain, pkey)))
    }
}

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn make_client_endpoint(
    socket: std::net::UdpSocket,
    server_certs: Option<&[&[u8]]>,
) -> Result<(Endpoint, Incoming), anyhow::Error> {
    let client_cfg = if let Some(server_certs) = server_certs {
        configure_client_secure(server_certs)?
    } else {
        configure_client_insecure()
    };

    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (endpoint, incoming) = endpoint_builder.with_socket(socket)?;

    Ok((endpoint, incoming))
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint(socket: std::net::UdpSocket, crypt: Option<(CertificateChain, PrivateKey)>) -> Result<(Endpoint, Incoming), anyhow::Error> {
    let server_config = configure_server_crypto(crypt)?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);

    let (endpoint, incoming) = endpoint_builder.with_socket(socket)?;
    Ok((endpoint, incoming))
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client_secure(server_certs: &[&[u8]]) -> Result<ClientConfig, anyhow::Error> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }

    let mut cfg = cfg_builder.build();

    load_hole_punch_friendly_quic_transport_config(&mut cfg);

    Ok(cfg)
}

fn configure_client_insecure() -> ClientConfig {
    let mut cfg = ClientConfigBuilder::default().build();
    load_hole_punch_friendly_quic_transport_config(&mut cfg);
    let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    // this is only available when compiled with "dangerous_configuration" feature
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    cfg
}

/// only one side needs to set this transport config
fn load_hole_punch_friendly_quic_transport_config(cfg: &mut ClientConfig) {
    let mut transport_cfg = TransportConfig::default();
    transport_cfg.keep_alive_interval(Some(Duration::from_millis(2000)));
    cfg.transport = Arc::new(transport_cfg);
}

/// Returns default server configuration along with its certificate.
fn configure_server_crypto(crypt: Option<(CertificateChain, PrivateKey)>) -> Result<ServerConfig, anyhow::Error> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);

    if let Some((chain, pkey)) = crypt {
        cfg_builder.certificate(chain, pkey)?;
    } else {
        log::info!("Generating self-signed cert [requires endpoint dangerous configuration]");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let priv_key = cert.serialize_private_key_der();
        let priv_key = PrivateKey::from_der(&priv_key)?;

        let cert = Certificate::from_der(&cert_der)?;
        cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;
    }

    Ok(cfg_builder.build())
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(&self, _roots: &RootCertStore, _presented_certs: &[rustls::Certificate], _dns_name: webpki::DNSNameRef<'_>, _ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}