use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use quinn::{Endpoint, SendStream, RecvStream, Incoming, ClientConfig, ServerConfig, ClientConfigBuilder, ServerConfigBuilder};
use futures::StreamExt;

use quinn::{Certificate, CertificateChain, PrivateKey, TransportConfig};
use std::sync::Arc;
use rustls::{ServerCertVerifier, ServerCertVerified, RootCertStore};
use quinn::crypto::rustls::TLSError;
use std::time::Duration;
use std::path::Path;

/// Used in the protocol mostly for obtaining a first bidirectional connection to the hole-punched endpoint. Supplies the QUIC endpoint and optional listener devices in case
/// the protocol requires further interaction
pub struct QuicContainer {
    pub endpoint: Endpoint,
    pub first_conn: Option<(SendStream, RecvStream)>,
    pub listener: Option<Incoming>
}

pub enum QuicEndpointType<'a> {
    Listener { crypt: Option<(CertificateChain, PrivateKey)> },
    Client { trusted_certs: Option<&'a [&'a [u8]]>, tls_domain: &'a str }
}

impl<'a> QuicEndpointType<'a> {
    pub fn listener_from_pkcs_12_der_path<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, anyhow::Error> {
        let (chain, pkey) = crate::misc::read_pkcs_12_der_to_quinn_keys(path, password)?;
        Ok(QuicEndpointType::Listener { crypt: Some((chain, pkey)) })
    }

    pub fn listener_dangerous_self_signed() -> Self {
        QuicEndpointType::Listener { crypt: None }
    }

    pub fn client_from_trusted_certs(certs: &'a [&'a [u8]], tls_domain: &'a str) -> Result<Self, anyhow::Error> {
        Ok(QuicEndpointType::Client { trusted_certs: Some(certs), tls_domain })
    }

    /// Required if using self-signed certs (for now)
    pub fn client_dangerous_no_verify(tls_domain: &'a str) -> Self {
        QuicEndpointType::Client { trusted_certs: None, tls_domain }
    }
}

impl QuicContainer {
    pub async fn new(socket: HolePunchedUdpSocket, quic_endpoint_type: QuicEndpointType<'_>) -> Result<QuicContainer, anyhow::Error> {
        //socket.socket.connect(socket.addr.natted).await?;
        let HolePunchedUdpSocket { addr, socket } = socket;
        let std_socket = socket.into_std()?;

        match quic_endpoint_type {
            QuicEndpointType::Listener { crypt } => {
                log::info!("RD0");
                let (endpoint, mut listener) = make_server_endpoint(std_socket, crypt)?;
                log::info!("RD1");
                let connecting = listener.next().await.ok_or_else(|| anyhow::Error::msg("No QUIC connections available"))?;
                log::info!("RD2");
                let mut conn = connecting.await?;
                log::info!("RD3");
                let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
                log::info!("RD4");
                Ok(QuicContainer { endpoint, first_conn: Some((sink, stream)), listener: Some(listener) })
            }

            QuicEndpointType::Client { trusted_certs, tls_domain } => {
                log::info!("RD0");
                let endpoint = make_client_endpoint(std_socket, trusted_certs)?;
                log::info!("RD1");
                let connecting = endpoint.connect(&addr.natted, tls_domain)?;
                log::info!("RD2");
                let conn = connecting.await?;
                log::info!("RD3");
                let (mut sink, stream) = conn.connection.open_bi().await?;
                // must send some data before the adjacent node can receive a bidirectional connection
                sink.write(&[]).await?;
                log::info!("RD4");
                Ok(QuicContainer { endpoint, first_conn: Some((sink, stream)), listener: None })
            }
        }
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
) -> Result<Endpoint, anyhow::Error> {
    let client_cfg = if let Some(server_certs) = server_certs {
        configure_client_secure(server_certs)?
    } else {
        configure_client_insecure()
    };

    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (endpoint, incoming) = endpoint_builder.with_socket(socket)?;
    Ok(endpoint)
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