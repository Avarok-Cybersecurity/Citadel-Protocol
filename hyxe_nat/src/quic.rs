use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use quinn::{Endpoint, SendStream, RecvStream, Incoming, ClientConfig, ServerConfig, ClientConfigBuilder, ServerConfigBuilder};
use futures::StreamExt;

use quinn::{Certificate, CertificateChain, PrivateKey, TransportConfig};
use std::sync::Arc;
use rustls::{ServerCertVerifier, ServerCertVerified, RootCertStore};
use quinn::crypto::rustls::TLSError;
use std::time::Duration;

/// Used in the protocol mostly for obtaining a first bidirectional connection to the hole-punched endpoint. Supplies the QUIC endpoint and optional listener devices in case
/// the protocol requires further interaction
pub struct QuicContainer {
    pub endpoint: Endpoint,
    pub first_conn: Option<(SendStream, RecvStream)>,
    pub listener: Option<Incoming>
}

impl QuicContainer {
    pub async fn new(socket: HolePunchedUdpSocket, is_server: bool, tls_domain: &str) -> Result<QuicContainer, anyhow::Error> {
        //socket.socket.connect(socket.addr.natted).await?;
        let HolePunchedUdpSocket { addr, socket } = socket;
        let std_socket = socket.into_std()?;

        if is_server {
            log::info!("RD0");
            let (endpoint, mut listener, _server_cert) = make_server_endpoint(std_socket)?;
            log::info!("RD1");
            let connecting = listener.next().await.ok_or_else(|| anyhow::Error::msg("No QUIC connections available"))?;
            log::info!("RD2");
            let mut conn = connecting.await?;
            log::info!("RD3");
            let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
            log::info!("RD4");
            Ok(QuicContainer { endpoint, first_conn: Some((sink, stream)), listener: Some(listener) })
        } else {
            log::info!("RD0");
            let endpoint = make_client_endpoint(std_socket, None)?;
            log::info!("RD1");
            let connecting = endpoint.connect(&addr.natted, tls_domain)?;
            log::info!("RD2");
            let conn = connecting.await?;
            log::info!("RD3");
            let (mut sink, stream) = conn.connection.open_bi().await?;
            // must send some data before the adjacent node can receive a bidirectional connection
            sink.write(b"Hello, world!").await?;
            log::info!("RD4");
            Ok(QuicContainer { endpoint, first_conn: Some((sink, stream)), listener: None })
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
pub fn make_server_endpoint(socket: std::net::UdpSocket) -> Result<(Endpoint, Incoming, Vec<u8>), anyhow::Error> {
    let (server_config, server_cert) = configure_server_crypto()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (endpoint, incoming) = endpoint_builder.with_socket(socket)?;
    Ok((endpoint, incoming, server_cert))
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

fn load_hole_punch_friendly_quic_transport_config(cfg: &mut ClientConfig) {
    let mut transport_cfg = TransportConfig::default();
    transport_cfg.keep_alive_interval(Some(Duration::from_millis(2000)));
    cfg.transport = Arc::new(transport_cfg);
}

/// Returns default server configuration along with its certificate.
fn configure_server_crypto() -> Result<(ServerConfig, Vec<u8>), anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_der(&priv_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;

    Ok((cfg_builder.build(), cert_der))
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