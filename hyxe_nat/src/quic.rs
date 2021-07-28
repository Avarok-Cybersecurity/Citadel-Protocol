use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use quinn::{Endpoint, SendStream, RecvStream};
use quinn::Incoming;
use futures::StreamExt;

use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder,
    PrivateKey, ServerConfig, ServerConfigBuilder, TransportConfig,
};
use std::sync::Arc;

/// Used in the protocol mostly for obtaining a first bidirectional connection to the hole-punched endpoint. Supplies the QUIC endpoint and optional listener devices in case
/// the protocol requires further interaction
pub struct QuicContainer {
    pub endpoint: Endpoint,
    pub first_conn: Option<(SendStream, RecvStream)>,
    pub listener: Option<Incoming>
}

impl QuicContainer {
    pub async fn new(socket: HolePunchedUdpSocket, is_server: bool, tls_domain: &str) -> Result<Self, anyhow::Error> {
        //socket.socket.connect(socket.addr.natted).await?;
        let HolePunchedUdpSocket { addr, socket } = socket;
        let std_socket = socket.into_std()?;

        if is_server {
            let (endpoint, mut listener, _server_cert) = make_server_endpoint(std_socket)?;
            let connecting = listener.next().await.ok_or_else(|| anyhow::Error::msg("No QUIC connections available"))?;
            let mut conn = connecting.await?;
            let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
            Ok(QuicContainer { endpoint, first_conn: Some((sink, stream)), listener: Some(listener) })
        } else {
            let endpoint = make_client_endpoint(std_socket, &[])?;
            let connecting = endpoint.connect(&addr.natted, tls_domain)?;
            let mut conn = connecting.await?;
            let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
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
    server_certs: &[&[u8]],
) -> Result<Endpoint, anyhow::Error> {
    let client_cfg = configure_client(server_certs)?;
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
fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, anyhow::Error> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }
    Ok(cfg_builder.build())
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