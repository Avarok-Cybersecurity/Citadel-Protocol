use quinn::{Endpoint, SendStream, RecvStream, Incoming, ClientConfig, ServerConfig, ClientConfigBuilder, ServerConfigBuilder, NewConnection, Connecting};
use futures::{StreamExt, Future};

use quinn::{Certificate, CertificateChain, PrivateKey, TransportConfig};
use std::sync::Arc;
use rustls::{ServerCertVerifier, ServerCertVerified, RootCertStore};
use quinn::crypto::rustls::TLSError;
use std::time::Duration;
use std::path::Path;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use async_trait_with_sync::async_trait;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;

/// Used in the protocol especially to receive bidirectional connections
pub struct QuicServer;

/// Used in the protocol to facilitate bidirectional connections
pub struct QuicClient;

pub struct QuicNode {
    pub endpoint: Endpoint,
    pub listener: Incoming,
    pub tls_domain_opt: Option<String>
}

#[async_trait]
pub trait QuicEndpointConnector {
    fn endpoint(&self) -> &Endpoint;

    async fn connect_biconn_with(&self, addr: SocketAddr, tls_domain: &str, cfg: Option<ClientConfig>) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        log::info!("Connecting to {:?}={} | Custom Cfg? {}", tls_domain, addr, cfg.is_some());
        let connecting = if let Some(cfg) = cfg {
            self.endpoint().connect_with(cfg, &addr, tls_domain)?
        } else {
            self.endpoint().connect(&addr, tls_domain)?
        };

        log::info!("RP0");

        let conn = connecting.await?;
        log::info!("RP1");
        let (mut sink, stream) = conn.connection.open_bi().await?;
        log::info!("RP2");
        // must send some data before the adjacent node can receive a bidirectional connection
        sink.write(&[]).await?;
        log::info!("RP3");

        Ok((conn, sink, stream))
    }

    /// Connects using the pre-stored ClientCfg
    async fn connect_biconn(&self, addr: SocketAddr, tls_domain: &str) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        self.connect_biconn_with(addr, tls_domain, None).await
    }


}

#[async_trait]
pub trait QuicEndpointListener {
    fn listener(&mut self) -> &mut Incoming;
    async fn next_connection(&mut self) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        log::info!("TT0");
        let connecting = self.listener().next().await.ok_or_else(|| anyhow::Error::msg("No QUIC connections available"))?;
        log::info!("TT1");
        handle_connecting(connecting).await
    }
}

pub fn handle_connecting(connecting: Connecting) -> Pin<Box<dyn Future<Output=Result<(NewConnection, SendStream, RecvStream), anyhow::Error>> + Send + Sync>> {
    Box::pin(async move {
        let mut conn = connecting.await?;
        log::info!("TT2");
        let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;
        Ok((conn, sink, stream))
    })
}

impl QuicEndpointListener for Incoming {
    fn listener(&mut self) -> &mut Incoming {
        self
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

impl Debug for QuicNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuicNode")
    }
}

impl QuicClient {
    /// - trusted_certs: If None, won't verify certs
    pub fn new(socket: UdpSocket, trusted_certs: Option<&[&[u8]]>) -> Result<QuicNode, anyhow::Error> {
        let (endpoint, listener) = make_client_endpoint(socket.into_std()?, trusted_certs)?;
        Ok(QuicNode { endpoint, listener, tls_domain_opt: None })
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
        Ok(QuicNode { endpoint, listener, tls_domain_opt: None })
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
pub fn configure_client_secure(server_certs: &[&[u8]]) -> Result<ClientConfig, anyhow::Error> {
    let mut cfg_builder = ClientConfigBuilder::default();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }

    let mut cfg = cfg_builder.build();

    load_hole_punch_friendly_quic_transport_config(&mut cfg);

    Ok(cfg)
}

pub fn configure_client_insecure() -> ClientConfig {
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

pub const SELF_SIGNED_DOMAIN: &'static str = "localhost";

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
        let (cert_der, priv_key) = generate_self_signed_cert()?;
        let priv_key = PrivateKey::from_der(&priv_key)?;
        let cert = Certificate::from_der(&cert_der)?;

        cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;
    }

    Ok(cfg_builder.build())
}

/// returns the (cert, priv_key) der bytes
///
/// domain is always SELF_SIGNED_DOMAIN (localhost)
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec![SELF_SIGNED_DOMAIN.into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();
    Ok((cert_der, priv_key_der))
}

pub(crate) struct SkipServerVerification;

impl SkipServerVerification {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(&self, _roots: &RootCertStore, _presented_certs: &[rustls::Certificate], _dns_name: webpki::DNSNameRef<'_>, _ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use crate::socket_helpers::is_ipv6_enabled;
    use rstest::*;
    use std::net::SocketAddr;
    use crate::quic::{QuicServer, QuicEndpointListener, QuicClient, QuicEndpointConnector, SELF_SIGNED_DOMAIN};

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }


    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[trace]
    #[tokio::test]
    async fn test_quic(#[case] addr: SocketAddr) -> std::io::Result<()> {
        setup_log();
        if addr.is_ipv6() {
            if !is_ipv6_enabled() {
                log::info!("Skipping IPv6 test since IPv6 is not enabled");
                return Ok(())
            }
        }
        let mut server = QuicServer::new_self_signed(tokio::net::UdpSocket::bind(addr).await?).unwrap();
        let client_bind_addr = SocketAddr::from((addr.ip(), 0));
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
        let addr = server.endpoint.local_addr().unwrap();

        let server = async move {
            log::info!("Starting server @ {:?}", addr);
            start_tx.send(()).unwrap();
            let (conn, _tx, mut rx) = server.next_connection().await.unwrap();
            let addr = conn.connection.remote_address();
            log::info!("RECV {:?} from {:?}", &conn, addr);
            let buf = &mut [0u8; 3];
            rx.read_exact(buf as &mut [u8]).await.unwrap();
            assert_eq!(buf, &[1, 2, 3]);
            end_tx.send(()).unwrap();
        };

        let client = async move {
            start_rx.await.unwrap();
            let client = QuicClient::new_no_verify(tokio::net::UdpSocket::bind(client_bind_addr).await.unwrap()).unwrap();
            let res = client.connect_biconn(addr, SELF_SIGNED_DOMAIN).await;
            log::info!("Client res: {:?}", res);
            let (_conn, mut tx, _rx) = res.unwrap();
            tx.write_all(&[1, 2, 3]).await.unwrap();
            end_rx.await.unwrap();
        };

        let (_r0, _r1) = tokio::join!(server, client);
        Ok(())
    }

}