use quinn::{Endpoint, SendStream, RecvStream, Incoming, ClientConfig, ServerConfig, NewConnection, EndpointConfig};
use futures::{StreamExt, Future};

use quinn::TransportConfig;
use std::sync::Arc;
use rustls::{PrivateKey, Certificate};
use std::time::Duration;
use std::path::Path;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use async_trait_with_sync::async_trait;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use either::Either;

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
            self.endpoint().connect_with(cfg, addr, tls_domain)?
        } else {
            self.endpoint().connect(addr, tls_domain)?
        };


        let conn = connecting.await?;
        let (mut sink, stream) = conn.connection.open_bi().await?;
        // must send some data before the adjacent node can receive a bidirectional connection
        sink.write(&[]).await?;

        Ok((conn, sink, stream))
    }

    /// Connects using the pre-stored ClientCfg
    async fn connect_biconn(&self, addr: SocketAddr, tls_domain: &str) -> Result<(NewConnection, SendStream, RecvStream), anyhow::Error>
        where Self: Sized {
        self.connect_biconn_with(addr, tls_domain, None).await
    }
}

pub trait QuicEndpointListener {
    fn listener(&mut self) -> &mut Incoming;
    fn next_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(NewConnection, SendStream, RecvStream), anyhow::Error>> + Send + Sync + 'a>>
        where Self: Sized + Send + Sync {
        Box::pin(async move {
            let connecting = self.listener().next().await.ok_or_else(|| anyhow::Error::msg(QUIC_LISTENER_DIED))?;
            let mut conn = connecting.await?;
            let (sink, stream) = conn.bi_streams.next().await.ok_or_else(|| anyhow::Error::msg("No bidirectional conns"))??;

            Ok((conn, sink, stream))
        })
    }
}

pub const QUIC_LISTENER_DIED: &'static str = "No QUIC connections available";

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
    /// - trusted_certs: If None, won't verify certs. NOTE: this implies is Some(&[]) is passed, no verification will work.
    pub fn new(socket: UdpSocket, trusted_certs: Option<&[&[u8]]>) -> Result<QuicNode, anyhow::Error> {
        if trusted_certs.as_ref().map(|r| r.is_empty()).unwrap_or(false) {
            log::warn!("Client passed an empty set of trusted certs. Will fallback to native roots")
        }

        let (endpoint, listener) = make_client_endpoint(socket, trusted_certs)?;
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
    pub fn new(socket: UdpSocket, crypt: Option<(Vec<Certificate>, PrivateKey)>) -> Result<QuicNode, anyhow::Error> {
        let (endpoint, listener) = make_server_endpoint(socket, crypt)?;
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

fn make_server_endpoint(socket: UdpSocket, crypt: Option<(Vec<Certificate>, PrivateKey)>) -> Result<(Endpoint, quinn::Incoming), anyhow::Error> {
    let mut server_cfg = match crypt {
        Some((certs, key)) => configure_server_with_crypto(certs, key)?,
        None => configure_server_self_signed()?.0
    };

    load_hole_punch_friendly_quic_transport_config(Either::Left(&mut server_cfg));
    let endpoint_config = EndpointConfig::default();
    let socket = socket.into_std()?; // Quinn sets nonblocking to true
    let (endpoint, incoming) = Endpoint::new(endpoint_config, Some(server_cfg), socket)?;
    Ok((endpoint, incoming))
}


fn make_client_endpoint(
    socket: UdpSocket,
    server_certs: Option<&[&[u8]]>,
) -> Result<(Endpoint, Incoming), anyhow::Error> {
    let mut client_cfg = match server_certs {
        Some(certs) => configure_client_secure(certs)?,
        None => insecure::configure_client()
    };

    let socket = socket.into_std()?; // Quinn handles setting nonblocking to true
    load_hole_punch_friendly_quic_transport_config(Either::Right(&mut client_cfg));
    let (mut endpoint, incoming) = Endpoint::new(EndpointConfig::default(), None, socket)?;
    endpoint.set_default_client_config(client_cfg);

    Ok((endpoint, incoming))
}


/// only one side needs to set this transport config
fn load_hole_punch_friendly_quic_transport_config<'a>(cfg: Either<&'a mut ServerConfig, &'a mut ClientConfig>) {
    let mut transport_cfg = TransportConfig::default();
    transport_cfg.keep_alive_interval(Some(Duration::from_millis(2000)));
    transport_cfg.max_concurrent_uni_streams(0u8.into());

    match cfg {
        Either::Left(cfg) => {
            cfg.transport = Arc::new(transport_cfg)
        }

        Either::Right(cfg) => {
            cfg.transport = Arc::new(transport_cfg)
        }
    }
}

pub const SELF_SIGNED_DOMAIN: &'static str = "localhost";

/// returns the (cert, priv_key) der bytes
///
/// domain is always SELF_SIGNED_DOMAIN (localhost)
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec![SELF_SIGNED_DOMAIN.into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();
    Ok((cert_der, priv_key_der))
}


/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client_secure(server_certs: &[&[u8]]) -> Result<ClientConfig, anyhow::Error> {
    if server_certs.is_empty() {
        log::warn!("Using native roots since no trusted server certs specified");
        return Ok(ClientConfig::with_native_roots())
    }

    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(&rustls::Certificate(cert.to_vec()))?;
    }

    Ok(ClientConfig::with_root_certificates(certs))
}


fn configure_server_self_signed() -> Result<(ServerConfig, Vec<u8>), anyhow::Error> {
    let (cert_der, priv_key) = generate_self_signed_cert()?;
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(secure::server_config(cert_chain, priv_key)?));

    Ok((server_config, cert_der))
}

fn configure_server_with_crypto(cert_chain: Vec<rustls::Certificate>, private_key: rustls::PrivateKey) -> Result<ServerConfig, anyhow::Error> {
    let server_crypto = secure::server_config(cert_chain, private_key)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Ok(server_config)
}

pub fn rustls_client_config_to_quinn_config(cfg: Arc<rustls::ClientConfig>) -> ClientConfig {
    ClientConfig::new(cfg)
}

pub mod secure {
    pub fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
        let mut cfg = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.enable_early_data = true;
        cfg.enable_sni = true;
        cfg
    }

    /// Initialize a sane QUIC-compatible TLS server configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
    /// `u32::MAX`. Advanced users can use any [`rustls::ServerConfig`] that satisfies these
    /// requirements.
    pub fn server_config(
        cert_chain: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    ) -> Result<rustls::ServerConfig, anyhow::Error> {
        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        cfg.max_early_data_size = u32::MAX;
        Ok(cfg)
    }
}

pub mod insecure {
    use std::sync::Arc;

    use quinn::ClientConfig;

    pub(crate) struct SkipServerVerification;

    impl SkipServerVerification {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    impl rustls::client::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }

    pub fn rustls_client_config() -> rustls::ClientConfig {
        let mut cfg = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        cfg.enable_sni = true;
        cfg
    }

    pub fn configure_client() -> ClientConfig {
        ClientConfig::new(Arc::new(rustls_client_config()))
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