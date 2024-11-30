//! QUIC Protocol Implementation for Secure Connections
//!
//! This module provides a high-level interface for establishing QUIC (Quick UDP Internet
//! Connections) connections. It supports both client and server roles with configurable
//! security options and NAT traversal capabilities.
//!
//! # Features
//!
//! - Client and server QUIC endpoint creation
//! - Self-signed and PKCS#12 certificate support
//! - Configurable TLS security levels
//! - NAT traversal-friendly transport configuration
//! - Bidirectional stream support
//! - Custom certificate verification options
//! - Async/await support with Tokio runtime
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::standard::quic::{QuicServer, QuicClient};
//! use citadel_io::tokio::net::UdpSocket;
//!
//! async fn setup_quic() -> Result<(), anyhow::Error> {
//!     // Create a self-signed server
//!     let socket = UdpSocket::bind("127.0.0.1:0").await?;
//!     let server = QuicServer::new_self_signed(socket)?;
//!     
//!     // Create a non-verifying client
//!     let socket = UdpSocket::bind("127.0.0.1:0").await?;
//!     let client = QuicClient::new_no_verify(socket)?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - QUIC requires UDP connectivity
//! - TLS 1.3 is mandatory for QUIC
//! - Certificate verification is configurable
//! - Self-signed certificates use 'localhost' domain
//! - Transport config optimized for NAT traversal
//!
//! # Related Components
//!
//! - [`crate::standard::nat_identification`] - NAT behavior analysis
//! - [`crate::standard::socket_helpers`] - UDP socket utilities
//! - [`crate::standard::tls`] - TLS configuration helpers
//! - [`crate::udp_traversal`] - UDP hole punching support
//!

use futures::Future;
use quinn::{
    Accept, ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream,
    ServerConfig, TokioRuntime,
};

use crate::exports::{Certificate, PrivateKey};
use async_trait_with_sync::async_trait;
use citadel_io::tokio::net::UdpSocket;
use either::Either;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::TransportConfig;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Used in the protocol especially to receive bidirectional connections
pub struct QuicServer;

/// Used in the protocol to facilitate bidirectional connections
pub struct QuicClient;

pub struct QuicNode {
    pub endpoint: Endpoint,
    pub tls_domain_opt: Option<String>,
}

#[async_trait]
pub trait QuicEndpointConnector {
    fn endpoint(&self) -> &Endpoint;

    async fn connect_biconn_with(
        &self,
        addr: SocketAddr,
        tls_domain: &str,
        cfg: Option<ClientConfig>,
    ) -> Result<(Connection, SendStream, RecvStream), anyhow::Error>
    where
        Self: Sized,
    {
        log::trace!(target: "citadel", "Connecting to {:?}={} | Custom Cfg? {}", tls_domain, addr, cfg.is_some());
        let connecting = if let Some(cfg) = cfg {
            self.endpoint().connect_with(cfg, addr, tls_domain)?
        } else {
            self.endpoint().connect(addr, tls_domain)?
        };

        let conn = connecting.await?;
        let (mut sink, stream) = conn.open_bi().await?;
        // must send some data before the adjacent node can receive a bidirectional connection
        sink.write(&[]).await?;

        Ok((conn, sink, stream))
    }

    /// Connects using the pre-stored ClientCfg
    async fn connect_biconn(
        &self,
        addr: SocketAddr,
        tls_domain: &str,
    ) -> Result<(Connection, SendStream, RecvStream), anyhow::Error>
    where
        Self: Sized,
    {
        self.connect_biconn_with(addr, tls_domain, None).await
    }
}

pub type QuicNextConnectionFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<(Connection, SendStream, RecvStream), anyhow::Error>>
            + Send
            + Sync
            + 'a,
    >,
>;

pub trait QuicEndpointListener {
    fn listener(&self) -> Accept;
    fn next_connection(&mut self) -> QuicNextConnectionFuture
    where
        Self: Sized + Send + Sync,
    {
        Box::pin(async move {
            let connecting = self
                .listener()
                .await
                .ok_or_else(|| anyhow::Error::msg(QUIC_LISTENER_DIED))?;
            let conn = connecting.await?;
            let (sink, stream) = conn
                .accept_bi()
                .await
                .map_err(|err| anyhow::Error::msg(err.to_string()))?;

            Ok((conn, sink, stream))
        })
    }
}

pub const QUIC_LISTENER_DIED: &str = "No QUIC connections available";

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
    fn listener(&self) -> Accept {
        self.endpoint.accept()
    }
}

impl Debug for QuicNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuicNode")
    }
}

impl QuicClient {
    /// - trusted_certs: If None, won't verify certs. NOTE: this implies is Some(&[]) is passed, no verification will work.
    pub fn create(
        socket: UdpSocket,
        client_config: Option<ClientConfig>,
    ) -> Result<QuicNode, anyhow::Error> {
        let endpoint = make_client_endpoint(socket, client_config)?;
        Ok(QuicNode {
            endpoint,
            tls_domain_opt: None,
        })
    }

    /// This client will not verify the certificates of outgoing connection
    pub fn new_no_verify(socket: UdpSocket) -> Result<QuicNode, anyhow::Error> {
        Self::create(socket, None)
    }

    /// Creates a new client that verifies certificates
    pub fn new_with_config(
        socket: UdpSocket,
        client_config: ClientConfig,
    ) -> Result<QuicNode, anyhow::Error> {
        Self::create(socket, Some(client_config))
    }

    pub fn new_with_rustls_config(
        socket: UdpSocket,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<QuicNode, anyhow::Error> {
        let quinn_config = rustls_client_config_to_quinn_config(client_config)?;
        Self::new_with_config(socket, quinn_config)
    }
}

impl QuicServer {
    pub fn create(
        socket: UdpSocket,
        crypt: Option<(Vec<Certificate<'static>>, PrivateKey<'static>)>,
    ) -> Result<QuicNode, anyhow::Error> {
        let endpoint = make_server_endpoint(socket, crypt)?;
        Ok(QuicNode {
            endpoint,
            tls_domain_opt: None,
        })
    }

    pub fn new_self_signed(socket: UdpSocket) -> Result<QuicNode, anyhow::Error> {
        Self::create(socket, None)
    }

    pub fn new_from_pkcs_12_der_path<P: AsRef<Path>>(
        socket: UdpSocket,
        path: P,
        password: &str,
    ) -> Result<QuicNode, anyhow::Error> {
        let (chain, pkey) = crate::misc::read_pkcs_12_der_to_quinn_keys(path, password)?;
        Self::create(socket, Some((chain, pkey)))
    }

    pub fn new_from_pkcs_12_der(
        socket: UdpSocket,
        der: &[u8],
        password: &str,
    ) -> Result<QuicNode, anyhow::Error> {
        let (chain, pkey) = crate::misc::pkcs12_to_quinn_keys(der, password)?;
        Self::create(socket, Some((chain, pkey)))
    }
}

fn make_server_endpoint(
    socket: UdpSocket,
    crypt: Option<(Vec<Certificate<'static>>, PrivateKey<'static>)>,
) -> Result<Endpoint, anyhow::Error> {
    let mut server_cfg = match crypt {
        Some((certs, key)) => secure::server_config(certs, key)?,
        None => configure_server_self_signed()?.0,
    };

    load_hole_punch_friendly_quic_transport_config(Either::Left(&mut server_cfg));
    let endpoint_config = EndpointConfig::default();
    let socket = socket.into_std()?; // Quinn sets nonblocking to true
    let endpoint = Endpoint::new(
        endpoint_config,
        Some(server_cfg),
        socket,
        Arc::new(TokioRuntime),
    )?;
    Ok(endpoint)
}

fn make_client_endpoint(
    socket: UdpSocket,
    client_config: Option<ClientConfig>,
) -> Result<Endpoint, anyhow::Error> {
    let mut client_cfg = client_config.unwrap_or_else(insecure::configure_client);

    let socket = socket.into_std()?; // Quinn handles setting nonblocking to true
    load_hole_punch_friendly_quic_transport_config(Either::Right(&mut client_cfg));
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_cfg);

    Ok(endpoint)
}

/// only one side needs to set this transport config
fn load_hole_punch_friendly_quic_transport_config<'a>(
    cfg: Either<&'a mut ServerConfig, &'a mut ClientConfig>,
) {
    let mut transport_cfg = TransportConfig::default();
    transport_cfg.keep_alive_interval(Some(Duration::from_millis(8000)));
    transport_cfg.max_concurrent_uni_streams(0u8.into());

    match cfg {
        Either::Left(cfg) => {
            // enable migration on the server to allow NAT rebinding
            cfg.migration(true);
            cfg.transport_config(Arc::new(transport_cfg));
        }
        Either::Right(cfg) => {
            cfg.transport_config(Arc::new(transport_cfg));
        }
    }
}

pub const SELF_SIGNED_DOMAIN: &str = "localhost";

/// returns the (cert, priv_key) der bytes
///
/// domain is always SELF_SIGNED_DOMAIN (localhost)
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec![SELF_SIGNED_DOMAIN.into()])?;
    let cert_der = cert.cert.der().as_ref().to_vec();
    let priv_key_der = cert.key_pair.serialize_der();
    Ok((cert_der, priv_key_der))
}

fn configure_server_self_signed() -> Result<(quinn::ServerConfig, Vec<u8>), anyhow::Error> {
    let (cert_der, priv_key) = generate_self_signed_cert()?;
    let priv_key = crate::exports::PrivateKey::try_from(priv_key)
        .map_err(|err| anyhow::Error::msg(format!("Failed to create private key: {err}")))?;
    let cert_chain = vec![crate::exports::Certificate::from(cert_der.clone())];

    let server_config = secure::server_config(cert_chain, priv_key)?;

    Ok((server_config, cert_der))
}

pub fn rustls_client_config_to_quinn_config(
    cfg: Arc<rustls::ClientConfig>,
) -> std::io::Result<ClientConfig> {
    Ok(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(cfg)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
    )))
}

pub mod secure {
    pub fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
        let mut cfg = rustls::ClientConfig::builder()
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
        cert_chain: Vec<crate::exports::Certificate<'static>>,
        key: crate::exports::PrivateKey<'static>,
    ) -> Result<quinn::ServerConfig, anyhow::Error> {
        let mut cfg = quinn::ServerConfig::with_single_cert(cert_chain, key)
            .map_err(|err| anyhow::Error::msg(err.to_string()))?;

        cfg.migration(true);
        cfg.max_incoming(u32::MAX as usize);

        Ok(cfg)
    }
}

pub mod insecure {
    use std::sync::Arc;

    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::ClientConfig;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct NoServerCertVerification;

    impl ServerCertVerifier for NoServerCertVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    pub fn rustls_client_config() -> rustls::ClientConfig {
        let versions = &rustls::version::TLS13;
        let mut rustls_config = rustls::ClientConfig::builder_with_protocol_versions(&[versions])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
            .with_no_client_auth();

        // Add requirements for TryFrom to succeed
        rustls_config.enable_sni = true;
        rustls_config.enable_early_data = true;

        //QuicClientConfig::try_from(rustls_config).expect("Failed to create QuicClientConfig")
        rustls_config
    }

    pub fn get_quic_client_config() -> QuicClientConfig {
        QuicClientConfig::try_from(rustls_client_config())
            .expect("Failed to create QuicClientConfig")
    }

    pub fn configure_client() -> ClientConfig {
        ClientConfig::new(Arc::new(get_quic_client_config()))
    }
}

#[cfg(test)]
mod tests {
    use crate::quic::{
        QuicClient, QuicEndpointConnector, QuicEndpointListener, QuicServer, SELF_SIGNED_DOMAIN,
    };
    use crate::socket_helpers::is_ipv6_enabled;
    use citadel_io::tokio;
    use rstest::*;
    use std::net::SocketAddr;

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[trace]
    #[timeout(std::time::Duration::from_secs(5))]
    #[tokio::test]
    async fn test_quic(#[case] addr: SocketAddr) -> std::io::Result<()> {
        citadel_logging::setup_log();
        if addr.is_ipv6() && !is_ipv6_enabled() {
            log::trace!(target: "citadel", "Skipping IPv6 test since IPv6 is not enabled");
            return Ok(());
        }
        let mut server =
            QuicServer::new_self_signed(citadel_io::tokio::net::UdpSocket::bind(addr).await?)
                .unwrap();
        let client_bind_addr = SocketAddr::from((addr.ip(), 0));
        let (start_tx, start_rx) = citadel_io::tokio::sync::oneshot::channel();
        let (end_tx, end_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let addr = server.endpoint.local_addr()?;

        let server = async move {
            log::trace!(target: "citadel", "Starting server @ {:?}", addr);
            start_tx.send(()).unwrap();
            let (conn, _tx, mut rx) = server.next_connection().await.unwrap();
            let addr = conn.remote_address();
            log::trace!(target: "citadel", "RECV {:?} from {:?}", &conn, addr);
            let buf = &mut [0u8; 3];
            rx.read(buf as &mut [u8]).await.unwrap();
            assert_eq!(buf, &[1, 2, 3]);
            end_tx.send(()).unwrap();
        };

        let client = async move {
            start_rx.await.unwrap();
            let client = QuicClient::new_no_verify(
                citadel_io::tokio::net::UdpSocket::bind(client_bind_addr)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let res = client.connect_biconn(addr, SELF_SIGNED_DOMAIN).await;
            log::trace!(target: "citadel", "Client res: {:?}", res);
            let (_conn, mut tx, _rx) = res.unwrap();
            tx.write_all(&[1, 2, 3]).await.unwrap();
            end_rx.await.unwrap();
        };

        let (_r0, _r1) = citadel_io::tokio::join!(server, client);
        Ok(())
    }
}
