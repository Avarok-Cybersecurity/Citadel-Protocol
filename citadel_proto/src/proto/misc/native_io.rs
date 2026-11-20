use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use citadel_io::tokio::net::UdpSocket;
use citadel_io::{ProtocolIO, ProtocolUpgrade, ServerMode, ThreadRng, UnreliableDatagram};
use citadel_wire::exports::ClientConfig;

use crate::proto::misc::native_config::{
    NativeOrderedReliableConfig, NativeP2PConfig, NativeSecureConfig, NativeServerModeExt,
};
use crate::proto::misc::native_upgrade::TcpToQuicUpgrade;
use crate::proto::misc::net::{DualListener, GenericNetworkStream};

/// The native client's TLS configuration: the verifier and roots a connection verifies a server
/// against when it requires verification (see [`citadel_io::CertVerification`], chosen per
/// connection). Cloning is cheap (the rustls config is behind an Arc).
#[derive(Clone)]
pub struct NativeClientConfig {
    /// The rustls client configuration (verifier, roots, ALPN, etc.).
    pub config: Arc<ClientConfig>,
    accepts_any_certificate: bool,
}

impl NativeClientConfig {
    /// Connections that require verification check servers with `config`'s verifier.
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            accepts_any_certificate: false,
        }
    }

    /// A verifier that accepts any certificate. A connection that requires a verified
    /// certificate is refused on it before it dials (`CertVerificationUnavailable`), instead of
    /// being verified by a verifier that verifies nothing.
    pub fn accepting_any_certificate() -> Self {
        Self {
            config: Arc::new(citadel_wire::quic::insecure::rustls_client_config()),
            accepts_any_certificate: true,
        }
    }

    /// Whether a connection demanding `verification` can be made with this configuration.
    pub(crate) fn admits(&self, verification: citadel_io::CertVerification) -> io::Result<()> {
        if verification.is_required() && self.accepts_any_certificate {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                citadel_io::error!(citadel_io::ErrorCode::CertVerificationUnavailable)
                    .into_string(),
            ));
        }
        Ok(())
    }
}

/// Default [`ProtocolIO`] implementation for native platforms.
///
/// Wraps TCP/TLS/QUIC for ordered streams, UDP for unreliable datagrams,
/// and the system RNG. All existing protocol behaviour is preserved.
#[derive(Clone)]
pub struct NativeIO;

impl ProtocolIO for NativeIO {
    type Addr = SocketAddr;
    type Stream = GenericNetworkStream;
    type Listener = DualListener;
    type UnreliableSocket = NativeUdpSocket;
    type OrderedReliableConfig = NativeOrderedReliableConfig;
    type SecureConfig = NativeSecureConfig;
    type P2PConfig = NativeP2PConfig;
    type ClientConfig = NativeClientConfig;
    type Rng = ThreadRng;

    async fn bind(
        config: ServerMode<Self>,
        addr: Self::Addr,
    ) -> io::Result<(Self::Listener, Self::Addr)> {
        match &config {
            ServerMode::P2P(..) => TcpToQuicUpgrade::bind_with_upgrade(config, addr).await,
            _ => {
                let (gnl, bound) = super::native_bind::create_listener(config, None, None, addr)?;
                Ok((DualListener::new(gnl, None), bound))
            }
        }
    }

    async fn connect(
        config: &Self::ClientConfig,
        addr: Self::Addr,
        verification: citadel_io::CertVerification,
    ) -> io::Result<Self::Stream> {
        super::native_connect::c2s_connect(None, addr, config, verification).await
    }

    async fn connect_endpoint(
        config: &Self::ClientConfig,
        _addr: Self::Addr,
        endpoint: citadel_io::WebSocketEndpoint,
        verification: citadel_io::CertVerification,
    ) -> io::Result<Self::Stream> {
        super::native_ws_connect::c2s_connect_endpoint(None, &endpoint, config, verification).await
    }

    async fn bind_unreliable(addr: Self::Addr) -> io::Result<Self::UnreliableSocket> {
        citadel_wire::socket_helpers::get_udp_socket(addr)
            .map(NativeUdpSocket)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn rng() -> Self::Rng {
        citadel_io::thread_rng()
    }

    async fn default_client_config() -> io::Result<Self::ClientConfig> {
        let native_certs = citadel_wire::tls::load_native_certs_async().await?;
        let config = citadel_wire::tls::create_rustls_client_config(&native_certs)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(NativeClientConfig::new(Arc::new(config)))
    }

    fn server_identity(config: &ServerMode<Self>) -> Option<String> {
        config.maybe_get_identity()
    }

    fn local_addr(stream: &Self::Stream) -> io::Result<Self::Addr> {
        stream.local_addr()
    }

    async fn default_server_config() -> io::Result<ServerMode<Self>> {
        NativeSecureConfig::self_signed()
            .map(ServerMode::OrderedReliableSecure)
            .map_err(|e| io::Error::other(e.into_string()))
    }

    fn config_warnings(config: &ServerMode<Self>) {
        if matches!(config, ServerMode::OrderedReliable(..)) {
            citadel_logging::warn!(target: "citadel", "⚠️ WARNING ⚠️ TCP is discouraged for production use until The Citadel Protocol has been reviewed. Use TLS automatically by not changing the underlying protocol");
        }
    }

    fn from_socket_addr(addr: SocketAddr) -> SocketAddr {
        addr
    }

    fn to_socket_addr(addr: &SocketAddr) -> SocketAddr {
        *addr
    }

    fn addr_port(addr: &SocketAddr) -> u16 {
        addr.port()
    }

    fn peer_addr(stream: &GenericNetworkStream) -> io::Result<SocketAddr> {
        stream.peer_addr()
    }

    fn take_p2p_connection(
        stream: &mut GenericNetworkStream,
    ) -> Option<Box<dyn std::any::Any + Send>> {
        stream.take_p2p_connection().map(|c| Box::new(c) as _)
    }

    fn client_config_to_any(config: &NativeClientConfig) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(config.config.clone()))
    }

    async fn bind_with_websocket(
        primary: Self::Listener,
        websocket: Option<citadel_io::WebSocketListen>,
    ) -> io::Result<Self::Listener> {
        if let Some(websocket) = websocket {
            let tcp = match websocket {
                citadel_io::WebSocketListen::Addr(addr) => {
                    citadel_io::tokio::net::TcpListener::bind(addr).await?
                }
                citadel_io::WebSocketListen::Bound(listener) => {
                    listener.set_nonblocking(true)?;
                    citadel_io::tokio::net::TcpListener::from_std(listener)?
                }
            };
            let addr = tcp.local_addr()?;
            let ws_listener = super::net::GenericNetworkListener::new_websocket(tcp)?;
            log::info!(target: "citadel", "WebSocket listener bound on {addr}");
            Ok(primary.merge_with(ws_listener))
        } else {
            Ok(primary)
        }
    }
}

/// Newtype around [`UdpSocket`] implementing [`UnreliableDatagram`].
///
/// Required because neither [`UnreliableDatagram`] nor [`UdpSocket`] is
/// defined in this crate (orphan rule).
pub struct NativeUdpSocket(pub UdpSocket);

impl UnreliableDatagram for NativeUdpSocket {
    type Addr = SocketAddr;

    async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
