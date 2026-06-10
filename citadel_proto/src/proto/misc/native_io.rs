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

/// Native client TLS configuration plus connection policy.
///
/// Bundles the rustls client config with a flag controlling whether the peer may downgrade the
/// connection to no-certificate-verification. Cloning is cheap (the rustls config is behind an Arc).
#[derive(Clone)]
pub struct NativeClientConfig {
    /// The rustls client configuration (verifier, roots, ALPN, etc.).
    pub config: Arc<ClientConfig>,
    /// When true, the client refuses to fall back to no-verification even if the peer's FirstPacket
    /// advertises a self-signed server. This prevents an active attacker from forcing the insecure
    /// (accept-any-cert) TLS/QUIC path by flipping the `is_self_signed`/absent-`domain` signal.
    /// Defaults to false so the self-signed deployment mode (and its tests) keep working.
    pub require_cert_verification: bool,
}

impl NativeClientConfig {
    /// Wraps a rustls client config with the default (permissive) verification policy.
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            require_cert_verification: false,
        }
    }
}

impl From<Arc<ClientConfig>> for NativeClientConfig {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self::new(config)
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

    async fn connect(config: &Self::ClientConfig, addr: Self::Addr) -> io::Result<Self::Stream> {
        super::native_connect::c2s_connect(None, addr, config).await
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
        ws_bind_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<Self::Listener> {
        if let Some(addr) = ws_bind_addr {
            let tcp = citadel_io::tokio::net::TcpListener::bind(addr).await?;
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
