use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio::net::UdpSocket;
use citadel_io::{ProtocolIO, ProtocolUpgrade, ServerMode, ThreadRng, UnreliableDatagram};
use citadel_wire::exports::ClientConfig;

use crate::proto::misc::native_config::{
    NativeOrderedReliableConfig, NativeP2PConfig, NativeSecureConfig, NativeServerModeExt,
};
use crate::proto::misc::native_upgrade::TcpToQuicUpgrade;
use crate::proto::misc::net::{DualListener, GenericNetworkStream};
use crate::proto::node::CitadelNode;

// Concrete node type for calling static methods that don't depend on the
// Ratchet parameter.
type AnyNode = CitadelNode<StackedRatchet, NativeIO>;

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
    type ClientConfig = Arc<ClientConfig>;
    type Rng = ThreadRng;

    async fn bind(
        config: ServerMode<Self>,
        addr: Self::Addr,
    ) -> io::Result<(Self::Listener, Self::Addr)> {
        match &config {
            ServerMode::P2P(..) => TcpToQuicUpgrade::bind_with_upgrade(config, addr).await,
            _ => AnyNode::server_create_primary_listen_socket(config, addr),
        }
    }

    async fn connect(config: &Self::ClientConfig, addr: Self::Addr) -> io::Result<Self::Stream> {
        let (stream, _quic_endpoint) = AnyNode::c2s_connect_defaults(None, addr, config).await?;
        Ok(stream)
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
        Ok(Arc::new(config))
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
