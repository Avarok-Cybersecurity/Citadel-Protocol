//! Native client connect logic and P2P connection helpers.
//!
//! Extracted from `CitadelNode` to satisfy SBIO — all socket creation,
//! protocol negotiation, and QUIC connection logic lives here.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use citadel_io::tokio::io::AsyncRead;
use citadel_io::{ProtocolUpgrade, ServerMode};
use citadel_wire::exports::tokio_rustls::rustls::{pki_types, ClientConfig};
use citadel_wire::quic::{QuicClient, QuicEndpointConnector, QuicServer, SELF_SIGNED_DOMAIN};
use citadel_wire::tls::client_config_to_tls_connector;

use crate::constants::TCP_CONN_TIMEOUT;
use crate::proto::misc::native_config::NativeP2PConfig;
use crate::proto::misc::native_io::NativeIO;
use crate::proto::misc::native_upgrade::{QuicRedirectSignal, TcpToQuicUpgrade};
use crate::proto::misc::net::{FirstPacket, GenericNetworkListener, GenericNetworkStream};
use crate::proto::node::TlsDomain;
use crate::proto::packet_processor::includes::Duration;
use crate::proto::peer::p2p_conn_handler::generic_error;

/// Connect to a Citadel server, performing protocol negotiation.
///
/// 1. Creates a TCP connection to `remote`
/// 2. Reads the server's [`FirstPacket`] to discover the transport mode
/// 3. Upgrades to TLS or QUIC as directed by the server
pub async fn c2s_connect(
    timeout: Option<Duration>,
    remote: SocketAddr,
    default_client_config: &Arc<ClientConfig>,
) -> io::Result<GenericNetworkStream> {
    log::trace!(target: "citadel", "C2S connect defaults to {remote:?}");
    let mut stream =
        citadel_wire::socket_helpers::get_tcp_stream(remote, timeout.unwrap_or(TCP_CONN_TIMEOUT))
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
    let bind_addr = stream.local_addr()?;
    log::trace!(target: "citadel", "C2S Bind addr: {bind_addr:?}");
    let first_packet = read_first_packet(&mut stream, timeout).await?;

    match first_packet {
        FirstPacket::OrderedReliable { external_addr } => {
            log::trace!(target: "citadel", "Host claims OrderedReliable (TCP) DEFAULT CONNECTION. External ADDR: {external_addr:?}");
            Ok(GenericNetworkStream::OrderedReliable(stream))
        }

        FirstPacket::OrderedReliableSecure {
            domain,
            external_addr,
            is_self_signed,
        } => {
            log::trace!(target: "citadel", "Host claims OrderedReliableSecure (TLS) CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed? {}", &domain, external_addr, is_self_signed);

            let connector = if is_self_signed {
                citadel_wire::tls::create_client_dangerous_config()
            } else {
                client_config_to_tls_connector(default_client_config.clone())
            };

            let stream = connector
                .connect(
                    pki_types::ServerName::try_from(
                        domain
                            .clone()
                            .unwrap_or_else(|| SELF_SIGNED_DOMAIN.to_string()),
                    )
                    .map_err(|err| generic_error(err.to_string()))?,
                    stream,
                )
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err))?;
            Ok(GenericNetworkStream::OrderedReliableSecure(Box::new(
                stream.into(),
            )))
        }

        FirstPacket::P2P {
            domain,
            external_addr,
            is_self_signed,
        } => {
            log::trace!(target: "citadel", "Host claims P2P (QUIC) CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed: {}", &domain, external_addr, is_self_signed);
            let signal = QuicRedirectSignal {
                domain,
                external_addr,
                is_self_signed,
            };
            <TcpToQuicUpgrade as ProtocolUpgrade<NativeIO>>::connect_target(
                signal,
                bind_addr,
                remote,
                default_client_config,
            )
            .await
        }
    }
}

/// Read the server's first-packet protocol signal.
async fn read_first_packet<Read: AsyncRead + Unpin>(
    stream: Read,
    timeout: Option<Duration>,
) -> io::Result<FirstPacket> {
    let (_stream, ret) = citadel_io::time::timeout(
        timeout.unwrap_or(TCP_CONN_TIMEOUT),
        super::read_one_packet_as_framed(stream),
    )
    .await
    .map_err(|err| io::Error::new(io::ErrorKind::TimedOut, err.to_string()))?
    .map_err(|err| generic_error(err.into_string()))?;
    Ok(ret)
}

/// Connect to a QUIC peer using an existing endpoint.
///
/// Shared helper used by both the C2S connect path (via
/// [`TcpToQuicUpgrade`]) and the P2P hole-punch initiator path.
pub async fn quic_p2p_connect(
    quic_endpoint: citadel_wire::exports::Endpoint,
    timeout: Option<Duration>,
    domain: TlsDomain,
    remote: SocketAddr,
    secure_client_config: Arc<ClientConfig>,
) -> io::Result<GenericNetworkStream> {
    log::trace!(target: "citadel", "Connecting to QUIC node {remote:?}");
    let cfg = if domain.is_some() {
        citadel_wire::quic::rustls_client_config_to_quinn_config(secure_client_config)?
    } else {
        citadel_wire::quic::insecure::configure_client()
    };

    log::trace!(target: "citadel", "Using cfg={cfg:?} to connect to {remote:?}");

    let (conn, sink, stream) = citadel_io::time::timeout(
        timeout.unwrap_or(TCP_CONN_TIMEOUT),
        quic_endpoint.connect_biconn_with(
            remote,
            domain.as_deref().unwrap_or(SELF_SIGNED_DOMAIN),
            Some(cfg),
        ),
    )
    .await?
    .map_err(generic_error)?;
    Ok(GenericNetworkStream::P2P(
        sink,
        stream,
        quic_endpoint,
        Some(conn),
        remote,
    ))
}

/// Create a QUIC listener from a hole-punched UDP socket (non-initiator).
pub fn p2p_listener_from_socket(
    socket: citadel_io::tokio::net::UdpSocket,
    quic_node: Option<citadel_wire::quic::QuicNode>,
    local_addr: SocketAddr,
) -> io::Result<(GenericNetworkListener, SocketAddr)> {
    super::native_bind::create_listener(
        ServerMode::P2P(NativeP2PConfig::self_signed()),
        None,
        quic_node.or_else(|| {
            QuicServer::new_self_signed(socket)
                .map_err(generic_error)
                .ok()
        }),
        local_addr,
    )
}

/// Connect to a peer via QUIC using a hole-punched UDP socket (initiator).
pub async fn p2p_connect_from_socket(
    socket: citadel_io::tokio::net::UdpSocket,
    remote_addr: SocketAddr,
    domain: TlsDomain,
    client_config: Arc<ClientConfig>,
    timeout: Option<Duration>,
) -> io::Result<GenericNetworkStream> {
    let quic_endpoint =
        QuicClient::new_with_rustls_config(socket, client_config.clone()).map_err(generic_error)?;
    quic_p2p_connect(
        quic_endpoint.endpoint,
        timeout,
        domain,
        remote_addr,
        client_config,
    )
    .await
}
