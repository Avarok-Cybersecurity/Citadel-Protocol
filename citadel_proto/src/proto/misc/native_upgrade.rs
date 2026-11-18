//! TCP-to-QUIC protocol upgrade implementation.
//!
//! Implements [`ProtocolUpgrade`] for [`NativeIO`], abstracting the
//! TCP signaling → QUIC data redirect pattern used for P2P connections.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use citadel_io::{ProtocolUpgrade, ServerMode, UpgradeListenerPair};
use citadel_user::serialization::SyncIO;
use citadel_wire::quic::{QuicClient, QuicEndpointConnector, QuicServer, SELF_SIGNED_DOMAIN};

use crate::constants::TCP_CONN_TIMEOUT;
use crate::proto::misc::native_config::NativeP2PConfig;
use crate::proto::misc::native_io::NativeIO;
use crate::proto::misc::net::{
    DualListener, FirstPacket, GenericNetworkListener, GenericNetworkStream,
};
use crate::proto::node::TlsDomain;

/// Redirect signal carrying QUIC connection parameters.
#[derive(Clone)]
pub struct QuicRedirectSignal {
    pub domain: TlsDomain,
    pub external_addr: SocketAddr,
    pub is_self_signed: bool,
}

/// How many ephemeral TCP ports a server draws, for a `:0` bind, looking for one whose UDP twin
/// is free too.
const SERVER_PORT_DRAWS: usize = 8;

fn bind_udp(addr: SocketAddr) -> io::Result<citadel_io::tokio::net::UdpSocket> {
    citadel_wire::socket_helpers::get_udp_socket(addr)
        .map_err(|e| super::io_error_from_anyhow(e, io::ErrorKind::AddrNotAvailable))
}

/// The server's TCP signalling listener and QUIC socket, on one address: a client dials QUIC at
/// the address it reached over TCP. TCP and UDP ports are allocated separately, so the port the
/// OS hands the TCP listener can already be held by an unrelated UDP socket on this host. For an
/// explicit port that is the caller's error to see; for `:0` the caller asked for any port, so
/// the listener is dropped and another port drawn, a bounded number of times.
fn server_socket_pair(
    addr: SocketAddr,
) -> io::Result<(
    citadel_io::tokio::net::TcpListener,
    citadel_io::tokio::net::UdpSocket,
)> {
    // The errno is kept (as `native_bind` keeps it): a caller retrying a reserved ephemeral
    // port on Windows (WSAEACCES) reads it, and `to_string` left only its English.
    let draws = if addr.port() == 0 {
        SERVER_PORT_DRAWS
    } else {
        1
    };
    let mut last = None;
    for _ in 0..draws {
        let tcp = citadel_wire::socket_helpers::get_tcp_listener(addr)
            .map_err(|e| super::io_error_from_anyhow(e, io::ErrorKind::AddrNotAvailable))?;
        match bind_udp(tcp.local_addr()?) {
            Ok(udp) => return Ok((tcp, udp)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                log::warn!(target: "citadel", "UDP twin of {:?} is held by another socket; drawing another port", tcp.local_addr());
                last = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.expect("at least one draw"))
}

/// The client's QUIC socket, on the TCP signalling socket's address when UDP has it free, so one
/// local address carries both (NAT and firewall state made for one serves the other). The two
/// port spaces are allocated separately, and an unrelated UDP socket on this host may hold the
/// TCP socket's port; the shared address is then a preference that cannot be met, and an
/// ephemeral port on the same IP serves. The QUIC connection does not depend on it.
fn client_quic_socket(signalling: SocketAddr) -> io::Result<citadel_io::tokio::net::UdpSocket> {
    match bind_udp(signalling) {
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            log::warn!(target: "citadel", "UDP port of {signalling} is held by another socket; QUIC uses an ephemeral port");
            bind_udp(SocketAddr::new(signalling.ip(), 0))
        }
        res => res,
    }
}

/// TCP-to-QUIC protocol upgrade.
///
/// Sends a [`QuicRedirectSignal`] over a TCP signaling channel, then
/// accepts real connections on a QUIC listener bound to the same address.
pub struct TcpToQuicUpgrade;

impl ProtocolUpgrade<NativeIO> for TcpToQuicUpgrade {
    type Signal = QuicRedirectSignal;

    fn build_signal(target_config: &ServerMode<NativeIO>, client_addr: SocketAddr) -> Self::Signal {
        let ServerMode::P2P(config) = target_config else {
            unreachable!("TcpToQuicUpgrade requires P2P config")
        };
        QuicRedirectSignal {
            domain: config.domain.clone(),
            external_addr: client_addr,
            is_self_signed: config.is_self_signed,
        }
    }

    fn serialize_signal(signal: &Self::Signal) -> io::Result<Bytes> {
        let first_packet = FirstPacket::P2P {
            domain: signal.domain.clone(),
            external_addr: signal.external_addr,
            is_self_signed: signal.is_self_signed,
        };
        first_packet
            .serialize_to_vector()
            .map(Bytes::from)
            .map_err(|e| io::Error::other(e.into_string()))
    }

    fn deserialize_signal(bytes: &[u8]) -> io::Result<Self::Signal> {
        let first_packet = FirstPacket::deserialize_from_vector(bytes)
            .map_err(|e| io::Error::other(e.into_string()))?;
        match first_packet {
            FirstPacket::P2P {
                domain,
                external_addr,
                is_self_signed,
            } => Ok(QuicRedirectSignal {
                domain,
                external_addr,
                is_self_signed,
            }),
            _ => Err(io::Error::other("Expected P2P redirect signal")),
        }
    }

    async fn bind_upgrade_pair(
        target_config: ServerMode<NativeIO>,
        addr: SocketAddr,
    ) -> io::Result<UpgradeListenerPair<NativeIO>> {
        let ServerMode::P2P(ref p2p_config) = target_config else {
            return Err(io::Error::other("TcpToQuicUpgrade requires P2P config"));
        };

        // TCP signaling listener: sends redirect signal to each connecting client
        let redirect_info = Some((p2p_config.domain.clone(), p2p_config.is_self_signed));
        let (tcp_listener, udp_socket) = server_socket_pair(addr)?;
        let bind_addr = tcp_listener.local_addr()?;
        let tcp_gnl = GenericNetworkListener::new_tcp(tcp_listener, redirect_info)?;

        // QUIC target listener on same address
        let NativeP2PConfig {
            crypto,
            domain,
            is_self_signed,
        } = p2p_config.clone();
        let mut quic =
            QuicServer::create(udp_socket, crypto).map_err(|e| io::Error::other(e.to_string()))?;
        quic.tls_domain_opt = domain;
        let quic_gnl = GenericNetworkListener::from_quic_node(quic, is_self_signed)?;

        Ok(UpgradeListenerPair {
            signal_listener: DualListener::new(tcp_gnl, None),
            target_listener: DualListener::new(quic_gnl, None),
            bound_addr: bind_addr,
        })
    }

    async fn connect_target(
        signal: Self::Signal,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        client_config: &super::native_io::NativeClientConfig,
    ) -> io::Result<GenericNetworkStream> {
        let udp_socket = client_quic_socket(local_addr)?;

        // Honor the local client policy: a peer must not be able to force the no-verification path
        // by advertising self-signed / omitting a domain when the client requires verification.
        let require_cert_verification = client_config.require_cert_verification;

        let mut quic_endpoint = if signal.is_self_signed && !require_cert_verification {
            QuicClient::new_no_verify(udp_socket)
        } else {
            QuicClient::new_with_rustls_config(udp_socket, client_config.config.clone())
        }
        .map_err(|e| io::Error::other(e.to_string()))?;

        quic_endpoint.tls_domain_opt.clone_from(&signal.domain);

        // Select QUIC client config based on cert type
        let cfg = if signal.domain.is_some() {
            citadel_wire::quic::rustls_client_config_to_quinn_config(client_config.config.clone())?
        } else if require_cert_verification {
            return Err(io::Error::other(
                "Certificate verification is required, but the peer advertised no domain (would force an insecure QUIC connection)",
            ));
        } else {
            citadel_wire::quic::insecure::configure_client()
        };

        let (conn, sink, stream) = citadel_io::time::timeout(
            Duration::from_secs(TCP_CONN_TIMEOUT.as_secs()),
            quic_endpoint.endpoint.connect_biconn_with(
                remote_addr,
                signal.domain.as_deref().unwrap_or(SELF_SIGNED_DOMAIN),
                Some(cfg),
            ),
        )
        .await
        .map_err(|e| io::Error::other(e.to_string()))?
        .map_err(|e| io::Error::other(e.to_string()))?;

        Ok(GenericNetworkStream::P2P(
            sink,
            stream,
            quic_endpoint.endpoint.clone(),
            Some(conn),
            remote_addr,
        ))
    }

    fn merge_upgrade_listeners(
        signal_listener: DualListener,
        target_listener: DualListener,
    ) -> DualListener {
        DualListener::merge_suppressing_signal(signal_listener, target_listener)
    }
}

#[cfg(test)]
#[path = "native_upgrade_tests.rs"]
mod tests;
