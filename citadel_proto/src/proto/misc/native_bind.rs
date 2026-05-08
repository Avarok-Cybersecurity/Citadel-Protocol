//! Native server bind logic for TCP, TLS, and QUIC listeners.
//!
//! Extracted from `CitadelNode` to satisfy SBIO — all socket creation
//! and listener construction lives here, not in the protocol layer.

use std::io;
use std::net::SocketAddr;

use citadel_io::ServerMode;
use citadel_wire::quic::{QuicNode, QuicServer};

use crate::proto::misc::native_config::{
    NativeOrderedReliableConfig, NativeP2PConfig, NativeSecureConfig,
};
use crate::proto::misc::native_io::NativeIO;
use crate::proto::misc::net::{GenericNetworkListener, TlsListener};
use crate::proto::node::TlsDomain;
use crate::proto::peer::p2p_conn_handler::generic_error;

/// Create a [`GenericNetworkListener`] for any [`ServerMode`] variant.
///
/// Handles TCP, TLS, and QUIC with optional P2P redirect signaling.
pub fn create_listener(
    config: ServerMode<NativeIO>,
    redirect_to_quic: Option<(TlsDomain, bool)>,
    quic_endpoint_opt: Option<QuicNode>,
    bind: SocketAddr,
) -> io::Result<(GenericNetworkListener, SocketAddr)> {
    match config {
        ServerMode::OrderedReliable(NativeOrderedReliableConfig {
            listener: Some(pre_existing),
        }) => {
            let listener = pre_existing
                .lock()
                .take()
                .ok_or_else(|| io::Error::other("TCP listener already taken"))?;
            let bind = listener.local_addr()?;
            Ok((
                GenericNetworkListener::new_tcp(listener, redirect_to_quic)?,
                bind,
            ))
        }

        ServerMode::OrderedReliable(NativeOrderedReliableConfig { listener: None }) => {
            let listener = citadel_wire::socket_helpers::get_tcp_listener(bind)
                .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
            let bind = listener.local_addr()?;
            Ok((
                GenericNetworkListener::new_tcp(listener, redirect_to_quic)?,
                bind,
            ))
        }

        ServerMode::OrderedReliableSecure(NativeSecureConfig {
            interop,
            domain,
            is_self_signed,
        }) => {
            let listener = citadel_wire::socket_helpers::get_tcp_listener(bind)
                .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
            log::trace!(target: "citadel", "Setting up TLS listener socket on {bind:?}");
            let bind = listener.local_addr()?;
            let tls_listener =
                TlsListener::new(listener, interop.tls_acceptor, domain, is_self_signed)?;
            Ok((GenericNetworkListener::new_tls(tls_listener)?, bind))
        }

        ServerMode::P2P(NativeP2PConfig {
            crypto,
            domain,
            is_self_signed,
        }) => {
            log::trace!(target: "citadel", "Setting up QUIC listener socket on {bind:?} | Self-signed? {is_self_signed}");
            let mut quic = if let Some(quic) = quic_endpoint_opt {
                quic
            } else {
                let udp_socket =
                    citadel_wire::socket_helpers::get_udp_socket(bind).map_err(generic_error)?;
                QuicServer::create(udp_socket, crypto).map_err(generic_error)?
            };
            let bind = quic.endpoint.local_addr()?;
            quic.tls_domain_opt = domain;
            Ok((
                GenericNetworkListener::from_quic_node(quic, is_self_signed)?,
                bind,
            ))
        }
    }
}
