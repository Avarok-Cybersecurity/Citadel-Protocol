use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::channel::mpsc::TrySendError;
use futures::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;
use tokio::task::LocalSet;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::auth::proposed_credentials::ProposedCredentials;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::external_services::ServicesObject;
use hyxe_wire::hypernode_type::NodeType;
use hyxe_wire::nat_identification::NatType;
use netbeam::time_tracker::TimeTracker;

use crate::auth::AuthenticationRequest;
use crate::constants::{MAX_OUTGOING_UNPROCESSED_REQUESTS, TCP_CONN_TIMEOUT};
use crate::error::NetworkError;
use crate::functional::PairMap;
use crate::kernel::kernel_communicator::{KernelAsyncCallbackHandler, KernelStreamSubscription};
use crate::kernel::RuntimeFuture;
use crate::proto::hdp_session::{HdpSession, HdpSessionInitMode};
use crate::proto::hdp_session_manager::HdpSessionManager;
use crate::proto::misc::net::{
    DualListener, FirstPacket, GenericNetworkListener, GenericNetworkStream, TlsListener,
};
use crate::proto::misc::session_security_settings::SessionSecuritySettings;
use crate::proto::misc::underlying_proto::UnderlyingProtocol;
use crate::proto::outbound_sender::{unbounded, BoundedReceiver, BoundedSender, UnboundedSender};
use crate::proto::packet_processor::includes::Duration;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::channel::{PeerChannel, UdpChannel};
use crate::proto::peer::group_channel::GroupChannel;
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::peer::peer_layer::{MailboxTransfer, PeerSignal, UdpMode};
use crate::proto::state_container::{VirtualConnectionType, VirtualTargetType};
use hyxe_crypt::prelude::SecBuffer;
use hyxe_crypt::streaming_crypt_scrambler::ObjectSource;
use hyxe_user::backend::utils::ObjectTransferHandle;
use hyxe_wire::exports::tokio_rustls::rustls::{ClientConfig, ServerName};
use hyxe_wire::exports::Endpoint;
use hyxe_wire::quic::{QuicEndpointConnector, QuicNode, QuicServer, SELF_SIGNED_DOMAIN};
use hyxe_wire::tls::client_config_to_tls_connector;
use std::convert::TryFrom;

pub type TlsDomain = Option<String>;

// The outermost abstraction for the networking layer. We use Rc to allow ensure single-threaded performance
// by default, but settings can be changed in crate::macros::*.
define_outer_struct_wrapper!(HdpServer, HdpServerInner);

/// Inner device for the HdpServer
pub struct HdpServerInner {
    primary_socket: Option<DualListener>,
    /// Key: cid (to account for multiple clients from the same node)
    session_manager: HdpSessionManager,
    to_kernel: UnboundedSender<NodeResult>,
    local_node_type: NodeType,
    // Applies only to listeners, not outgoing connections
    underlying_proto: UnderlyingProtocol,
    nat_type: NatType,
    // for TLS params
    client_config: Arc<ClientConfig>,
}

impl HdpServer {
    /// Creates a new [HdpServer]
    pub(crate) async fn init(
        local_node_type: NodeType,
        to_kernel: UnboundedSender<NodeResult>,
        account_manager: AccountManager,
        shutdown: tokio::sync::oneshot::Sender<()>,
        underlying_proto: UnderlyingProtocol,
        client_config: Option<Arc<ClientConfig>>,
    ) -> io::Result<(
        NodeRemote,
        Pin<Box<dyn RuntimeFuture>>,
        Option<LocalSet>,
        KernelAsyncCallbackHandler,
    )> {
        let (primary_socket, bind_addr) = match local_node_type {
            NodeType::Server(bind_addr) => {
                Self::server_create_primary_listen_socket(underlying_proto.clone(), &bind_addr)?
                    .map_left(|l| Some(l))
                    .map_right(|r| Some(r))
            }

            NodeType::Peer => (None, None),
        };

        if let Some(local_bind_addr) = bind_addr {
            log::trace!(target: "lusna", "HdpServer established on {}", local_bind_addr);
        } else {
            log::trace!(target: "lusna", "HdpClient Established")
        }

        let client_config = if let Some(config) = client_config {
            config
        } else {
            let native_certs = hyxe_wire::tls::load_native_certs_async().await?;
            Arc::new(
                hyxe_wire::tls::create_rustls_client_config(&native_certs)
                    .map_err(|err| generic_error(err.to_string()))?,
            )
        };

        let time_tracker = TimeTracker::new();
        let session_manager = HdpSessionManager::new(
            local_node_type,
            to_kernel.clone(),
            account_manager.clone(),
            time_tracker.clone(),
            client_config.clone(),
        );

        let nat_type = NatType::identify().await.map_err(|err| err.std())?;

        let inner = HdpServerInner {
            underlying_proto,
            local_node_type,
            primary_socket,
            to_kernel,
            session_manager,
            nat_type,
            client_config,
        };

        let this = Self::from(inner);
        Ok(HdpServer::load(this, account_manager, shutdown))
    }

    /// Note: spawning via handle is more efficient than joining futures. Source: https://cafbit.com/post/tokio_internals/
    /// To handle the shutdown process, we need
    ///
    /// This will panic if called twice in succession without a proper server reload.
    ///
    /// Returns a handle to communicate with the [HdpServer].
    #[allow(unused_results, unused_must_use)]
    fn load(
        this: HdpServer,
        account_manager: AccountManager,
        shutdown: tokio::sync::oneshot::Sender<()>,
    ) -> (
        NodeRemote,
        Pin<Box<dyn RuntimeFuture>>,
        Option<LocalSet>,
        KernelAsyncCallbackHandler,
    ) {
        // Allow the listeners to read data without instantly returning
        // Load the readers
        let read = inner!(this);

        let sess_mgr = read.session_manager.clone();
        let kernel_tx = read.to_kernel.clone();
        let node_type = read.local_node_type;

        let (session_spawner_tx, session_spawner_rx) = unbounded();
        let session_spawner = HdpSession::session_future_receiver(session_spawner_rx);

        let (outbound_send_request_tx, outbound_send_request_rx) =
            BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS); // for the Hdp remote
        let kernel_async_callback_handler = KernelAsyncCallbackHandler::new();
        let remote = NodeRemote::new(
            outbound_send_request_tx,
            kernel_async_callback_handler.clone(),
            account_manager,
            node_type,
        );
        let tt = read
            .session_manager
            .load_server_remote_get_tt(remote.clone());
        let session_manager = read.session_manager.clone();

        std::mem::drop(read);

        let (
            outbound_kernel_request_handler,
            primary_stream_listener,
            peer_container,
            localset_opt,
        ) = {
            #[cfg(feature = "multi-threaded")]
            {
                let outbound_kernel_request_handler = Self::outbound_kernel_request_handler(
                    this.clone(),
                    kernel_tx.clone(),
                    outbound_send_request_rx,
                    session_spawner_tx.clone(),
                );
                let primary_stream_listener = if node_type.is_server() {
                    Some(Self::listen_primary(
                        this.clone(),
                        tt,
                        kernel_tx.clone(),
                        session_spawner_tx.clone(),
                    ))
                } else {
                    None
                };
                let peer_container = HdpSessionManager::run_peer_container(session_manager);
                let localset_opt = None;
                (
                    outbound_kernel_request_handler,
                    primary_stream_listener,
                    peer_container,
                    localset_opt,
                )
            }

            #[cfg(not(feature = "multi-threaded"))]
            {
                let localset = LocalSet::new();
                let outbound_kernel_request_handler = Self::outbound_kernel_request_handler(
                    this.clone(),
                    kernel_tx.clone(),
                    outbound_send_request_rx,
                    session_spawner_tx.clone(),
                );
                let primary_stream_listener = if node_type.is_server() {
                    Some(Self::listen_primary(
                        this.clone(),
                        tt,
                        kernel_tx.clone(),
                        session_spawner_tx.clone(),
                    ))
                } else {
                    None
                };
                let peer_container = HdpSessionManager::run_peer_container(session_manager);
                (
                    outbound_kernel_request_handler,
                    primary_stream_listener,
                    peer_container,
                    Some(localset),
                )
            }
        };

        let server_future = async move {
            let res = if let Some(primary_stream_listener) = primary_stream_listener {
                tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::trace!(target: "lusna", "OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = primary_stream_listener => res1,
                    res2 = peer_container => res2,
                    res3 = session_spawner => res3
                }
            } else {
                tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::trace!(target: "lusna", "OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = peer_container => res1,
                    res2 = session_spawner => res2
                }
            };

            if let Err(_) = kernel_tx.unbounded_send(NodeResult::Shutdown) {
                log::warn!(target: "lusna", "Unable to send shutdown result to kernel (kernel died prematurely?)");
            }

            // the kernel will wait until the server shuts down to prevent cleanup tasks from being killed too early
            shutdown.send(());

            tokio::time::timeout(Duration::from_millis(1000), sess_mgr.shutdown())
                .await
                .map_err(|err| NetworkError::Generic(err.to_string()))?;

            log::trace!(target: "lusna", "HdpServer shutting down (future ended)...");

            res
        };

        //handle.load_server_future(server_future);

        (
            remote,
            Box::pin(server_future),
            localset_opt,
            kernel_async_callback_handler,
        )
    }

    pub fn server_create_primary_listen_socket<T: ToSocketAddrs>(
        underlying_proto: UnderlyingProtocol,
        full_bind_addr: T,
    ) -> io::Result<(DualListener, SocketAddr)> {
        match &underlying_proto {
            UnderlyingProtocol::Tls(..) | UnderlyingProtocol::Tcp => {
                Self::create_listen_socket(underlying_proto, None, None, full_bind_addr)
                    .map(|r| (DualListener::new(r.0, None), r.1))
            }

            UnderlyingProtocol::Quic(_, domain, is_self_signed) => {
                // we need two sockets: one for TCP connection to allow connecting peers to determine the protocol, then another for QUIC
                let (tcp_listener, bind_addr) = Self::create_listen_socket(
                    UnderlyingProtocol::Tcp,
                    Some((domain.clone(), *is_self_signed)),
                    None,
                    full_bind_addr,
                )?;
                let (quic_listener, _bind_addr_quic) =
                    Self::create_listen_socket(underlying_proto, None, None, bind_addr)?;
                Ok((
                    DualListener::new(tcp_listener, Some(quic_listener)),
                    bind_addr,
                ))
            }
        }
    }

    pub fn create_listen_socket<T: ToSocketAddrs>(
        underlying_proto: UnderlyingProtocol,
        redirect_to_quic: Option<(TlsDomain, bool)>,
        quic_endpoint_opt: Option<QuicNode>,
        full_bind_addr: T,
    ) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        let bind: SocketAddr =
            full_bind_addr
                .to_socket_addrs()?
                .next()
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "bad addr",
                ))?;
        Self::bind_defaults(underlying_proto, redirect_to_quic, quic_endpoint_opt, bind)
    }

    /// redirect_to_quic is only applicable when using TCP
    /// - quic_endpoint_opt is only relevant (yet optional) when the underlying proto specified is quic
    fn bind_defaults(
        underlying_proto: UnderlyingProtocol,
        redirect_to_quic: Option<(TlsDomain, bool)>,
        quic_endpoint_opt: Option<QuicNode>,
        bind: SocketAddr,
    ) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        match underlying_proto {
            UnderlyingProtocol::Tls(..) | UnderlyingProtocol::Tcp => {
                hyxe_wire::socket_helpers::get_tcp_listener(bind)
                    .and_then(|listener| {
                        log::trace!(target: "lusna", "Setting up {:?} listener socket on {:?}", &underlying_proto, bind);
                        let bind = listener.local_addr()?;
                        match underlying_proto {
                            UnderlyingProtocol::Tcp => {
                                Ok((GenericNetworkListener::new_tcp(listener, redirect_to_quic)?, bind))
                            }

                            UnderlyingProtocol::Tls(interop, domain, is_self_signed) => {
                                let tls_listener = TlsListener::new(listener, interop.tls_acceptor, domain, is_self_signed)?;
                                Ok((GenericNetworkListener::new_tls(tls_listener)?, bind))
                            }

                            UnderlyingProtocol::Quic(..) => {
                                unreachable!("TCP listener called, but not a QUIC listener")
                            }
                        }
                    }).map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))
            }

            UnderlyingProtocol::Quic(crypto, domain, is_self_signed) => {
                log::trace!(target: "lusna", "Setting up QUIC listener socket on {:?} | Self-signed? {}", bind, is_self_signed);

                let mut quic = if let Some(quic) = quic_endpoint_opt {
                    quic
                } else {
                    let udp_socket = hyxe_wire::socket_helpers::get_udp_socket(bind).map_err(generic_error)?;
                    QuicServer::new(udp_socket, crypto).map_err(generic_error)?
                };

                let bind = quic.endpoint.local_addr()?;

                quic.tls_domain_opt = domain;

                Ok((GenericNetworkListener::from_quic_node(quic, is_self_signed)?, bind))
            }
        }
    }

    /// Returns a TcpStream to the remote addr, as well as a local TcpListener on the same bind addr going to remote
    /// to allow for TCP hole-punching (we need the same port to cover port-restricted NATS, worst-case scenario)
    ///
    /// The remote is usually the central server. Then the P2P listener binds to it to allow NATs to keep the hole punched
    ///
    /// It is expected that the listener_underlying_proto is QUIC here since this is called for p2p connections!
    pub(crate) async fn create_session_transport_init<R: ToSocketAddrs>(
        remote: R,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<GenericNetworkStream> {
        // We start by creating a client to server connection
        let (stream, _quic_endpoint_generated_during_connect) =
            Self::create_c2s_connect_socket(remote, None, default_client_config).await?;

        log::trace!(target: "lusna", "[Client] Finished connecting to server {} w/ proto {:?}", stream.peer_addr()?, &stream);
        Ok(stream)
    }

    /// Important: Assumes UDP NAT traversal has concluded. This should ONLY be used for p2p
    /// This takes the local socket AND QuicNode instance
    #[allow(dead_code)]
    pub async fn create_p2p_quic_connect_socket<R: ToSocketAddrs>(
        quic_endpoint: Endpoint,
        remote: R,
        tls_domain: TlsDomain,
        timeout: Option<Duration>,
        secure_client_config: Arc<ClientConfig>,
    ) -> io::Result<GenericNetworkStream> {
        let remote: SocketAddr = remote.to_socket_addrs()?.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "bad addr",
        ))?;
        Self::quic_p2p_connect_defaults(
            quic_endpoint,
            timeout,
            tls_domain,
            remote,
            secure_client_config,
        )
        .await
    }

    /// - force_use_default_config: if true, this will unconditionally use the default client config already present inside the quic_endpoint parameter
    pub async fn quic_p2p_connect_defaults(
        quic_endpoint: Endpoint,
        timeout: Option<Duration>,
        domain: TlsDomain,
        remote: SocketAddr,
        secure_client_config: Arc<ClientConfig>,
    ) -> io::Result<GenericNetworkStream> {
        log::trace!(target: "lusna", "Connecting to QUIC node {:?}", remote);
        // when using p2p quic, if domain is some, then we will use the default cfg
        let cfg = if domain.is_some() {
            hyxe_wire::quic::rustls_client_config_to_quinn_config(secure_client_config)
        } else {
            // if there is no domain specified, assume self-signed (For now)
            // this is non-blocking since native certs won't be loaded
            hyxe_wire::quic::insecure::configure_client()
        };

        log::trace!(target: "lusna", "Using cfg={:?} to connect to {:?}", cfg, remote);

        // we MUST use the connect_biconn_WITH below since we are using the server quic instance to make this outgoing connection
        let (conn, sink, stream) = tokio::time::timeout(
            timeout.unwrap_or(TCP_CONN_TIMEOUT),
            quic_endpoint.connect_biconn_with(
                remote,
                domain
                    .as_ref()
                    .map(|r| r.as_str())
                    .unwrap_or(SELF_SIGNED_DOMAIN),
                Some(cfg),
            ),
        )
        .await?
        .map_err(generic_error)?;
        Ok(GenericNetworkStream::Quic(
            sink,
            stream,
            quic_endpoint,
            Some(conn),
            remote,
        ))
    }

    /// Only for client to server conns
    pub async fn create_c2s_connect_socket<R: ToSocketAddrs>(
        remote: R,
        timeout: Option<Duration>,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        let remote: SocketAddr = remote.to_socket_addrs()?.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "bad addr",
        ))?;
        Self::c2s_connect_defaults(timeout, remote, default_client_config).await
    }

    pub async fn c2s_connect_defaults(
        timeout: Option<Duration>,
        remote: SocketAddr,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        log::trace!(target: "lusna", "C2S connect defaults to {:?}", remote);
        let mut stream =
            hyxe_wire::socket_helpers::get_tcp_stream(remote, timeout.unwrap_or(TCP_CONN_TIMEOUT))
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
        let bind_addr = stream.local_addr()?;
        log::trace!(target: "lusna", "C2S Bind addr: {:?}", bind_addr);
        let first_packet = Self::read_first_packet(&mut stream, timeout).await?;

        match first_packet {
            FirstPacket::Tcp { external_addr } => {
                log::trace!(target: "lusna", "Host claims TCP DEFAULT CONNECTION. External ADDR: {:?}", external_addr);
                Ok((GenericNetworkStream::Tcp(stream), None))
            }

            FirstPacket::Tls {
                domain,
                external_addr,
                is_self_signed,
            } => {
                log::trace!(target: "lusna", "Host claims TLS CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed? {}", &domain, external_addr, is_self_signed);

                let connector = if is_self_signed {
                    hyxe_wire::tls::create_client_dangerous_config()
                } else {
                    client_config_to_tls_connector(default_client_config.clone())
                };

                let stream = connector
                    .connect(
                        ServerName::try_from(
                            domain
                                .as_ref()
                                .map(|r| r.as_str())
                                .unwrap_or(SELF_SIGNED_DOMAIN),
                        )
                        .map_err(|err| generic_error(err.to_string()))?,
                        stream,
                    )
                    .await
                    .map_err(|err| {
                        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err)
                    })?;
                Ok((GenericNetworkStream::Tls(stream.into()), None))
            }
            FirstPacket::Quic {
                domain,
                external_addr,
                is_self_signed,
            } => {
                log::trace!(target: "lusna", "Host claims QUIC CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed: {}", &domain, external_addr, is_self_signed);
                let udp_socket =
                    hyxe_wire::socket_helpers::get_udp_socket(bind_addr).map_err(generic_error)?; // bind to same address as tcp for firewall purposes
                let mut quic_endpoint = if is_self_signed {
                    hyxe_wire::quic::QuicClient::new_no_verify(udp_socket).map_err(generic_error)?
                } else {
                    hyxe_wire::quic::QuicClient::new_with_config(
                        udp_socket,
                        default_client_config.clone(),
                    )
                    .map_err(generic_error)?
                };

                quic_endpoint.tls_domain_opt = domain.clone();

                Self::quic_p2p_connect_defaults(
                    quic_endpoint.endpoint.clone(),
                    timeout,
                    domain,
                    remote,
                    default_client_config.clone(),
                )
                .await
                .map(|r| (r, Some(quic_endpoint)))
            }
        }
    }

    async fn read_first_packet<R: AsyncRead + Unpin>(
        stream: R,
        timeout: Option<Duration>,
    ) -> std::io::Result<FirstPacket> {
        let (_stream, ret) = tokio::time::timeout(
            timeout.unwrap_or(TCP_CONN_TIMEOUT),
            super::misc::read_one_packet_as_framed(stream),
        )
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string()))?
        .map_err(|err| generic_error(err.into_string()))?;
        Ok(ret)
    }

    /// In impersonal mode, each hypernode needs to check for incoming connections on the primary port.
    /// Once a TcpStream is established, it is passed into the underlying HdpSessionManager and a Session
    /// is created to handle the stream.
    ///
    /// In personal mode, if a new connection needs to be forged with another node, then a new SO_REUSE socket
    /// will need to be created that is bound to the local primary port and connected to the adjacent hypernode's
    /// primary port. That socket will be created in the underlying HdpSessionManager during the connection process
    async fn listen_primary(
        server: HdpServer,
        _tt: TimeTracker,
        to_kernel: UnboundedSender<NodeResult>,
        session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>,
    ) -> Result<(), NetworkError> {
        let primary_port_future = {
            let mut this = inner_mut!(server);
            let listener = this.primary_socket.take().unwrap();
            let session_manager = this.session_manager.clone();
            let local_nat_type = this.nat_type.clone();
            std::mem::drop(this);
            Self::primary_session_creator_loop(
                to_kernel,
                local_nat_type,
                session_manager,
                listener,
                session_spawner,
            )
        };

        primary_port_future.await
    }

    async fn primary_session_creator_loop(
        to_kernel: UnboundedSender<NodeResult>,
        local_nat_type: NatType,
        session_manager: HdpSessionManager,
        mut socket: DualListener,
        session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>,
    ) -> Result<(), NetworkError> {
        loop {
            match socket.next().await {
                Some(Ok((stream, peer_addr))) => {
                    log::trace!(target: "lusna", "Received stream from {:?}", peer_addr);
                    let local_bind_addr = stream.local_addr().unwrap();

                    log::trace!(target: "lusna", "[Server] Starting connection with remote={} w/ proto={:?}", peer_addr, &stream);

                    match session_manager.process_new_inbound_connection(
                        local_bind_addr,
                        local_nat_type.clone(),
                        peer_addr,
                        stream,
                    ) {
                        Ok(session) => {
                            session_spawner
                                .unbounded_send(session)
                                .map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            to_kernel.unbounded_send(NodeResult::InternalServerError(
                                None,
                                format!(
                                    "HDP Server dropping connection to {}. Reason: {}",
                                    peer_addr,
                                    err.to_string()
                                ),
                            ))?;
                        }
                    }
                }

                Some(Err(err)) => {
                    const WSACCEPT_ERROR: i32 = 10093;
                    if err.raw_os_error().unwrap_or(-1) != WSACCEPT_ERROR {
                        log::error!(target: "lusna", "Error accepting stream: {}", err.to_string());
                    }
                }

                None => {
                    log::error!(target: "lusna", "Primary session listener returned None");
                    return Err(NetworkError::InternalError("Primary session listener died"));
                }
            }
        }
    }

    async fn outbound_kernel_request_handler(
        this: HdpServer,
        ref to_kernel_tx: UnboundedSender<NodeResult>,
        mut outbound_send_request_rx: BoundedReceiver<(NodeRequest, Ticket)>,
        session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>,
    ) -> Result<(), NetworkError> {
        let (
            local_node_type,
            session_manager,
            listener_underlying_proto,
            local_nat_type,
            default_client_config,
        ) = {
            let read = inner!(this);
            let local_node_type = read.local_node_type;
            let listener_underlying_proto = read.underlying_proto.clone();

            // We need only the underlying [HdpSessionManager]
            let session_manager = read.session_manager.clone();
            let local_nat_type = read.nat_type.clone();
            let default_client_config = read.client_config.clone();
            // Drop the read handle; we are done with it
            //std::mem::drop(read);
            (
                local_node_type,
                session_manager,
                listener_underlying_proto,
                local_nat_type,
                default_client_config,
            )
        };

        let send_error = |ticket_id: Ticket, err: NetworkError| {
            let err = err.into_string();
            if let Err(_) = to_kernel_tx.unbounded_send(NodeResult::InternalServerError(
                Some(ticket_id),
                err.clone(),
            )) {
                log::error!(target: "lusna", "TO_KERNEL_TX Error: {:?}", err);
                return Err(NetworkError::InternalError(
                    "kernel disconnected from hypernode instance",
                ));
            } else {
                Ok(())
            }
        };

        while let Some((outbound_request, ticket_id)) = outbound_send_request_rx.next().await {
            match outbound_request {
                NodeRequest::GroupBroadcastCommand(implicated_cid, cmd) => {
                    if let Err(err) = session_manager.process_outbound_broadcast_command(
                        ticket_id,
                        implicated_cid,
                        cmd,
                    ) {
                        send_error(ticket_id, err)?;
                    }
                }

                NodeRequest::RegisterToHypernode(peer_addr, credentials, security_settings) => {
                    match session_manager
                        .initiate_connection(
                            local_node_type,
                            local_nat_type.clone(),
                            HdpSessionInitMode::Register(peer_addr, credentials),
                            ticket_id,
                            None,
                            listener_underlying_proto.clone(),
                            None,
                            None,
                            security_settings,
                            &default_client_config,
                        )
                        .await
                    {
                        Ok(session) => {
                            session_spawner
                                .unbounded_send(session)
                                .map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            send_error(ticket_id, err)?;
                        }
                    }
                }

                NodeRequest::ConnectToHypernode(
                    authentication_request,
                    connect_mode,
                    udp_mode,
                    keep_alive_timeout,
                    security_settings,
                ) => {
                    match session_manager
                        .initiate_connection(
                            local_node_type,
                            local_nat_type.clone(),
                            HdpSessionInitMode::Connect(authentication_request),
                            ticket_id,
                            Some(connect_mode),
                            listener_underlying_proto.clone(),
                            Some(udp_mode),
                            keep_alive_timeout.map(|val| (val as i64) * 1_000_000_000),
                            security_settings,
                            &default_client_config,
                        )
                        .await
                    {
                        Ok(session) => {
                            session_spawner
                                .unbounded_send(session)
                                .map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            send_error(ticket_id, err)?;
                        }
                    }
                }

                NodeRequest::DisconnectFromHypernode(implicated_cid, target) => {
                    if let Err(err) =
                        session_manager.initiate_disconnect(implicated_cid, target, ticket_id)
                    {
                        send_error(ticket_id, err)?;
                    }
                }

                NodeRequest::ReKey(virtual_target) => {
                    if let Err(err) =
                        session_manager.initiate_update_drill_subroutine(virtual_target, ticket_id)
                    {
                        send_error(ticket_id, err)?;
                    }
                }

                NodeRequest::DeregisterFromHypernode(implicated_cid, virtual_connection_type) => {
                    if let Err(err) = session_manager.initiate_deregistration_subroutine(
                        implicated_cid,
                        virtual_connection_type,
                        ticket_id,
                    ) {
                        send_error(ticket_id, err)?;
                    }
                }

                // TODO: Update this to include security levels (FCM conflicts though)
                NodeRequest::PeerCommand(implicated_cid, peer_command) => {
                    if let Err(err) = session_manager
                        .dispatch_peer_command(
                            implicated_cid,
                            ticket_id,
                            peer_command,
                            SecurityLevel::LOW,
                        )
                        .await
                    {
                        send_error(ticket_id, err)?;
                    }
                }

                NodeRequest::SendObject(path, chunk_size, implicated_cid, virtual_target) => {
                    if let Err(err) = session_manager.process_outbound_file(
                        ticket_id,
                        chunk_size,
                        path,
                        implicated_cid,
                        virtual_target,
                        SecurityLevel::LOW,
                    ) {
                        send_error(ticket_id, err)?;
                    }
                }

                NodeRequest::GetActiveSessions => {
                    if let Err(err) = to_kernel_tx.unbounded_send(NodeResult::SessionList(
                        ticket_id,
                        session_manager.get_active_sessions(),
                    )) {
                        send_error(ticket_id, NetworkError::Generic(err.to_string()))?;
                    }
                }

                NodeRequest::Shutdown => {
                    break;
                }
            }
        }

        Ok(())
    }
}

/// allows convenient communication with the server
#[derive(Clone)]
pub struct NodeRemote {
    outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
    inner: Arc<HdpServerRemoteInner>,
}

struct HdpServerRemoteInner {
    callback_handler: KernelAsyncCallbackHandler,
    node_type: NodeType,
    account_manager: AccountManager,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, &mut)]
pub trait Remote: Clone + Send {
    async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError>;
    async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError>;
    async fn send_callback(&mut self, request: NodeRequest) -> Result<NodeResult, NetworkError>;
    fn account_manager(&self) -> &AccountManager;
    fn get_next_ticket(&self) -> Ticket;
}

#[async_trait::async_trait]
impl Remote for NodeRemote {
    async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        NodeRemote::send(self, request).await
    }

    async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        NodeRemote::send_with_custom_ticket(self, ticket, request).await
    }

    async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        NodeRemote::send_callback_subscription(self, request).await
    }

    async fn send_callback(&mut self, request: NodeRequest) -> Result<NodeResult, NetworkError> {
        NodeRemote::send_callback(self, request).await
    }

    fn account_manager(&self) -> &AccountManager {
        NodeRemote::account_manager(self)
    }

    fn get_next_ticket(&self) -> Ticket {
        NodeRemote::get_next_ticket(self)
    }
}

impl Debug for NodeRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HdpServerRemote")
    }
}

impl NodeRemote {
    /// Creates a new [HdpServerRemote]
    pub(crate) fn new(
        outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
        callback_handler: KernelAsyncCallbackHandler,
        account_manager: AccountManager,
        node_type: NodeType,
    ) -> Self {
        // starts at 1. Ticket 0 is for reserved
        Self {
            outbound_send_request_tx,
            inner: Arc::new(HdpServerRemoteInner {
                callback_handler,
                account_manager,
                node_type,
            }),
        }
    }

    /// Especially used to keep track of a conversation (b/c a certain ticket number may be expected)
    pub async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        self.outbound_send_request_tx.send((request, ticket)).await
    }

    /// Sends a request to the HDP server. This should always be used to communicate with the server
    /// in order to obtain a ticket
    pub async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    /// Returns an error if the ticket is already registered for a callback
    pub async fn send_callback_custom_ticket(
        &mut self,
        request: NodeRequest,
        ticket: Ticket,
    ) -> Result<NodeResult, NetworkError> {
        let rx = self.inner.callback_handler.register_future(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => rx
                .await
                .map_err(|err| NetworkError::Generic(err.to_string())),

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Returns an error if the ticket is already registered for a stream-callback
    pub(crate) async fn send_callback_subscription_custom_ticket(
        &mut self,
        request: NodeRequest,
        ticket: Ticket,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let rx = self.inner.callback_handler.register_stream(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => Ok(rx),

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_subscription_custom_ticket(request, ticket)
            .await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback(
        &mut self,
        request: NodeRequest,
    ) -> Result<NodeResult, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_custom_ticket(request, ticket).await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket (with a timeout)
    pub async fn send_callback_timeout(
        &mut self,
        request: NodeRequest,
        timeout: Duration,
    ) -> Result<NodeResult, NetworkError> {
        tokio::time::timeout(timeout, self.send_callback(request))
            .await
            .map_err(|_| NetworkError::Timeout(0))?
    }

    /// Safely shutsdown the internal server
    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        let _ = self.send(NodeRequest::Shutdown).await?;
        self.outbound_send_request_tx.close().await
    }

    // Note: when two nodes create a ticket, there may be equivalent values
    // Thus, use UUID's instead
    pub fn get_next_ticket(&self) -> Ticket {
        uuid::Uuid::new_v4().as_u128().into()
    }

    pub fn try_send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), TrySendError<(NodeRequest, Ticket)>> {
        self.outbound_send_request_tx.try_send((request, ticket))
    }

    pub fn try_send(
        &mut self,
        request: NodeRequest,
    ) -> Result<(), TrySendError<(NodeRequest, Ticket)>> {
        let ticket = self.get_next_ticket();
        self.outbound_send_request_tx.try_send((request, ticket))
    }

    pub fn local_node_type(&self) -> &NodeType {
        &self.inner.node_type
    }

    pub fn account_manager(&self) -> &AccountManager {
        &self.inner.account_manager
    }
}

impl Unpin for NodeRemote {}

impl Sink<(Ticket, NodeRequest)> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_ready(self, cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: (Ticket, NodeRequest),
    ) -> Result<(), Self::Error> {
        Pin::new(&mut self.outbound_send_request_tx).start_send((item.1, item.0))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_flush(self, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_close(self, cx)
    }
}

impl Sink<NodeRequest> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: NodeRequest) -> Result<(), Self::Error> {
        let ticket = self.get_next_ticket();
        Pin::new(&mut self.outbound_send_request_tx).start_send((item, ticket))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx)
            .poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx)
            .poll_close(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

/// These are sent down the stack into the server. Most of the requests expect a ticket ID
/// in order for processes sitting above the [Kernel] to know how the request went
#[allow(variant_size_differences)]
pub enum NodeRequest {
    /// Sends a request to the underlying HdpSessionManager to begin connecting to a new client
    RegisterToHypernode(SocketAddr, ProposedCredentials, SessionSecuritySettings),
    /// A high-level peer command. Can be used to facilitate communications between nodes in the HyperLAN
    PeerCommand(u64, PeerSignal),
    /// For submitting a de-register request
    DeregisterFromHypernode(u64, VirtualConnectionType),
    /// Implicated CID, creds, connect mode, fcm keys, TCP/TLS only, keep alive timeout, security settings
    ConnectToHypernode(
        AuthenticationRequest,
        ConnectMode,
        UdpMode,
        Option<u64>,
        SessionSecuritySettings,
    ),
    /// Updates the drill for the given CID
    ReKey(VirtualTargetType),
    /// Send a file
    SendObject(Box<dyn ObjectSource>, Option<usize>, u64, VirtualTargetType),
    /// A group-message related command
    GroupBroadcastCommand(u64, GroupBroadcast),
    /// Tells the server to disconnect a session (implicated cid, target_cid)
    DisconnectFromHypernode(u64, VirtualConnectionType),
    /// Returns a list of connected sessions
    GetActiveSessions,
    /// shutdown signal
    Shutdown,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
/// If force_login is true, the protocol will disconnect any previously existent sessions in the session manager attributed to the account logging-in (so long as login succeeds)
/// The default is a Standard login that will with force_login set to false
pub enum ConnectMode {
    Standard { force_login: bool },
    Fetch { force_login: bool },
}

impl Default for ConnectMode {
    fn default() -> Self {
        Self::Standard { force_login: false }
    }
}

/// This type is for relaying results between the lower-level server and the higher-level kernel
/// TODO: Convert to enum structs
#[derive(Debug)]
pub enum NodeResult {
    /// Returns the CNAC which was created during the registration process
    RegisterOkay(Ticket, ClientNetworkAccount, Vec<u8>),
    /// The registration was a failure
    RegisterFailure(Ticket, String),
    /// When de-registration occurs. Third is_personal, Fourth is true if success, false otherwise
    DeRegistration(u64, Option<Ticket>, bool),
    /// Connection succeeded for the cid self.0. bool is "is personal"
    ConnectSuccess(
        Ticket,
        u64,
        SocketAddr,
        bool,
        VirtualConnectionType,
        ServicesObject,
        String,
        PeerChannel,
        Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
    ),
    /// The connection was a failure
    ConnectFail(Ticket, Option<u64>, String),
    /// The outbound request was rejected
    OutboundRequestRejected(Ticket, Option<Vec<u8>>),
    /// For file transfers. Implicated CID, Peer/Target CID, object ID
    ObjectTransferHandle(Ticket, ObjectTransferHandle),
    /// Data has been delivered for implicated cid self.0. The original outbound send request's ticket
    /// will be returned in the delivery, thus enabling higher-level abstractions to listen for data
    /// returns
    MessageDelivery(Ticket, u64, SecBuffer),
    MessageDelivered(Ticket),
    /// Mailbox
    MailboxDelivery(u64, Option<Ticket>, MailboxTransfer),
    /// Peer result
    PeerEvent(PeerSignal, Ticket),
    /// For denoting a channel was created
    GroupChannelCreated(Ticket, GroupChannel),
    /// for group-related events. Implicated cid, ticket, group info
    GroupEvent(u64, Ticket, GroupBroadcast),
    /// vt-cxn-type is optional, because it may have only been a provisional connection
    Disconnect(Ticket, u128, bool, Option<VirtualConnectionType>, String),
    /// An internal error occured
    InternalServerError(Option<Ticket>, String),
    /// A channel was created, with channel_id = ticket (same as post-connect ticket received)
    PeerChannelCreated(
        Ticket,
        PeerChannel,
        Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
    ),
    /// A list of running sessions
    SessionList(Ticket, Vec<u64>),
    /// For shutdowns
    Shutdown,
}

impl NodeResult {
    pub fn is_connect_success_type(&self) -> bool {
        match self {
            NodeResult::ConnectSuccess(..) => true,
            _ => false,
        }
    }

    pub fn ticket(&self) -> Option<Ticket> {
        match self {
            NodeResult::RegisterOkay(t, _, _) => Some(*t),
            NodeResult::RegisterFailure(t, _) => Some(*t),
            NodeResult::DeRegistration(_, t, ..) => t.clone(),
            NodeResult::ConnectSuccess(t, ..) => Some(*t),
            NodeResult::ConnectFail(t, _, _) => Some(*t),
            NodeResult::OutboundRequestRejected(t, _) => Some(*t),
            NodeResult::ObjectTransferHandle(t, ..) => Some(*t),
            NodeResult::MessageDelivery(t, _, _) => Some(*t),
            NodeResult::MessageDelivered(t) => Some(*t),
            NodeResult::MailboxDelivery(_, t, _) => t.clone(),
            NodeResult::PeerEvent(_, t) => Some(*t),
            NodeResult::GroupEvent(_, t, _) => Some(*t),
            NodeResult::PeerChannelCreated(t, ..) => Some(*t),
            NodeResult::GroupChannelCreated(t, _) => Some(*t),
            NodeResult::Disconnect(t, _, _, _, _) => Some(*t),
            NodeResult::InternalServerError(t, _) => t.clone(),
            NodeResult::SessionList(t, _) => Some(*t),
            NodeResult::Shutdown => None,
        }
    }
}

/// A type sent through the server when a request is made
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Ticket(pub u128);

impl Into<Ticket> for u128 {
    fn into(self) -> Ticket {
        Ticket(self)
    }
}

impl Into<Ticket> for usize {
    fn into(self) -> Ticket {
        (self as u128).into()
    }
}

impl Display for Ticket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum SecrecyMode {
    /// Slowest, but ensures each packet gets encrypted with a unique symmetrical key
    Perfect,
    /// Fastest. Meant for high-throughput environments. Each message will attempt to get re-keyed, but if not possible, will use the most recent symmetrical key
    BestEffort,
}

impl Default for SecrecyMode {
    fn default() -> Self {
        Self::BestEffort
    }
}
