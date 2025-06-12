//! Network Node Implementation
//!
//! This module implements the core networking functionality for Citadel Protocol nodes.
//! It provides the foundation for both server and peer nodes, handling connection
//! establishment, protocol negotiation, and secure communication.
//!
//! # Features
//!
//! - **Flexible Transport**: Supports TCP, TLS, and QUIC protocols
//! - **NAT Traversal**: Implements hole punching for P2P connections
//! - **Session Management**: Handles multiple concurrent sessions
//! - **Security**: Post-quantum cryptography and pre-shared key authentication
//! - **Dual Mode**: Supports both client-server and peer-to-peer architectures
//!
//! # Important Notes
//!
//! - Server nodes require proper bind address configuration
//! - Client nodes automatically handle protocol negotiation
//! - Pre-shared keys are required for server authentication
//! - QUIC support requires valid TLS certificates
//!
//! # Related Components
//!
//! - `SessionManager`: Manages active network sessions
//! - `NodeRemote`: Provides remote control interface
//! - `KernelCommunicator`: Handles kernel message passing
//! - `NetworkListener`: Manages network socket listeners
//!

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::io::AsyncRead;
use citadel_io::Mutex;
use citadel_types::crypto::SecurityLevel;
use citadel_user::account_manager::AccountManager;
use citadel_wire::exports::tokio_rustls::rustls::{pki_types, ClientConfig};
use citadel_wire::exports::Endpoint;
use citadel_wire::hypernode_type::NodeType;
use citadel_wire::nat_identification::NatType;
use citadel_wire::quic::{QuicEndpointConnector, QuicNode, QuicServer, SELF_SIGNED_DOMAIN};
use citadel_wire::tls::client_config_to_tls_connector;
use futures::StreamExt;
use netbeam::time_tracker::TimeTracker;

use crate::constants::{MAX_OUTGOING_UNPROCESSED_REQUESTS, TCP_CONN_TIMEOUT};
use crate::error::NetworkError;
use crate::functional::PairMap;
use crate::kernel::kernel_communicator::{
    KernelAsyncCallbackHandler, KernelAsyncCallbackHandlerInner,
};
use crate::kernel::kernel_executor::LocalSet;
use crate::kernel::RuntimeFuture;
use crate::prelude::{DeleteObject, PullObject};
use crate::proto::misc::net::{
    DualListener, FirstPacket, GenericNetworkListener, GenericNetworkStream, TlsListener,
};
use crate::proto::misc::underlying_proto::ServerUnderlyingProtocol;
use crate::proto::node_request::{
    ConnectToHypernode, DeregisterFromHypernode, DisconnectFromHypernode, GroupBroadcastCommand,
    NodeRequest, PeerCommand, ReKey, RegisterToHypernode, SendObject,
};
use crate::proto::node_result::{InternalServerError, NodeResult, SessionList};
use crate::proto::outbound_sender::{BoundedReceiver, BoundedSender, UnboundedSender};
use crate::proto::packet_processor::includes::Duration;
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::{HdpSessionInitMode, ServerOnlySessionInitSettings};
use crate::proto::session_manager::CitadelSessionManager;

pub type TlsDomain = Option<String>;

// The outermost abstraction for the networking layer. We use Rc to allow ensure single-threaded performance
// by default, but settings can be changed in crate::macros::*.
define_outer_struct_wrapper!(CitadelNode, CitadelNodeInner, <R: Ratchet>, <R>);

/// Inner device for the [`CitadelNode`]
pub struct CitadelNodeInner<R: Ratchet> {
    primary_socket: Option<DualListener>,
    /// Key: cid (to account for multiple clients from the same node)
    session_manager: CitadelSessionManager<R>,
    to_kernel: UnboundedSender<NodeResult<R>>,
    local_node_type: NodeType,
    // Applies only to listeners, not outgoing connections
    underlying_proto: ServerUnderlyingProtocol,
    nat_type: NatType,
    // for TLS params
    client_config: Arc<ClientConfig>,
    // All connecting/registering clients must present this pre-shared password in order to register and connect
    // to the server. This is an additional security measure to prevent unauthorized connections.
    server_only_session_init_settings: Option<ServerOnlySessionInitSettings>,
}

impl<R: Ratchet> CitadelNode<R> {
    /// Creates a new [`CitadelNode`]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn init(
        local_node_type: NodeType,
        to_kernel: UnboundedSender<NodeResult<R>>,
        account_manager: AccountManager<R, R>,
        shutdown: citadel_io::tokio::sync::oneshot::Sender<()>,
        underlying_proto: ServerUnderlyingProtocol,
        client_config: Option<Arc<ClientConfig>>,
        stun_servers: Option<Vec<String>>,
        server_only_session_init_settings: Option<ServerOnlySessionInitSettings>,
    ) -> io::Result<(
        NodeRemote<R>,
        Pin<Box<dyn RuntimeFuture>>,
        Option<LocalSet>,
        KernelAsyncCallbackHandler<R>,
    )> {
        let (primary_socket, bind_addr) = match local_node_type {
            NodeType::Server(bind_addr) => {
                Self::server_create_primary_listen_socket(underlying_proto.clone(), bind_addr)?
                    .map_left(Some)
                    .map_right(Some)
            }

            NodeType::Peer => (None, None),
        };

        if let Some(local_bind_addr) = bind_addr {
            log::info!(target: "citadel", "Citadel server established on {}", local_bind_addr);
        } else {
            log::info!(target: "citadel", "Citadel client established")
        }

        let client_config = if let Some(config) = client_config {
            config
        } else {
            let native_certs = citadel_wire::tls::load_native_certs_async().await?;
            Arc::new(
                citadel_wire::tls::create_rustls_client_config(&native_certs)
                    .map_err(|err| generic_error(err.to_string()))?,
            )
        };

        let time_tracker = TimeTracker::new();
        let session_manager = CitadelSessionManager::new(
            local_node_type,
            to_kernel.clone(),
            account_manager.clone(),
            time_tracker,
            client_config.clone(),
            stun_servers.clone(),
        );

        let nat_type = NatType::identify(stun_servers).await?;

        let inner = CitadelNodeInner {
            underlying_proto,
            local_node_type,
            primary_socket,
            to_kernel,
            session_manager,
            nat_type,
            client_config,
            server_only_session_init_settings,
        };

        let this = Self::from(inner);
        Ok(CitadelNode::load(this, account_manager, shutdown))
    }

    /// Note: spawning via handle is more efficient than joining futures. Source: https://cafbit.com/post/tokio_internals/
    /// To handle the shutdown process, we need
    /// This will panic if called twice in succession without a proper server reload.
    /// Returns a handle to communicate with the [CitadelNode].
    #[allow(clippy::type_complexity)]
    #[allow(unused_results, unused_must_use)]
    fn load(
        this: CitadelNode<R>,
        account_manager: AccountManager<R, R>,
        shutdown: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> (
        NodeRemote<R>,
        Pin<Box<dyn RuntimeFuture>>,
        Option<LocalSet>,
        KernelAsyncCallbackHandler<R>,
    ) {
        // Allow the listeners to read data without instantly returning
        // Load the readers
        let read = inner!(this);

        let sess_mgr = read.session_manager.clone();
        let kernel_tx = read.to_kernel.clone();
        let node_type = read.local_node_type;

        let (outbound_send_request_tx, outbound_send_request_rx) =
            BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS); // for the Hdp remote
        let kernel_async_callback_handler = KernelAsyncCallbackHandler {
            inner: Arc::new(Mutex::new(KernelAsyncCallbackHandlerInner {
                map: HashMap::new(),
            })),
        };
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
        let server_only_session_settings = read
            .server_only_session_init_settings
            .clone()
            .unwrap_or_default();

        drop(read);

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
                );
                let primary_stream_listener = if node_type.is_server() {
                    Some(Self::listen_primary(
                        this.clone(),
                        tt,
                        kernel_tx.clone(),
                        server_only_session_settings,
                    ))
                } else {
                    None
                };
                let peer_container = CitadelSessionManager::run_peer_container(session_manager);
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
                );
                let primary_stream_listener = if node_type.is_server() {
                    Some(Self::listen_primary(
                        this.clone(),
                        tt,
                        kernel_tx.clone(),
                        server_only_session_settings,
                    ))
                } else {
                    None
                };
                let peer_container = CitadelSessionManager::run_peer_container(session_manager);
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
                citadel_io::tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::trace!(target: "citadel", "OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = primary_stream_listener => res1,
                    res2 = peer_container => res2,
                }
            } else {
                citadel_io::tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::trace!(target: "citadel", "OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = peer_container => res1,
                }
            };

            if kernel_tx.unbounded_send(NodeResult::Shutdown).is_err() {
                log::warn!(target: "citadel", "Unable to send shutdown result to kernel (kernel died prematurely?)");
            }

            // the kernel will wait until the server shuts down to prevent cleanup tasks from being killed too early
            shutdown.send(());

            citadel_io::tokio::time::timeout(Duration::from_millis(1000), sess_mgr.shutdown())
                .await
                .map_err(|err| NetworkError::Generic(err.to_string()))?;

            log::trace!(target: "citadel", "HdpServer shutting down (future ended)...");

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
        underlying_proto: ServerUnderlyingProtocol,
        full_bind_addr: T,
    ) -> io::Result<(DualListener, SocketAddr)> {
        match &underlying_proto {
            ServerUnderlyingProtocol::Tls(..) | ServerUnderlyingProtocol::Tcp(..) => {
                Self::create_listen_socket(underlying_proto, None, None, full_bind_addr)
                    .map(|r| (DualListener::new(r.0, None), r.1))
            }

            ServerUnderlyingProtocol::Quic(_, domain, is_self_signed) => {
                // we need two sockets: one for TCP connection to allow connecting peers to determine the protocol, then another for QUIC
                let (tcp_listener, bind_addr) = Self::create_listen_socket(
                    ServerUnderlyingProtocol::tcp(),
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
        underlying_proto: ServerUnderlyingProtocol,
        redirect_to_quic: Option<(TlsDomain, bool)>,
        quic_endpoint_opt: Option<QuicNode>,
        full_bind_addr: T,
    ) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        let bind: SocketAddr = full_bind_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::bind_defaults(underlying_proto, redirect_to_quic, quic_endpoint_opt, bind)
    }

    /// redirect_to_quic is only applicable when using TCP
    /// - quic_endpoint_opt is only relevant (yet optional) when the underlying proto specified is quic
    fn bind_defaults(
        underlying_proto: ServerUnderlyingProtocol,
        redirect_to_quic: Option<(TlsDomain, bool)>,
        quic_endpoint_opt: Option<QuicNode>,
        bind: SocketAddr,
    ) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        match underlying_proto {
            ServerUnderlyingProtocol::Tcp(Some(listener)) => {
                let listener = listener.lock().take().ok_or_else(|| {
                    std::io::Error::other(
                        "TCP listener already taken",
                    )
                })?;

                let bind = listener.local_addr()?;

                Ok((GenericNetworkListener::new_tcp(listener, redirect_to_quic)?, bind))
            }
            ServerUnderlyingProtocol::Tls(..) | ServerUnderlyingProtocol::Tcp(None) => {
                citadel_wire::socket_helpers::get_tcp_listener(bind)
                    .and_then(|listener| {
                        log::trace!(target: "citadel", "Setting up {:?} listener socket on {:?}", &underlying_proto, bind);
                        let bind = listener.local_addr()?;
                        match underlying_proto {
                            ServerUnderlyingProtocol::Tcp(None) => {
                                Ok((GenericNetworkListener::new_tcp(listener, redirect_to_quic)?, bind))
                            }

                            ServerUnderlyingProtocol::Tls(interop, domain, is_self_signed) => {
                                let tls_listener = TlsListener::new(listener, interop.tls_acceptor, domain, is_self_signed)?;
                                Ok((GenericNetworkListener::new_tls(tls_listener)?, bind))
                            }

                            _ => {
                                unreachable!("TCP listener called, but not the right listener")
                            }
                        }
                    }).map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))
            }

            ServerUnderlyingProtocol::Quic(crypto, domain, is_self_signed) => {
                log::trace!(target: "citadel", "Setting up QUIC listener socket on {:?} | Self-signed? {}", bind, is_self_signed);

                let mut quic = if let Some(quic) = quic_endpoint_opt {
                    quic
                } else {
                    let udp_socket = citadel_wire::socket_helpers::get_udp_socket(bind).map_err(generic_error)?;
                    QuicServer::create(udp_socket, crypto).map_err(generic_error)?
                };

                let bind = quic.endpoint.local_addr()?;

                quic.tls_domain_opt = domain;

                Ok((GenericNetworkListener::from_quic_node(quic, is_self_signed)?, bind))
            }
        }
    }

    /// Returns a TcpStream to the remote addr, as well as a local TcpListener on the same bind addr going to remote
    /// to allow for TCP hole-punching (we need the same port to cover port-restricted NATS, worst-case scenario)
    /// The remote is usually the central server. Then the P2P listener binds to it to allow NATs to keep the hole punched
    /// It is expected that the listener_underlying_proto is QUIC here since this is called for p2p connections!
    pub(crate) async fn create_session_transport_init<T: ToSocketAddrs>(
        remote: T,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<GenericNetworkStream> {
        // We start by creating a client to server connection
        let (stream, _quic_endpoint_generated_during_connect) =
            Self::create_c2s_connect_socket(remote, None, default_client_config).await?;

        log::trace!(target: "citadel", "[Client] Finished connecting to server {} w/ proto {:?}", stream.peer_addr()?, &stream);
        Ok(stream)
    }

    /// Important: Assumes UDP NAT traversal has concluded. This should ONLY be used for p2p
    /// This takes the local socket AND QuicNode instance
    #[allow(dead_code)]
    pub async fn create_p2p_quic_connect_socket<T: ToSocketAddrs>(
        quic_endpoint: Endpoint,
        remote: T,
        tls_domain: TlsDomain,
        timeout: Option<Duration>,
        secure_client_config: Arc<ClientConfig>,
    ) -> io::Result<GenericNetworkStream> {
        let remote: SocketAddr = remote
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
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
        log::trace!(target: "citadel", "Connecting to QUIC node {:?}", remote);
        // when using p2p quic, if domain is some, then we will use the default cfg
        let cfg = if domain.is_some() {
            citadel_wire::quic::rustls_client_config_to_quinn_config(secure_client_config)?
        } else {
            // if there is no domain specified, assume self-signed (For now)
            // this is non-blocking since native certs won't be loaded
            citadel_wire::quic::insecure::configure_client()
        };

        log::trace!(target: "citadel", "Using cfg={:?} to connect to {:?}", cfg, remote);

        // we MUST use the connect_biconn_WITH below since we are using the server quic instance to make this outgoing connection
        let (conn, sink, stream) = citadel_io::tokio::time::timeout(
            timeout.unwrap_or(TCP_CONN_TIMEOUT),
            quic_endpoint.connect_biconn_with(
                remote,
                domain.as_deref().unwrap_or(SELF_SIGNED_DOMAIN),
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
    pub async fn create_c2s_connect_socket<T: ToSocketAddrs>(
        remote: T,
        timeout: Option<Duration>,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        let remote: SocketAddr = remote
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::c2s_connect_defaults(timeout, remote, default_client_config).await
    }

    pub async fn c2s_connect_defaults(
        timeout: Option<Duration>,
        remote: SocketAddr,
        default_client_config: &Arc<ClientConfig>,
    ) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        log::trace!(target: "citadel", "C2S connect defaults to {:?}", remote);
        let mut stream = citadel_wire::socket_helpers::get_tcp_stream(
            remote,
            timeout.unwrap_or(TCP_CONN_TIMEOUT),
        )
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
        let bind_addr = stream.local_addr()?;
        log::trace!(target: "citadel", "C2S Bind addr: {:?}", bind_addr);
        let first_packet = Self::read_first_packet(&mut stream, timeout).await?;

        match first_packet {
            FirstPacket::Tcp { external_addr } => {
                log::trace!(target: "citadel", "Host claims TCP DEFAULT CONNECTION. External ADDR: {:?}", external_addr);
                Ok((GenericNetworkStream::Tcp(stream), None))
            }

            FirstPacket::Tls {
                domain,
                external_addr,
                is_self_signed,
            } => {
                log::trace!(target: "citadel", "Host claims TLS CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed? {}", &domain, external_addr, is_self_signed);

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
                Ok((GenericNetworkStream::Tls(Box::new(citadel_wire::exports::tokio_rustls::TlsStream::Client(stream))), None))
            }
            FirstPacket::Quic {
                domain,
                external_addr,
                is_self_signed,
            } => {
                log::trace!(target: "citadel", "Host claims QUIC CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed: {}", &domain, external_addr, is_self_signed);
                let udp_socket = citadel_wire::socket_helpers::get_udp_socket(bind_addr)
                    .map_err(generic_error)?; // bind to same address as tcp for firewall purposes
                let mut quic_endpoint = if is_self_signed {
                    citadel_wire::quic::QuicClient::new_no_verify(udp_socket)
                        .map_err(generic_error)?
                } else {
                    citadel_wire::quic::QuicClient::new_with_rustls_config(
                        udp_socket,
                        default_client_config.clone(),
                    )
                    .map_err(generic_error)?
                };

                quic_endpoint.tls_domain_opt.clone_from(&domain);

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

    async fn read_first_packet<Read: AsyncRead + Unpin>(
        stream: Read,
        timeout: Option<Duration>,
    ) -> std::io::Result<FirstPacket> {
        let (_stream, ret) = citadel_io::tokio::time::timeout(
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
    /// In personal mode, if a new connection needs to be forged with another node, then a new SO_REUSE socket
    /// will need to be created that is bound to the local primary port and connected to the adjacent hypernode's
    /// primary port. That socket will be created in the underlying HdpSessionManager during the connection process
    async fn listen_primary(
        server: CitadelNode<R>,
        _tt: TimeTracker,
        to_kernel: UnboundedSender<NodeResult<R>>,
        server_only_session_init_settings: ServerOnlySessionInitSettings,
    ) -> Result<(), NetworkError> {
        let primary_port_future = {
            let mut this = inner_mut!(server);
            let listener = this.primary_socket.take().unwrap();
            let session_manager = this.session_manager.clone();
            let local_nat_type = this.nat_type.clone();
            drop(this);
            Self::primary_session_creator_loop(
                to_kernel,
                local_nat_type,
                session_manager,
                listener,
                server_only_session_init_settings,
            )
        };

        primary_port_future.await
    }

    async fn primary_session_creator_loop(
        to_kernel: UnboundedSender<NodeResult<R>>,
        local_nat_type: NatType,
        session_manager: CitadelSessionManager<R>,
        mut socket: DualListener,
        server_only_session_init_settings: ServerOnlySessionInitSettings,
    ) -> Result<(), NetworkError> {
        loop {
            match socket.next().await {
                Some(Ok((stream, peer_addr))) => {
                    log::trace!(target: "citadel", "Received stream from {:?}", peer_addr);
                    let local_bind_addr = stream.local_addr().unwrap();

                    log::trace!(target: "citadel", "[Server] Starting connection with remote={} w/ proto={:?}", peer_addr, &stream);

                    match session_manager.process_new_inbound_connection(
                        local_bind_addr,
                        local_nat_type.clone(),
                        peer_addr,
                        stream,
                        server_only_session_init_settings.clone(),
                    ) {
                        Ok(session) => {
                            spawn!(session);
                        }

                        Err(err) => {
                            to_kernel.unbounded_send(NodeResult::InternalServerError(
                                InternalServerError {
                                    ticket_opt: None,
                                    cid_opt: None,
                                    message: format!(
                                        "HDP Server dropping connection to {peer_addr}. Reason: {err}"
                                    ),
                                },
                            ))?;
                        }
                    }
                }

                Some(Err(err)) => {
                    const WSACCEPT_ERROR: i32 = 10093;
                    if err.raw_os_error().unwrap_or(-1) != WSACCEPT_ERROR {
                        log::error!(target: "citadel", "Error accepting stream: {err}");
                    }
                }

                None => {
                    log::error!(target: "citadel", "Primary session listener returned None");
                    return Err(NetworkError::InternalError("Primary session listener died"));
                }
            }
        }
    }

    async fn outbound_kernel_request_handler(
        this: CitadelNode<R>,
        to_kernel_tx: UnboundedSender<NodeResult<R>>,
        mut outbound_send_request_rx: BoundedReceiver<(NodeRequest, Ticket)>,
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

        fn send_error<K: Ratchet>(
            to_kernel_tx: &UnboundedSender<NodeResult<K>>,
            ticket_id: Ticket,
            err: NetworkError,
        ) -> Result<(), NetworkError> {
            let err = err.into_string();
            if to_kernel_tx
                .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                    ticket_opt: Some(ticket_id),
                    cid_opt: None,
                    message: err.clone(),
                }))
                .is_err()
            {
                log::error!(target: "citadel", "TO_KERNEL_TX Error: {:?}", err);
                Err(NetworkError::InternalError(
                    "kernel disconnected from hypernode instance",
                ))
            } else {
                Ok(())
            }
        }

        while let Some((outbound_request, ticket_id)) = outbound_send_request_rx.recv().await {
            if let Some(cid) = outbound_request.session_cid() {
                if cid == 0 {
                    send_error(&to_kernel_tx, ticket_id, NetworkError::msg(format!("Cannot use zero-cid for outbound requests. Invalid: {outbound_request:?}")))?;
                    continue;
                }
            }
            match outbound_request {
                NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
                    session_cid,
                    command: cmd,
                }) => {
                    if let Err(err) = session_manager.process_outbound_broadcast_command(
                        ticket_id,
                        session_cid,
                        cmd,
                    ) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::RegisterToHypernode(RegisterToHypernode {
                    remote_addr: peer_addr,
                    proposed_credentials: credentials,
                    static_security_settings: security_settings,
                    session_password,
                }) => {
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
                            session_password,
                        )
                        .await
                    {
                        Ok(session) => {
                            let to_kernel_tx = to_kernel_tx.clone();
                            let task = async move {
                                if let Err(err) = session.await {
                                    let _ = send_error(&to_kernel_tx, ticket_id, err);
                                }
                            };

                            spawn!(task);
                        }

                        Err(err) => {
                            send_error(&to_kernel_tx, ticket_id, err)?;
                        }
                    }
                }

                NodeRequest::ConnectToHypernode(ConnectToHypernode {
                    auth_request: authentication_request,
                    connect_mode,
                    udp_mode,
                    keep_alive_timeout,
                    session_security_settings: security_settings,
                    session_password,
                }) => {
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
                            session_password,
                        )
                        .await
                    {
                        Ok(session) => {
                            let to_kernel_tx = to_kernel_tx.clone();
                            let task = async move {
                                if let Err(err) = session.await {
                                    let _ = send_error(&to_kernel_tx, ticket_id, err);
                                }
                            };
                            spawn!(task);
                        }

                        Err(err) => {
                            send_error(&to_kernel_tx, ticket_id, err)?;
                        }
                    }
                }

                NodeRequest::DisconnectFromHypernode(DisconnectFromHypernode { session_cid }) => {
                    if let Err(err) = session_manager.initiate_disconnect(session_cid, ticket_id) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::ReKey(ReKey {
                    v_conn_type: virtual_target,
                }) => {
                    if let Err(err) = session_manager
                        .initiate_update_entropy_bank_subroutine(virtual_target, ticket_id)
                    {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::DeregisterFromHypernode(DeregisterFromHypernode {
                    session_cid,
                    v_conn_type: virtual_connection_type,
                }) => {
                    if let Err(err) = session_manager.initiate_deregistration_subroutine(
                        session_cid,
                        virtual_connection_type,
                        ticket_id,
                    ) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                // TODO: Update this to include security levels (FCM conflicts though)
                NodeRequest::PeerCommand(PeerCommand {
                    session_cid,
                    command: peer_command,
                }) => {
                    if let Err(err) = session_manager
                        .dispatch_peer_command(
                            session_cid,
                            ticket_id,
                            peer_command,
                            SecurityLevel::Standard,
                        )
                        .await
                    {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::SendObject(SendObject {
                    source: path,
                    chunk_size,
                    session_cid,
                    v_conn_type: virtual_target,
                    transfer_type,
                }) => {
                    if let Err(err) = session_manager.process_outbound_file(
                        ticket_id,
                        chunk_size,
                        path,
                        session_cid,
                        virtual_target,
                        SecurityLevel::Standard,
                        transfer_type,
                    ) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::PullObject(PullObject {
                    v_conn,
                    virtual_dir,
                    delete_on_pull,
                    transfer_security_level,
                }) => {
                    if let Err(err) = session_manager.revfs_pull(
                        ticket_id,
                        v_conn.get_session_cid(),
                        v_conn,
                        virtual_dir,
                        delete_on_pull,
                        transfer_security_level,
                    ) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::DeleteObject(DeleteObject {
                    v_conn,
                    virtual_dir,
                    security_level,
                }) => {
                    if let Err(err) = session_manager.revfs_delete(
                        ticket_id,
                        v_conn.get_session_cid(),
                        v_conn,
                        virtual_dir,
                        security_level,
                    ) {
                        send_error(&to_kernel_tx, ticket_id, err)?;
                    }
                }

                NodeRequest::GetActiveSessions => {
                    if let Err(err) =
                        to_kernel_tx.unbounded_send(NodeResult::SessionList(SessionList {
                            ticket: ticket_id,
                            sessions: session_manager.get_active_sessions(),
                        }))
                    {
                        send_error(
                            &to_kernel_tx,
                            ticket_id,
                            NetworkError::Generic(err.to_string()),
                        )?;
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

pub(crate) struct CitadelNodeRemoteInner<R: Ratchet> {
    pub callback_handler: KernelAsyncCallbackHandler<R>,
    pub node_type: NodeType,
    pub account_manager: AccountManager<R, R>,
}
