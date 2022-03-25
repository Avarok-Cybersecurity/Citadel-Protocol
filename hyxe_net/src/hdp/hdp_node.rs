use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{Sink, SinkExt, StreamExt};
use futures::channel::mpsc::TrySendError;
use log::info;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;
use tokio::task::LocalSet;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_wire::hypernode_type::NodeType;
use hyxe_wire::local_firewall_handler::{FirewallProtocol, open_local_firewall_port, remove_firewall_rule};
use hyxe_wire::nat_identification::NatType;
use netbeam::time_tracker::TimeTracker;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::external_services::fcm::data_structures::RawFcmPacketStore;
use hyxe_user::external_services::ServicesObject;
use hyxe_user::auth::proposed_credentials::ProposedCredentials;

use crate::constants::{MAX_OUTGOING_UNPROCESSED_REQUESTS, TCP_CONN_TIMEOUT};
use crate::error::NetworkError;
use crate::functional::PairMap;
use crate::hdp::file_transfer::FileTransferStatus;
use crate::hdp::hdp_packet_processor::includes::Duration;
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::hdp::hdp_session::{HdpSession, HdpSessionInitMode};
use crate::hdp::hdp_session_manager::HdpSessionManager;
use crate::hdp::misc::net::{FirstPacket, GenericNetworkListener, GenericNetworkStream, TlsListener, DualListener};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::misc::underlying_proto::UnderlyingProtocol;
use crate::hdp::outbound_sender::{BoundedReceiver, BoundedSender, unbounded, UnboundedSender};
use crate::hdp::peer::channel::{PeerChannel, UdpChannel};
use crate::hdp::peer::peer_layer::{MailboxTransfer, PeerSignal, UdpMode};
use crate::hdp::state_container::{FileKey, VirtualConnectionType, VirtualTargetType};
use crate::kernel::kernel_communicator::{KernelAsyncCallbackHandler, KernelStreamSubscription};
use crate::kernel::RuntimeFuture;
use hyxe_wire::quic::{QuicServer, QuicEndpointConnector, SELF_SIGNED_DOMAIN, QuicNode};
use crate::hdp::peer::p2p_conn_handler::generic_error;
use hyxe_wire::exports::Endpoint;
use hyxe_crypt::prelude::SecBuffer;
use crate::hdp::peer::group_channel::GroupChannel;
use crate::auth::AuthenticationRequest;
use hyxe_wire::exports::tokio_rustls::rustls::{ServerName, ClientConfig};
use std::convert::TryFrom;
use hyxe_wire::tls::client_config_to_tls_connector;

/// ports which were opened that must be closed atexit
static OPENED_PORTS: Mutex<Vec<u16>> = parking_lot::const_mutex(Vec::new());

pub extern fn atexit() {
    log::info!("Cleaning up firewall ports ...");
    let lock = OPENED_PORTS.lock();
    for port in lock.iter() {
        HdpServer::close_tcp_port(*port);
    }
}

pub type TlsDomain = Option<String>;

// The outermost abstraction for the networking layer. We use Rc to allow ensure single-threaded performance
// by default, but settings can be changed in crate::macros::*.
define_outer_struct_wrapper!(HdpServer, HdpServerInner);

/// Inner device for the HdpServer
pub struct HdpServerInner {
    primary_socket: Option<DualListener>,
    /// Key: cid (to account for multiple clients from the same node)
    session_manager: HdpSessionManager,
    to_kernel: UnboundedSender<HdpServerResult>,
    local_node_type: NodeType,
    // Applies only to listeners, not outgoing connections
    underlying_proto: UnderlyingProtocol,
    nat_type: NatType,
    // for TLS params
    client_config: Arc<ClientConfig>
}

impl HdpServer {
    /// Creates a new [HdpServer]
    pub(crate) async fn init(local_node_type: NodeType, to_kernel: UnboundedSender<HdpServerResult>, account_manager: AccountManager, shutdown: tokio::sync::oneshot::Sender<()>, underlying_proto: UnderlyingProtocol, client_config: Option<Arc<ClientConfig>>) -> io::Result<(NodeRemote, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>, KernelAsyncCallbackHandler)> {
        let (primary_socket, bind_addr) = match local_node_type {
            NodeType::Server(bind_addr) => {
                Self::server_create_primary_listen_socket(underlying_proto.clone(), &bind_addr)?.map_left(|l|Some(l)).map_right(|r|Some(r))
            }

            NodeType::Peer => {
                (None, None)
            }
        };

        if let Some(local_bind_addr) = bind_addr {
            let primary_port = local_bind_addr.port();
            // Note: on Android/IOS, the below command will fail since sudo access is prohibited
            Self::open_tcp_port(primary_port);

            info!("HdpServer established on {}", local_bind_addr);
        } else {
            info!("HdpClient Established")
        }

        let client_config = if let Some(config) = client_config {
            config
        } else {
            let native_certs = hyxe_wire::tls::load_native_certs_async().await?;
            Arc::new(hyxe_wire::tls::create_rustls_client_config(&native_certs).map_err(|err| generic_error(err.to_string()))?)
        };

        let time_tracker = TimeTracker::new();
        let session_manager = HdpSessionManager::new(local_node_type, to_kernel.clone(), account_manager.clone(), time_tracker.clone(), client_config.clone());

        let nat_type = NatType::identify().await.map_err(|err| err.std())?;

        let inner = HdpServerInner {
            underlying_proto,
            local_node_type,
            primary_socket,
            to_kernel,
            session_manager,
            nat_type,
            client_config
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
    fn load(this: HdpServer, account_manager: AccountManager, shutdown: tokio::sync::oneshot::Sender<()>) -> (NodeRemote, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>, KernelAsyncCallbackHandler) {
        // Allow the listeners to read data without instantly returning
        // Load the readers
        let read = inner!(this);

        let sess_mgr = read.session_manager.clone();
        let kernel_tx = read.to_kernel.clone();
        let node_type = read.local_node_type;

        let (session_spawner_tx, session_spawner_rx) = unbounded();
        let session_spawner = HdpSession::session_future_receiver(session_spawner_rx);

        let (outbound_send_request_tx, outbound_send_request_rx) = BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS); // for the Hdp remote
        let kernel_async_callback_handler = KernelAsyncCallbackHandler::new();
        let remote = NodeRemote::new(outbound_send_request_tx, kernel_async_callback_handler.clone(), account_manager, node_type);
        let tt = read.session_manager.load_server_remote_get_tt(remote.clone());
        let session_manager = read.session_manager.clone();

        std::mem::drop(read);

        let (outbound_kernel_request_handler, primary_stream_listener, peer_container, localset_opt) = {
            #[cfg(feature = "multi-threaded")]
            {
                let outbound_kernel_request_handler = Self::outbound_kernel_request_handler(this.clone(), kernel_tx.clone(), outbound_send_request_rx, session_spawner_tx.clone());
                let primary_stream_listener = if node_type.is_server() { Some(Self::listen_primary(this.clone(), tt, kernel_tx.clone(), session_spawner_tx.clone())) } else { None };
                let peer_container = HdpSessionManager::run_peer_container(session_manager);
                let localset_opt = None;
                (outbound_kernel_request_handler, primary_stream_listener, peer_container, localset_opt)
            }

            #[cfg(not(feature = "multi-threaded"))]
                {
                    let localset = LocalSet::new();
                    let outbound_kernel_request_handler = Self::outbound_kernel_request_handler(this.clone(), kernel_tx.clone(), outbound_send_request_rx, session_spawner_tx.clone());
                    let primary_stream_listener = if node_type.is_server() { Some(Self::listen_primary(this.clone(), tt, kernel_tx.clone(), session_spawner_tx.clone())) } else { None };
                    let peer_container = HdpSessionManager::run_peer_container(session_manager);
                    (outbound_kernel_request_handler, primary_stream_listener, peer_container, Some(localset))
                }
        };

        let server_future = async move {
            let res = if let Some(primary_stream_listener) = primary_stream_listener {
                tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::info!("OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = primary_stream_listener => res1,
                    res2 = peer_container => res2,
                    res3 = session_spawner => res3
                }
            } else {
                tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::info!("OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = peer_container => res1,
                    res2 = session_spawner => res2
                }
            };

            if let Err(_) = kernel_tx.unbounded_send(HdpServerResult::Shutdown) {
                log::warn!("Unable to send shutdown result to kernel (kernel died prematurely?)");
            }

            // the kernel will wait until the server shuts down to prevent cleanup tasks from being killed too early
            shutdown.send(());

            tokio::time::timeout(Duration::from_millis(1000), sess_mgr.shutdown()).await.map_err(|err| NetworkError::Generic(err.to_string()))?;

            log::info!("HdpServer shutting down (future ended)...");

            res
        };

        //handle.load_server_future(server_future);

        (remote, Box::pin(server_future), localset_opt, kernel_async_callback_handler)
    }

    fn open_tcp_port(port: u16) {
        if let Ok(Some(res)) = open_local_firewall_port(FirewallProtocol::TCP(port)) {
            if !res.status.success() {
                let data = if res.stdout.is_empty() { res.stderr } else { res.stdout };
                log::warn!("We were unable to ensure that port {}, be open. Reason: {}", port, String::from_utf8(data).unwrap_or_default());
            } else {
                OPENED_PORTS.lock().push(port);
            }
        }
    }

    fn close_tcp_port(port: u16) {
        if let Ok(Some(res)) = remove_firewall_rule(FirewallProtocol::TCP(port)) {
            if !res.status.success() {
                let data = if res.stdout.is_empty() { res.stderr } else { res.stdout };
                log::warn!("We were unable to ensure that port {}, be CLOSED. Reason: {}", port, String::from_utf8(data).unwrap_or_default());
            } else {
                log::info!("Successfully shutdown port {}", port);
            }
        }
    }

    pub fn server_create_primary_listen_socket<T: ToSocketAddrs>(underlying_proto: UnderlyingProtocol, full_bind_addr: T) -> io::Result<(DualListener, SocketAddr)> {
        match &underlying_proto {
            UnderlyingProtocol::Tls(..) | UnderlyingProtocol::Tcp => {
                Self::create_listen_socket(underlying_proto, None, None, full_bind_addr).map(|r| (DualListener::new(r.0, None), r.1))
            }

            UnderlyingProtocol::Quic(_, domain, is_self_signed) => {
                // we need two sockets: one for TCP connection to allow connecting peers to determine the protocol, then another for QUIC
                let (tcp_listener, bind_addr) = Self::create_listen_socket(UnderlyingProtocol::Tcp, Some((domain.clone(), *is_self_signed)), None,full_bind_addr)?;
                let (quic_listener, _bind_addr_quic) = Self::create_listen_socket(underlying_proto, None, None, bind_addr)?;
                Ok((DualListener::new(tcp_listener, Some(quic_listener)), bind_addr))
            }
        }
    }

    pub fn create_listen_socket<T: ToSocketAddrs>(underlying_proto: UnderlyingProtocol, redirect_to_quic: Option<(TlsDomain, bool)>, quic_endpoint_opt: Option<QuicNode>, full_bind_addr: T) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        let bind: SocketAddr = full_bind_addr.to_socket_addrs()?.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::bind_defaults(underlying_proto, redirect_to_quic, quic_endpoint_opt, bind)
    }

    /// redirect_to_quic is only applicable when using TCP
    /// - quic_endpoint_opt is only relevant (yet optional) when the underlying proto specified is quic
    fn bind_defaults(underlying_proto: UnderlyingProtocol, redirect_to_quic: Option<(TlsDomain, bool)>, quic_endpoint_opt: Option<QuicNode>,  bind: SocketAddr) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        match underlying_proto {
            UnderlyingProtocol::Tls(..) | UnderlyingProtocol::Tcp => {
                hyxe_wire::socket_helpers::get_tcp_listener(bind)
                    .and_then(|listener| {
                        log::info!("Setting up {:?} listener socket on {:?}", &underlying_proto, bind);
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
                log::info!("Setting up QUIC listener socket on {:?} | Self-signed? {}", bind, is_self_signed);

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
    pub(crate) async fn create_session_transport_init<R: ToSocketAddrs>(listener_underlying_proto: UnderlyingProtocol, remote: R, default_client_config: &Arc<ClientConfig>) -> io::Result<(GenericNetworkListener, GenericNetworkStream)> {
        // We start by creating a client to server connection
        let (stream, quic_endpoint_generated_during_connect) = Self::create_c2s_connect_socket(remote, None, default_client_config).await?;
        // We bind to the addr from the source socket_addr the stream has reserved for NAT traversal purposes
        // NOTE! We CANNOT bind to this address otherwise there will be overlapping TCP connections from the SO_REUSEADDR, causing stream CORRUPTION under high traffic loads. This was proven to exist from stress-testing this protocol
        // Wait ... maybe not? Jul 22 2021
        // We obtain the bind addr of the client-to-server connection for NAT traversal purposes
        let stream_bind_addr = stream.local_addr()?;

        // we then bind a listener to the same local addr as the connection to the central server. The central server just needs to share the external addr with each peer to know where to connect
        let (p2p_listener, _bind_addr) = Self::bind_defaults(listener_underlying_proto, None,quic_endpoint_generated_during_connect, SocketAddr::new(stream_bind_addr.ip(), stream_bind_addr.port()))?;

        Self::open_tcp_port(stream_bind_addr.port());

        log::info!("[Client] Finished connecting to server {} w/ proto {:?}", stream.peer_addr()?, &stream);
        Ok((p2p_listener, stream))
    }

    /// Important: Assumes UDP NAT traversal has concluded. This should ONLY be used for p2p
    /// This takes the local socket AND QuicNode instance
    pub async fn create_p2p_quic_connect_socket<R: ToSocketAddrs>(quic_endpoint: Endpoint, remote: R, tls_domain: TlsDomain, timeout: Option<Duration>, secure_client_config: Arc<ClientConfig>) -> io::Result<GenericNetworkStream> {
        let remote: SocketAddr = remote.to_socket_addrs()?.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::quic_p2p_connect_defaults(quic_endpoint, timeout, tls_domain, remote, secure_client_config).await
    }

    /// - force_use_default_config: if true, this will unconditionally use the default client config already present inside the quic_endpoint parameter
    pub async fn quic_p2p_connect_defaults(quic_endpoint: Endpoint, timeout: Option<Duration>, domain: TlsDomain, remote: SocketAddr, secure_client_config: Arc<ClientConfig>) -> io::Result<GenericNetworkStream> {
        log::info!("Connecting to QUIC node {:?}", remote);
        // when using p2p quic, if domain is some, then we will use the default cfg
        let cfg = if domain.is_some() {
            hyxe_wire::quic::rustls_client_config_to_quinn_config(secure_client_config)
        } else {
            // if there is no domain specified, assume self-signed (For now)
            // this is non-blocking since native certs won't be loaded
            hyxe_wire::quic::insecure::configure_client()
        };

        log::info!("Using cfg={:?} to connect to {:?}", cfg, remote);

        // we MUST use the connect_biconn_WITH below since we are using the server quic instance to make this outgoing connection
        let (conn, sink, stream) = tokio::time::timeout(timeout.unwrap_or(TCP_CONN_TIMEOUT), quic_endpoint.connect_biconn_with(remote, domain.as_ref().map(|r| r.as_str()).unwrap_or(SELF_SIGNED_DOMAIN), Some(cfg))).await?.map_err(generic_error)?;
        Ok(GenericNetworkStream::Quic(sink, stream, quic_endpoint, Some(conn), remote))
    }

    /// Only for client to server conns
    pub async fn create_c2s_connect_socket<R: ToSocketAddrs>(remote: R, timeout: Option<Duration>, default_client_config: &Arc<ClientConfig>) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        let remote: SocketAddr = remote.to_socket_addrs()?.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::c2s_connect_defaults(timeout, remote, default_client_config).await
    }

    pub async fn c2s_connect_defaults(timeout: Option<Duration>, remote: SocketAddr, default_client_config: &Arc<ClientConfig>) -> io::Result<(GenericNetworkStream, Option<QuicNode>)> {
        log::info!("C2S connect defaults to {:?}", remote);
        let mut stream = hyxe_wire::socket_helpers::get_tcp_stream(remote, timeout.unwrap_or(TCP_CONN_TIMEOUT)).await.map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err.to_string()))?;
        let bind_addr = stream.local_addr()?;
        log::info!("C2S Bind addr: {:?}", bind_addr);
        let first_packet = Self::read_first_packet(&mut stream, timeout).await?;

        match first_packet {
            FirstPacket::Tcp { external_addr } => {
                log::info!("Host claims TCP DEFAULT CONNECTION. External ADDR: {:?}", external_addr);
                Ok((GenericNetworkStream::Tcp(stream), None))
            }

            FirstPacket::Tls { domain, external_addr, is_self_signed } => {
                log::info!("Host claims TLS CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed? {}", &domain, external_addr, is_self_signed);

                let connector = if is_self_signed {
                    hyxe_wire::tls::create_client_dangerous_config()
                } else {
                    client_config_to_tls_connector(default_client_config.clone())
                };

                let stream = connector.connect(ServerName::try_from(domain.as_ref().map(|r| r.as_str()).unwrap_or(SELF_SIGNED_DOMAIN)).map_err(|err| generic_error(err.to_string()))?, stream).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                Ok((GenericNetworkStream::Tls(stream.into()), None))
            }
            FirstPacket::Quic { domain, external_addr, is_self_signed } => {
                log::info!("Host claims QUIC CONNECTION (domain: {:?}) | External ADDR: {:?} | self-signed: {}", &domain, external_addr, is_self_signed);
                let udp_socket = hyxe_wire::socket_helpers::get_udp_socket(bind_addr).map_err(generic_error)?; // bind to same address as tcp for firewall purposes
                let mut quic_endpoint = if is_self_signed {
                    hyxe_wire::quic::QuicClient::new_no_verify(udp_socket).map_err(generic_error)?
                } else {
                    hyxe_wire::quic::QuicClient::new_with_config(udp_socket, default_client_config.clone()).map_err(generic_error)?
                };

                quic_endpoint.tls_domain_opt = domain.clone();

                Self::quic_p2p_connect_defaults(quic_endpoint.endpoint.clone(), timeout, domain, remote,default_client_config.clone()).await
                    .map(|r| (r, Some(quic_endpoint)))
            }
        }
    }

    async fn read_first_packet<R: AsyncRead + Unpin>(stream: R, timeout: Option<Duration>) -> std::io::Result<FirstPacket> {
        let (_stream, ret) = tokio::time::timeout(timeout.unwrap_or(TCP_CONN_TIMEOUT), super::misc::read_one_packet_as_framed(stream)).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string()))?
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
    async fn listen_primary(server: HdpServer, _tt: TimeTracker, to_kernel: UnboundedSender<HdpServerResult>, session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>) -> Result<(), NetworkError> {
        let primary_port_future= {
            let mut this = inner_mut!(server);
            let listener = this.primary_socket.take().unwrap();
            let session_manager = this.session_manager.clone();
            let local_nat_type = this.nat_type.clone();
            std::mem::drop(this);
            Self::primary_session_creator_loop(to_kernel, local_nat_type, session_manager, listener, session_spawner)
        };

        primary_port_future.await
    }

    async fn primary_session_creator_loop(to_kernel: UnboundedSender<HdpServerResult>, local_nat_type: NatType, session_manager: HdpSessionManager, mut socket: DualListener, session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>) -> Result<(), NetworkError> {
        loop {
            match socket.next().await {
                Some(Ok((stream, peer_addr))) => {
                    log::trace!("Received stream from {:?}", peer_addr);
                    let local_bind_addr = stream.local_addr().unwrap();

                    log::info!("[Server] Starting connection with remote={} w/ proto={:?}", peer_addr, &stream);

                    match session_manager.process_new_inbound_connection(local_bind_addr, local_nat_type.clone(), peer_addr, stream) {
                        Ok(session) => {
                            session_spawner.unbounded_send(session).map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            to_kernel.unbounded_send(HdpServerResult::InternalServerError(None, format!("HDP Server dropping connection to {}. Reason: {}", peer_addr, err.to_string())))?;
                        }
                    }

                }

                Some(Err(err)) => {
                    const WSACCEPT_ERROR: i32 = 10093;
                    if err.raw_os_error().unwrap_or(-1) != WSACCEPT_ERROR {
                        log::error!("Error accepting stream: {}", err.to_string());
                    }
                }

                None => {
                    log::error!("Primary session listener returned None");
                    return Err(NetworkError::InternalError("Primary session listener died"))
                }
            }
        }
    }

    async fn outbound_kernel_request_handler(this: HdpServer, ref to_kernel_tx: UnboundedSender<HdpServerResult>, mut outbound_send_request_rx: BoundedReceiver<(HdpServerRequest, Ticket)>, session_spawner: UnboundedSender<Pin<Box<dyn RuntimeFuture>>>) -> Result<(), NetworkError> {
        let (local_node_type, session_manager, listener_underlying_proto, local_nat_type, default_client_config) = {
            let read = inner!(this);
            let local_node_type = read.local_node_type;
            let listener_underlying_proto = read.underlying_proto.clone();

            // We need only the underlying [HdpSessionManager]
            let session_manager = read.session_manager.clone();
            let local_nat_type = read.nat_type.clone();
            let default_client_config = read.client_config.clone();
            // Drop the read handle; we are done with it
            //std::mem::drop(read);
            (local_node_type, session_manager, listener_underlying_proto ,local_nat_type, default_client_config)
        };

        let send_error = |ticket_id: Ticket, err: NetworkError| {
            let err = err.into_string();
            if let Err(_) = to_kernel_tx.unbounded_send(HdpServerResult::InternalServerError(Some(ticket_id), err.clone())) {
                log::error!("TO_KERNEL_TX Error: {:?}", err);
                return Err(NetworkError::InternalError("kernel disconnected from hypernode instance"));
            } else {
                Ok(())
            }
        };

        while let Some((outbound_request, ticket_id)) = outbound_send_request_rx.next().await {
            match outbound_request {
                HdpServerRequest::GroupBroadcastCommand(implicated_cid, cmd) => {
                    if let Err(err) = session_manager.process_outbound_broadcast_command(ticket_id, implicated_cid, cmd) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::RegisterToHypernode(peer_addr, credentials, fcm_keys,  security_settings) => {
                    match session_manager.initiate_connection(local_node_type, local_nat_type.clone(), HdpSessionInitMode::Register(peer_addr, credentials),ticket_id, None, listener_underlying_proto.clone(), fcm_keys, None,None, security_settings, &default_client_config).await {
                        Ok(session) => {
                            session_spawner.unbounded_send(session).map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            send_error(ticket_id, err)?;
                        }
                    }
                }

                HdpServerRequest::ConnectToHypernode(authentication_request, connect_mode, fcm_keys, udp_mode, keep_alive_timeout,  security_settings) => {
                    match session_manager.initiate_connection(local_node_type, local_nat_type.clone(), HdpSessionInitMode::Connect(authentication_request), ticket_id,  Some(connect_mode), listener_underlying_proto.clone(), fcm_keys, Some(udp_mode), keep_alive_timeout.map(|val| (val as i64) * 1_000_000_000), security_settings, &default_client_config).await {
                        Ok(session) => {
                            session_spawner.unbounded_send(session).map_err(|err| NetworkError::Generic(err.to_string()))?;
                        }

                        Err(err) => {
                            send_error(ticket_id, err)?;
                        }
                    }
                }

                HdpServerRequest::DisconnectFromHypernode(implicated_cid, target) => {
                    if let Err(err) = session_manager.initiate_disconnect(implicated_cid, target, ticket_id) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::ReKey(virtual_target) => {
                    if let Err(err) = session_manager.initiate_update_drill_subroutine(virtual_target, ticket_id) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::DeregisterFromHypernode(implicated_cid, virtual_connection_type) => {
                    if let Err(err) = session_manager.initiate_deregistration_subroutine(implicated_cid, virtual_connection_type, ticket_id) {
                        send_error(ticket_id, err)?;
                    }
                }

                // TODO: Update this to include security levels (FCM conflicts though)
                HdpServerRequest::PeerCommand(implicated_cid, peer_command) => {
                    if let Err(err) = session_manager.dispatch_peer_command(implicated_cid, ticket_id, peer_command, SecurityLevel::LOW).await {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::SendFile(path, chunk_size, implicated_cid, virtual_target) => {
                    if let Err(err) = session_manager.process_outbound_file(ticket_id, chunk_size, path, implicated_cid, virtual_target, SecurityLevel::LOW) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::GetActiveSessions => {
                    if let Err(err) = to_kernel_tx.unbounded_send(HdpServerResult::SessionList(ticket_id, session_manager.get_active_sessions())) {
                        send_error(ticket_id, NetworkError::Generic(err.to_string()))?;
                    }
                }

                HdpServerRequest::Shutdown => {
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
    outbound_send_request_tx: BoundedSender<(HdpServerRequest, Ticket)>,
    inner: Arc<HdpServerRemoteInner>
}

struct HdpServerRemoteInner {
    callback_handler: KernelAsyncCallbackHandler,
    node_type: NodeType,
    account_manager: AccountManager
}

#[async_trait::async_trait]
pub trait Remote: Clone + Send {
    async fn send(&mut self, request: HdpServerRequest) -> Result<Ticket, NetworkError>;
    async fn send_callback_stream(&mut self, request: HdpServerRequest) -> Result<KernelStreamSubscription, NetworkError>;
    async fn send_callback(&mut self, request: HdpServerRequest) -> Result<HdpServerResult, NetworkError>;
    fn account_manager(&self) -> &AccountManager;
}

#[async_trait::async_trait]
impl Remote for NodeRemote {
    async fn send(&mut self, request: HdpServerRequest) -> Result<Ticket, NetworkError> {
        NodeRemote::send(self, request).await
    }

    async fn send_callback_stream(&mut self, request: HdpServerRequest) -> Result<KernelStreamSubscription, NetworkError> {
        NodeRemote::send_callback_stream(self, request).await
    }

    async fn send_callback(&mut self, request: HdpServerRequest) -> Result<HdpServerResult, NetworkError> {
        NodeRemote::send_callback(self, request).await
    }

    fn account_manager(&self) -> &AccountManager {
        NodeRemote::account_manager(self)
    }
}

impl Debug for NodeRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HdpServerRemote")
    }
}

impl NodeRemote {
    /// Creates a new [HdpServerRemote]
    pub(crate) fn new(outbound_send_request_tx: BoundedSender<(HdpServerRequest, Ticket)>, callback_handler: KernelAsyncCallbackHandler, account_manager: AccountManager, node_type: NodeType) -> Self {
        // starts at 1. Ticket 0 is for reserved
        Self { outbound_send_request_tx, inner: Arc::new(HdpServerRemoteInner { callback_handler, account_manager, node_type }) }
    }

    /// Especially used to keep track of a conversation (b/c a certain ticket number may be expected)
    pub async fn send_with_custom_ticket(&mut self, ticket: Ticket, request: HdpServerRequest) -> Result<(), NetworkError> {
        self.outbound_send_request_tx.send((request, ticket)).await
    }

    /// Sends a request to the HDP server. This should always be used to communicate with the server
    /// in order to obtain a ticket
    pub async fn send(&mut self, request: HdpServerRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request).await.map(|_| ticket)
    }

    /// Returns an error if the ticket is already registered for a callback
    pub async fn send_callback_custom_ticket(&mut self, request: HdpServerRequest, ticket: Ticket) -> Result<HdpServerResult, NetworkError> {
        let rx = self.inner.callback_handler.register_future(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => {
                rx.await.map_err(|err| NetworkError::Generic(err.to_string()))
            }

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Returns an error if the ticket is already registered for a stream-callback
    pub(crate) async fn send_callback_stream_custom_ticket(&mut self, request: HdpServerRequest, ticket: Ticket) -> Result<KernelStreamSubscription, NetworkError> {
        let rx = self.inner.callback_handler.register_stream(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => {
                Ok(rx)
            }

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback_stream(&mut self, request: HdpServerRequest) -> Result<KernelStreamSubscription, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_stream_custom_ticket(request, ticket).await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback(&mut self, request: HdpServerRequest) -> Result<HdpServerResult, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_custom_ticket(request, ticket).await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket (with a timeout)
    pub async fn send_callback_timeout(&mut self, request: HdpServerRequest, timeout: Duration) -> Result<HdpServerResult, NetworkError> {
        tokio::time::timeout(timeout, self.send_callback(request)).await.map_err(|_| NetworkError::Timeout(0))?
    }

    /// Safely shutsdown the internal server
    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        let _ = self.send(HdpServerRequest::Shutdown).await?;
        self.outbound_send_request_tx.close().await
    }

    // Note: when two nodes create a ticket, there may be equivalent values
    // Thus, use UUID's instead
    pub fn get_next_ticket(&self) -> Ticket {
        uuid::Uuid::new_v4().as_u128().into()
    }

    pub fn try_send_with_custom_ticket(&mut self, ticket: Ticket, request: HdpServerRequest) -> Result<(), TrySendError<(HdpServerRequest, Ticket)>> {
        self.outbound_send_request_tx.try_send((request, ticket))
    }

    pub fn try_send(&mut self, request: HdpServerRequest) -> Result<(), TrySendError<(HdpServerRequest, Ticket)>> {
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

impl Sink<(Ticket, HdpServerRequest)> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<HdpServerRequest>>::poll_ready(self, cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: (Ticket, HdpServerRequest)) -> Result<(), Self::Error> {
        Pin::new(&mut self.outbound_send_request_tx).start_send((item.1, item.0))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<HdpServerRequest>>::poll_flush(self, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<HdpServerRequest>>::poll_close(self, cx)
    }
}

impl Sink<HdpServerRequest> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: HdpServerRequest) -> Result<(), Self::Error> {
        let ticket = self.get_next_ticket();
        Pin::new(&mut self.outbound_send_request_tx).start_send((item, ticket))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx).poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx).poll_close(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

/// These are sent down the stack into the server. Most of the requests expect a ticket ID
/// in order for processes sitting above the [Kernel] to know how the request went
#[allow(variant_size_differences)]
pub enum HdpServerRequest {
    /// Sends a request to the underlying HdpSessionManager to begin connecting to a new client
    RegisterToHypernode(SocketAddr, ProposedCredentials, Option<FcmKeys>, SessionSecuritySettings),
    /// A high-level peer command. Can be used to facilitate communications between nodes in the HyperLAN
    PeerCommand(u64, PeerSignal),
    /// For submitting a de-register request
    DeregisterFromHypernode(u64, VirtualConnectionType),
    /// Implicated CID, creds, connect mode, fcm keys, TCP/TLS only, keep alive timeout, security settings
    ConnectToHypernode(AuthenticationRequest, ConnectMode, Option<FcmKeys>, UdpMode, Option<u32>, SessionSecuritySettings),
    /// Updates the drill for the given CID
    ReKey(VirtualTargetType),
    /// Send a file
    SendFile(PathBuf, Option<usize>, u64, VirtualTargetType),
    /// A group-message related command
    GroupBroadcastCommand(u64, GroupBroadcast),
    /// Tells the server to disconnect a session (implicated cid, target_cid)
    DisconnectFromHypernode(u64, VirtualConnectionType),
    /// Returns a list of connected sessions
    GetActiveSessions,
    /// shutdown signal
    Shutdown,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
/// If force_login is true, the protocol will disconnect any previously existent sessions in the session manager attributed to the account logging-in (so long as login succeeds)
/// The default is a Standard login that will with force_login set to false
pub enum ConnectMode {
    Standard { force_login: bool },
    Fetch { force_login: bool }
}

impl Default for ConnectMode {
    fn default() -> Self {
        Self::Standard { force_login: false }
    }
}

/// This type is for relaying results between the lower-level server and the higher-level kernel
/// TODO: Convert to enum structs
#[derive(Debug)]
pub enum HdpServerResult {
    /// Returns the CNAC which was created during the registration process
    RegisterOkay(Ticket, ClientNetworkAccount, Vec<u8>),
    /// The registration was a failure
    RegisterFailure(Ticket, String),
    /// When de-registration occurs. Third is_personal, Fourth is true if success, false otherwise
    DeRegistration(VirtualConnectionType, Option<Ticket>, bool, bool),
    /// Connection succeeded for the cid self.0. bool is "is personal"
    ConnectSuccess(Ticket, u64, SocketAddr, bool, VirtualConnectionType, Option<RawFcmPacketStore>, ServicesObject, String, PeerChannel, Option<tokio::sync::oneshot::Receiver<UdpChannel>>),
    /// The connection was a failure
    ConnectFail(Ticket, Option<u64>, String),
    /// The outbound request was rejected
    OutboundRequestRejected(Ticket, Option<Vec<u8>>),
    /// For file transfers. Implicated CID, Peer/Target CID, object ID
    FileTransferStatus(u64, FileKey, Ticket, FileTransferStatus),
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
    PeerChannelCreated(Ticket, PeerChannel, Option<tokio::sync::oneshot::Receiver<UdpChannel>>),
    /// A list of running sessions
    SessionList(Ticket, Vec<u64>),
    /// For shutdowns
    Shutdown,
}

impl HdpServerResult {
    pub fn is_connect_success_type(&self) -> bool {
        match self {
            HdpServerResult::ConnectSuccess(..) => true,
            _ => false
        }
    }

    pub fn ticket(&self) -> Option<Ticket> {
        match self {
            HdpServerResult::RegisterOkay(t, _, _) => {Some(*t)}
            HdpServerResult::RegisterFailure(t, _) => {Some(*t)}
            HdpServerResult::DeRegistration(_, t, _, _) => {t.clone()}
            HdpServerResult::ConnectSuccess(t,..) => {Some(*t)}
            HdpServerResult::ConnectFail(t, _, _) => {Some(*t)}
            HdpServerResult::OutboundRequestRejected(t, _) => {Some(*t)}
            HdpServerResult::FileTransferStatus(_, _, t, _) => {Some(*t)}
            HdpServerResult::MessageDelivery(t, _, _) => {Some(*t)}
            HdpServerResult::MessageDelivered(t) => {Some(*t)}
            HdpServerResult::MailboxDelivery(_, t, _) => {t.clone()}
            HdpServerResult::PeerEvent(_, t) => {Some(*t)}
            HdpServerResult::GroupEvent(_, t, _) => {Some(*t)}
            HdpServerResult::PeerChannelCreated(t, ..) => {Some(*t)}
            HdpServerResult::GroupChannelCreated(t, _) => {Some(*t)}
            HdpServerResult::Disconnect(t, _, _, _, _) => {Some(*t)}
            HdpServerResult::InternalServerError(t, _) => {t.clone()}
            HdpServerResult::SessionList(t, _) => {Some(*t)}
            HdpServerResult::Shutdown => {None}
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
    BestEffort
}

impl Default for SecrecyMode {
    fn default() -> Self {
        Self::BestEffort
    }
}