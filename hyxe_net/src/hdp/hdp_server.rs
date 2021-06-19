use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures::{Sink, StreamExt};
use log::info;
use net2::TcpListenerExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::task::LocalSet;
use tokio_native_tls::native_tls::Identity;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::local_firewall_handler::{FirewallProtocol, open_local_firewall_port, remove_firewall_rule};
use hyxe_nat::time_tracker::TimeTracker;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::external_services::fcm::data_structures::RawFcmPacketStore;
use hyxe_user::proposed_credentials::ProposedCredentials;

use crate::constants::{DEFAULT_SO_LINGER_TIME, NTP_RESYNC_FREQUENCY, TCP_CONN_TIMEOUT, MAX_OUTGOING_UNPROCESSED_REQUESTS};
use crate::error::NetworkError;
use crate::functional::PairMap;
use crate::hdp::file_transfer::FileTransferStatus;
use crate::hdp::hdp_packet_processor::includes::{Duration, Instant};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::hdp::hdp_session::HdpSessionInitMode;
use crate::hdp::hdp_session_manager::HdpSessionManager;
use crate::hdp::misc::net::{GenericNetworkListener, GenericNetworkStream, TlsListener, FirstPacket};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::outbound_sender::{UnboundedSender, BoundedSender, BoundedReceiver};
use crate::hdp::peer::channel::PeerChannel;
use crate::hdp::peer::peer_layer::{MailboxTransfer, PeerSignal};
use crate::hdp::state_container::{FileKey, VirtualConnectionType, VirtualTargetType};
use crate::kernel::RuntimeFuture;
use tokio::io::AsyncReadExt;
use hyxe_fs::io::SyncIO;
use hyxe_user::external_services::PostLoginObject;

/// ports which were opened that must be closed atexit
static OPENED_PORTS: Mutex<Vec<u16>> = parking_lot::const_mutex(Vec::new());

pub extern fn atexit() {
    log::info!("Cleaning up firewall ports ...");
    let lock = OPENED_PORTS.lock();
    for port in lock.iter() {
        HdpServer::close_tcp_port(*port);
    }
}

#[derive(Clone)]
#[allow(variant_size_differences)]
pub enum UnderlyingProtocol {
    Tcp,
    Tls(Identity, TlsDomain)
}

pub type TlsDomain = Option<String>;

// The outermost abstraction for the networking layer. We use Rc to allow ensure single-threaded performance
// by default, but settings can be changed in crate::macros::*.
define_outer_struct_wrapper!(HdpServer, HdpServerInner);

/// Inner device for the HdpServer
pub struct HdpServerInner {
    primary_socket: Option<GenericNetworkListener>,
    /// Key: cid (to account for multiple clients from the same node)
    session_manager: HdpSessionManager,
    local_bind_addr: SocketAddr,
    to_kernel: UnboundedSender<HdpServerResult>,
    local_node_type: HyperNodeType,
    // Applies only to listeners, not outgoing connections
    underlying_proto: UnderlyingProtocol
}

impl HdpServer {
    /// Creates a new [HdpServer]
    pub async fn init<T: tokio::net::ToSocketAddrs + std::net::ToSocketAddrs>(local_node_type: HyperNodeType, to_kernel: UnboundedSender<HdpServerResult>, bind_addr: T, account_manager: AccountManager, shutdown: tokio::sync::oneshot::Sender<()>, underlying_proto: UnderlyingProtocol) -> io::Result<(HdpServerRemote, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>)> {
        let (primary_socket, local_bind_addr) = if local_node_type == HyperNodeType::GloballyReachable {
            Self::create_tcp_listen_socket(underlying_proto.clone(), &bind_addr)?.map_left(|r| Some(r))
        } else {
            (None, std::net::ToSocketAddrs::to_socket_addrs(&bind_addr)?.next().ok_or(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid bind address"))?)
        };

        let primary_port = local_bind_addr.port();
        // Note: on Android/IOS, the below command will fail since sudo access is prohibited
        Self::open_tcp_port(primary_port);

        info!("HdpServer established on {}", local_bind_addr);

        let time_tracker = TimeTracker::new().await?;
        let session_manager = HdpSessionManager::new(local_node_type, to_kernel.clone(), account_manager, time_tracker.clone());
        let inner = HdpServerInner {
            underlying_proto,
            local_bind_addr,
            local_node_type,
            primary_socket,
            to_kernel,
            session_manager,
        };

        let this = Self::from(inner);
        Ok(HdpServer::load(this, shutdown).await)
    }

    /// Note: spawning via handle is more efficient than joining futures. Source: https://cafbit.com/post/tokio_internals/
    /// To handle the shutdown process, we need
    ///
    /// This will panic if called twice in succession without a proper server reload.
    ///
    /// Returns a handle to communicate with the [HdpServer].
    #[allow(unused_results, unused_must_use)]
    async fn load(this: HdpServer, shutdown: tokio::sync::oneshot::Sender<()>) -> (HdpServerRemote, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>) {
        // Allow the listeners to read data without instantly returning
        // Load the readers
        let read = inner!(this);

        let sess_mgr = read.session_manager.clone();
        let kernel_tx = read.to_kernel.clone();
        let node_type = read.local_node_type;

        let (outbound_send_request_tx, outbound_send_request_rx) = BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS); // for the Hdp remote
        let remote = HdpServerRemote::new(outbound_send_request_tx);
        let tt = read.session_manager.load_server_remote_get_tt(remote.clone());

        let (outbound_kernel_request_handler, primary_stream_listener, peer_container, localset_opt) = {
            #[cfg(feature = "multi-threaded")]
            {
                let outbound_kernel_request_handler = spawn_handle!(Self::outbound_kernel_request_handler(this.clone(), kernel_tx.clone(), outbound_send_request_rx));
                let primary_stream_listener = if node_type == HyperNodeType::GloballyReachable { Some(spawn_handle!(Self::listen_primary(this.clone(), tt, kernel_tx.clone()))) } else { None };
                let peer_container = spawn_handle!(HdpSessionManager::run_peer_container(read.session_manager.clone()));
                let localset_opt = None;
                (outbound_kernel_request_handler, primary_stream_listener, peer_container, localset_opt)
            }

            #[cfg(not(feature = "multi-threaded"))]
                {
                    let localset = LocalSet::new();
                    let outbound_kernel_request_handler = crate::hdp::misc::panic_future::ExplicitPanicFuture::new(localset.spawn_local(Self::outbound_kernel_request_handler(this.clone(), kernel_tx.clone(), outbound_send_request_rx)));
                    let primary_stream_listener = if node_type == HyperNodeType::GloballyReachable { Some(crate::hdp::misc::panic_future::ExplicitPanicFuture::new(localset.spawn_local(Self::listen_primary(this.clone(), tt, kernel_tx.clone())))) } else { None };
                    let peer_container = crate::hdp::misc::panic_future::ExplicitPanicFuture::new(localset.spawn_local(HdpSessionManager::run_peer_container(read.session_manager.clone())));
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
                    res2 = peer_container => res2
                }
            } else {
                tokio::select! {
                    res0 = outbound_kernel_request_handler => {
                        log::info!("OUTBOUND KERNEL REQUEST HANDLER ENDED: {:?}", &res0);
                        res0
                    }

                    res1 = peer_container => res1
                }
            };

            if let Err(_) = kernel_tx.unbounded_send(HdpServerResult::Shutdown) {
                log::warn!("Unable to send shutdown result to kernel (kernel died prematurely?)");
            }

            // the kernel will wait until the server shuts down to prevent cleanup tasks from being killed too early
            shutdown.send(());

            tokio::time::timeout(Duration::from_millis(1000), sess_mgr.shutdown()).await.map_err(|err| NetworkError::Generic(err.to_string()))??;

            log::info!("HdpServer shutting down (future ended)...");

            res.map_err(|err| NetworkError::Generic(err.to_string()))?
        };

        //handle.load_server_future(server_future);

        (remote, Box::pin(server_future), localset_opt)
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

    pub(crate) fn create_tcp_listen_socket<T: ToSocketAddrs>(underlying_proto: UnderlyingProtocol, full_bind_addr: T) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        let bind: SocketAddr = full_bind_addr.to_socket_addrs()?.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;

        if bind.is_ipv4() {
            let ref builder = net2::TcpBuilder::new_v4()?;
            Self::bind_defaults(underlying_proto, builder, bind, 1024)
        } else {
            let builder = net2::TcpBuilder::new_v6()?;
            Self::bind_defaults(underlying_proto, builder.only_v6(false)?, bind, 1024)
        }
    }

    fn bind_defaults(underlying_proto: UnderlyingProtocol, builder: &net2::TcpBuilder, bind: SocketAddr, backlog: i32) -> io::Result<(GenericNetworkListener, SocketAddr)> {
        builder
            .reuse_address(true)?
            .bind(bind)?
            .listen(backlog)
            .and_then(|std_stream| {
                std_stream.set_nonblocking(true)?;
                //std_stream.set_linger(Some(Duration::from_millis(0)))?;
                std_stream.set_linger(Some(DEFAULT_SO_LINGER_TIME))?;
                Ok(std_stream)
            })
            .map(tokio::net::TcpListener::from_std)?
            .and_then(|listener| {
                match underlying_proto {
                    UnderlyingProtocol::Tcp => {
                        Ok((GenericNetworkListener::Tcp(listener), bind))
                    }

                    UnderlyingProtocol::Tls(identity, domain) => {
                        let tls_listener = TlsListener::new(listener, identity, domain.unwrap_or_else(|| "".to_string()))?;
                        Ok((GenericNetworkListener::Tls(tls_listener), bind))
                    }
                }
            })
    }

    /// Returns a TcpStream to the remote addr, as well as a local TcpListener on the same bind addr going to remote
    /// to allow for TCP hole-punching (we need the same port to cover port-restricted NATS, worst-case scenario)
    pub(crate) async fn create_init_tcp_listener<R: ToSocketAddrs>(listener_underlying_proto: UnderlyingProtocol, remote: R) -> io::Result<(GenericNetworkListener, GenericNetworkStream)> {
        let stream = Self::create_reuse_tcp_connect_socket(remote, None).await?;

        let stream_bind_addr = stream.local_addr()?;

        let (p2p_listener, _stream_bind_addr) = if stream_bind_addr.is_ipv4() {
            let ref builder = net2::TcpBuilder::new_v4()?;
            Self::bind_defaults(listener_underlying_proto, builder, stream_bind_addr, 16)?
        } else {
            let builder = net2::TcpBuilder::new_v6()?;
            Self::bind_defaults(listener_underlying_proto,builder.only_v6(false)?, stream_bind_addr, 16)?
        };
        Self::open_tcp_port(stream_bind_addr.port());

        Ok((p2p_listener, stream))
    }

    pub(crate) async fn create_reuse_tcp_connect_socket<R: ToSocketAddrs>(remote: R, timeout: Option<Duration>) -> io::Result<GenericNetworkStream> {
        let remote: SocketAddr = remote.to_socket_addrs()?.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "bad addr"))?;
        Self::connect_defaults(timeout, remote).await
    }

    async fn connect_defaults(timeout: Option<Duration>, remote: SocketAddr) -> io::Result<GenericNetworkStream> {
        let mut stream = tokio::time::timeout(timeout.unwrap_or(TCP_CONN_TIMEOUT), tokio::task::spawn_blocking(move || {
            let std_stream = if remote.is_ipv4() {
                net2::TcpBuilder::new_v4()?
                    .reuse_address(true)?
                    .connect(remote)?
            } else {
                net2::TcpBuilder::new_v6()?
                    .only_v6(false)?
                    .reuse_address(true)?
                    .connect(remote)?
            };

            std_stream.set_nonblocking(true)?;

            let stream = tokio::net::TcpStream::from_std(std_stream)?;
            //stream.set_linger(Some(tokio::time::Duration::from_secs(0)))?;
            stream.set_linger(Some(DEFAULT_SO_LINGER_TIME))?;
            //stream.set_keepalive(None)?;

            Ok(stream) as std::io::Result<tokio::net::TcpStream>
        })).await???;

        let buf = &mut [0u8; 4096];
        let amt = tokio::time::timeout(timeout.unwrap_or(TCP_CONN_TIMEOUT), stream.read(buf as &mut [u8])).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string()))??;
        let first_packet: FirstPacket = FirstPacket::deserialize_from_vector(&buf[..amt]).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;

        match first_packet {
            FirstPacket::Tcp => {
                log::info!("Host claims TCP DEFAULT CONNECTION");
                Ok(GenericNetworkStream::Tcp(stream))
            }

            FirstPacket::Tls(domain) => {
                log::info!("Host claims TLS CONNECTION (domain: {:?})", &domain);
                // for debug builds, allow invalid certs to make testing TLS easier
                //#[cfg(debug_assertions)]
                let connector = tokio_native_tls::native_tls::TlsConnector::builder().use_sni(true).danger_accept_invalid_certs(true).build().map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                //#[cfg(not(debug_assertions))]
                //    let connector = tokio_native_tls::native_tls::TlsConnector::builder().use_sni(true).build().map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;

                let connector = tokio_native_tls::TlsConnector::from(connector);
                let stream = connector.connect(domain.as_ref().map(|r| r.as_str()).unwrap_or(""), stream).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                //let stream = connector.connect("", stream).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                Ok(GenericNetworkStream::Tls(stream))
            }
        }


        /*match connect_underlying_proto {
            ConnectProtocol::Tcp => {
                Ok(GenericNetworkStream::Tcp(stream))
            }

            ConnectProtocol::Tls(domain) => {
                // for debug builds, allow invalid certs to make testing TLS easier
                //#[cfg(debug_assertions)]
                let connector = tokio_native_tls::native_tls::TlsConnector::builder().use_sni(true).danger_accept_invalid_certs(true).build().map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                //#[cfg(not(debug_assertions))]
                //    let connector = tokio_native_tls::native_tls::TlsConnector::builder().use_sni(true).build().map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;

                let connector = tokio_native_tls::TlsConnector::from(connector);
                let stream = connector.connect(domain.as_ref().map(|r| r.as_str()).unwrap_or(""), stream).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
                Ok(GenericNetworkStream::Tls(stream))
            }
        }*/
    }

    /// In impersonal mode, each hypernode needs to check for incoming connections on the primary port.
    /// Once a TcpStream is established, it is passed into the underlying HdpSessionManager and a Session
    /// is created to handle the stream.
    ///
    /// In personal mode, if a new connection needs to be forged with another node, then a new SO_REUSE socket
    /// will need to be created that is bound to the local primary port and connected to the adjacent hypernode's
    /// primary port. That socket will be created in the underlying HdpSessionManager during the connection process
    async fn listen_primary(server: HdpServer, tt: TimeTracker, to_kernel: UnboundedSender<HdpServerResult>) -> Result<(), NetworkError> {
        let (primary_port_future, tt_updater_future) = {
            let mut this = inner_mut!(server);
            let socket = this.primary_socket.take().unwrap();
            let session_manager = this.session_manager.clone();
            std::mem::drop(this);
            let primary_port_future = spawn_handle!(Self::primary_session_creator_loop(to_kernel, session_manager, socket));
            let tt_updater_future = spawn_handle!(Self::time_tracker_updater(tt));
            // If the timer detects that the server is shutdown, it will return an error, thus causing the try_join to end the future
            (primary_port_future, tt_updater_future)
        };

        let res = tokio::select! {
            res = primary_port_future => res,
            res1 = tt_updater_future => res1
        };

        res.map_err(|err| NetworkError::Generic(err.to_string()))?
    }

    #[allow(unused_results)]
    async fn time_tracker_updater(tt: TimeTracker) -> Result<(), NetworkError> {
        let mut iter = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval_at(Instant::now() + NTP_RESYNC_FREQUENCY, NTP_RESYNC_FREQUENCY));
        while let Some(_) = iter.next().await {
            if !tt.resync().await {
                log::warn!("Unable to resynchronize NTP time (non-fatal; clock may diverge from synchronicity)");
            }
        }

        Ok(())
    }


    async fn primary_session_creator_loop(to_kernel: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, mut socket: GenericNetworkListener) -> Result<(), NetworkError> {
        loop {
            //let _ = tokio::task::spawn_local(async move{ log::info!("HELLO 2 THE WORLD!") });
            match socket.next().await {
                Some(Ok((stream, peer_addr))) => {
                    log::trace!("Received stream from {:?}", peer_addr);
                    let local_bind_addr = stream.local_addr().unwrap();

                    //let res = tokio::task::spawn_local(async move{ log::info!("AAA HELLO 2 THE WORLD!") });
                    //log::info!("RES: {:?}", res);

                    //stream.set_linger(Some(tokio::time::Duration::from_secs(0))).unwrap();
                    // stream.set_keepalive(None).unwrap();
                    //stream.set_nodelay(true).unwrap();
                    // the below closure spawns a new future on the tokio thread pool
                    if let Err(err) = session_manager.process_new_inbound_connection(local_bind_addr, peer_addr, stream) {
                        to_kernel.unbounded_send(HdpServerResult::InternalServerError(None, format!("HDP Server dropping connection to {}. Reason: {}", peer_addr, err.to_string())))?;
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

    async fn outbound_kernel_request_handler(this: HdpServer, ref to_kernel_tx: UnboundedSender<HdpServerResult>, mut outbound_send_request_rx: BoundedReceiver<(HdpServerRequest, Ticket)>) -> Result<(), NetworkError> {
        let (primary_port, local_bind_addr, local_node_type, session_manager, listener_underlying_proto) = {
            let read = inner!(this);
            let primary_port = read.local_bind_addr.port();
            //let port_start = read.multiport_range.start;
            let local_bind_addr = read.local_bind_addr.ip();
            let local_node_type = read.local_node_type;
            let listener_underlying_proto = read.underlying_proto.clone();

            // We need only the underlying [HdpSessionManager]
            let session_manager = read.session_manager.clone();
            // Drop the read handle; we are done with it
            //std::mem::drop(read);
            (primary_port, local_bind_addr, local_node_type, session_manager, listener_underlying_proto)
        };

        let send_error = |ticket_id: Ticket, err: NetworkError| {
            if let Err(_) = to_kernel_tx.unbounded_send(HdpServerResult::InternalServerError(Some(ticket_id), err.into_string())) {
                return Err(NetworkError::InternalError("kernel disconnected from hypernode instance"));
            } else {
                Ok(())
            }
        };

        while let Some((outbound_request, ticket_id)) = outbound_send_request_rx.next().await {
            match outbound_request {
                HdpServerRequest::SendMessage(packet, implicated_cid, virtual_target, security_level) => {
                    if let Err(err) = session_manager.process_outbound_packet(ticket_id, packet, implicated_cid, virtual_target, security_level) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::GroupBroadcastCommand(implicated_cid, cmd) => {
                    if let Err(err) = session_manager.process_outbound_broadcast_command(ticket_id, implicated_cid, cmd) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::RegisterToHypernode(peer_addr, credentials, fcm_keys,  security_settings) => {
                    if let Err(err) = session_manager.initiate_connection(local_node_type, (local_bind_addr, primary_port), HdpSessionInitMode::Register(peer_addr),ticket_id, credentials, None, listener_underlying_proto.clone(), fcm_keys, None, None, security_settings).await {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::ConnectToHypernode(implicated_cid, credentials, connect_mode, fcm_keys, tcp_only, keep_alive_timeout,  security_settings) => {
                    if let Err(err) = session_manager.initiate_connection(local_node_type, (local_bind_addr, primary_port), HdpSessionInitMode::Connect(implicated_cid), ticket_id, credentials, Some(connect_mode), listener_underlying_proto.clone(), fcm_keys, tcp_only, keep_alive_timeout.map(|val| (val as i64) * 1_000_000_000), security_settings).await {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::DisconnectFromHypernode(implicated_cid, target) => {
                    if let Err(err) = session_manager.initiate_disconnect(implicated_cid, target, ticket_id) {
                        send_error(ticket_id, err)?;
                    }
                }

                HdpServerRequest::UpdateDrill(virtual_target) => {
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
pub struct HdpServerRemote {
    outbound_send_request_tx: BoundedSender<(HdpServerRequest, Ticket)>,
    ticket_counter: Arc<AtomicUsize>,
}

impl Debug for HdpServerRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HdpServerRemote")
    }
}

impl HdpServerRemote {
    /// Creates a new [HdpServerRemote]
    pub fn new(outbound_send_request_tx: BoundedSender<(HdpServerRequest, Ticket)>) -> Self {
        // starts at 1. Ticket 0 is for reserved
        Self { ticket_counter: Arc::new(AtomicUsize::new(1)), outbound_send_request_tx }
    }

    /// Especially used to keep track of a conversation (b/c a certain ticket number may be expected)
    pub async fn send_with_custom_ticket(&mut self, ticket: Ticket, request: HdpServerRequest) -> Result<(), NetworkError> {
        struct Send<T> {
            inner: Option<T>
        }

        let mut item = Send {
            inner: Some((request, ticket))
        };

        futures::future::poll_fn(|cx| {
            let mut this = &mut self.outbound_send_request_tx;
            let mut this = Pin::new(&mut this);
            futures::ready!(this.as_mut().poll_ready(cx))?;

            if let Some(item) = item.inner.take() {
                this.as_mut().start_send(item)?;
            }

            this.poll_flush(cx).map_err(|err| NetworkError::Generic(err.to_string()))
        }).await
    }

    /// Sends a request to the HDP server. This should always be used to communicate with the server
    /// in order to obtain a ticket
    pub async fn send(&mut self, request: HdpServerRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request).await.map(|_| ticket)
    }

    /// Safely shutsdown the internal server
    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        let _ = self.send(HdpServerRequest::Shutdown).await?;

        futures::future::poll_fn(|cx| {
            let mut this = &mut self.outbound_send_request_tx;
            let this = Pin::new(&mut this);
            this.poll_close(cx).map_err(|err| NetworkError::Generic(err.to_string()))
        }).await
    }

    pub fn get_next_ticket(&self) -> Ticket {
        Ticket(self.ticket_counter.fetch_add(1, Ordering::Relaxed) as u64)
    }
}

impl Unpin for HdpServerRemote {}

impl Sink<(Ticket, HdpServerRequest)> for HdpServerRemote {
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

impl Sink<HdpServerRequest> for HdpServerRemote {
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
    /// Sends a request to the underlying [HdpSessionManager] to begin connecting to a new client
    RegisterToHypernode(SocketAddr, ProposedCredentials, Option<FcmKeys>, SessionSecuritySettings),
    /// A high-level peer command. Can be used to facilitate communications between nodes in the HyperLAN
    PeerCommand(u64, PeerSignal),
    /// For submitting a de-register request
    DeregisterFromHypernode(u64, VirtualConnectionType),
    /// Send data to client. Peer addr, implicated cid, hdp_nodelay, quantum algorithm, tcp only,
    ConnectToHypernode(u64, ProposedCredentials, ConnectMode, Option<FcmKeys>, Option<bool>, Option<u32>, SessionSecuritySettings),
    /// Updates the drill for the given CID
    UpdateDrill(VirtualTargetType),
    /// Send data to an already existent connection
    SendMessage(SecBuffer, u64, VirtualTargetType, SecurityLevel),
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

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum ConnectMode {
    Standard,
    Fetch
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
    ConnectSuccess(Ticket, u64, SocketAddr, bool, VirtualConnectionType, Option<RawFcmPacketStore>, PostLoginObject, String, PeerChannel),
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
    /// for group-related events. Implicated cid, ticket, group info
    GroupEvent(u64, Ticket, GroupBroadcast),
    /// vt-cxn-type is optional, because it may have only been a provisional connection
    Disconnect(Ticket, u64, bool, Option<VirtualConnectionType>, String),
    /// An internal error occured
    InternalServerError(Option<Ticket>, String),
    /// A channel was created, with channel_id = ticket (same as post-connect ticket received)
    PeerChannelCreated(Ticket, PeerChannel),
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
}

/// A type sent through the server when a request is made
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Ticket(pub u64);

impl Into<Ticket> for u64 {
    fn into(self) -> Ticket {
        Ticket(self)
    }
}

impl Into<Ticket> for usize {
    fn into(self) -> Ticket {
        Ticket(self as u64)
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