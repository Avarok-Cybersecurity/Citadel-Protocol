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
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::misc::platform_ops::PlatformOps;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::Mutex;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecurityLevel;
use citadel_user::account_manager::AccountManager;
use citadel_wire::hypernode_type::NodeType;
use citadel_wire::nat_identification::NatType;
use futures::StreamExt;
use netbeam::time_tracker::TimeTracker;

use crate::constants::MAX_OUTGOING_UNPROCESSED_REQUESTS;
use crate::error::NetworkError;
use crate::kernel::kernel_communicator::{
    KernelAsyncCallbackHandler, KernelAsyncCallbackHandlerInner,
};
use crate::kernel::kernel_executor::LocalSet;
use crate::kernel::RuntimeFuture;
use crate::prelude::ActiveSessions;
use crate::prelude::{DeleteObject, PullObject};
use crate::proto::node_request::{
    ConnectToHypernode, DeregisterFromHypernode, DisconnectFromHypernode, GroupBroadcastCommand,
    NodeRequest, PeerCommand, ReKey, RegisterToHypernode, SendObject,
};
use crate::proto::node_result::{InternalServerError, NodeResult, SessionList};
use crate::proto::outbound_sender::{BoundedReceiver, BoundedSender, UnboundedSender};
use crate::proto::packet_processor::includes::Duration;
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::{HdpSessionInitMode, ServerOnlySessionInitSettings};
use crate::proto::session_manager::CitadelSessionManager;
use citadel_io::ServerMode;

pub type TlsDomain = Option<String>;

// The outermost abstraction for the networking layer. We use Rc to allow ensure single-threaded performance
// by default, but settings can be changed in crate::macros::*.
define_outer_struct_wrapper!(CitadelNode, CitadelNodeInner, <R: Ratchet, T: PlatformOps>, <R, T>);

/// Inner device for the [`CitadelNode`]
pub struct CitadelNodeInner<R: Ratchet, T: PlatformOps> {
    primary_socket: Option<citadel_io::Mutex<T::Listener>>,
    /// Server bind address (set during init for server nodes).
    bind_address: Option<T::Addr>,
    /// Key: cid (to account for multiple clients from the same node)
    session_manager: CitadelSessionManager<R, T>,
    to_kernel: UnboundedSender<NodeResult<R>>,
    local_node_type: NodeType,
    // Applies only to listeners, not outgoing connections
    underlying_proto: ServerMode<T>,
    nat_type: NatType,
    // for TLS params
    client_config: T::ClientConfig,
    // All connecting/registering clients must present this pre-shared password in order to register and connect
    // to the server. This is an additional security measure to prevent unauthorized connections.
    server_only_session_init_settings: Option<ServerOnlySessionInitSettings>,
}

impl<R: Ratchet, T: PlatformOps> CitadelNode<R, T> {
    /// Creates a new [`CitadelNode`]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn init(
        local_node_type: NodeType,
        to_kernel: UnboundedSender<NodeResult<R>>,
        account_manager: AccountManager<R, R>,
        shutdown: citadel_io::tokio::sync::oneshot::Sender<()>,
        underlying_proto: ServerMode<T>,
        client_config: Option<T::ClientConfig>,
        stun_servers: Option<Vec<String>>,
        turn_servers: Option<Vec<crate::proto::session::TurnServerConfig>>,
        server_only_session_init_settings: Option<ServerOnlySessionInitSettings>,
        websocket_listen_addr: Option<std::net::SocketAddr>,
        pre_built_listener: Option<T::Listener>,
    ) -> io::Result<(
        NodeRemote<R>,
        Pin<Box<dyn RuntimeFuture>>,
        Option<LocalSet>,
        KernelAsyncCallbackHandler<R>,
    )> {
        let (primary_socket, bind_addr) = match local_node_type {
            NodeType::Server(bind_addr) => {
                if let Some(listener) = pre_built_listener {
                    // Serverless mode: use injected listener.
                    let addr = T::from_socket_addr(bind_addr);
                    (Some(citadel_io::Mutex::new(listener)), Some(addr))
                } else {
                    // Normal mode: bind to address.
                    let (listener, addr) =
                        T::bind(underlying_proto.clone(), T::from_socket_addr(bind_addr)).await?;
                    let listener = T::bind_with_websocket(listener, websocket_listen_addr).await?;
                    (Some(citadel_io::Mutex::new(listener)), Some(addr))
                }
            }

            NodeType::Peer => (None, None),
        };

        if let Some(local_bind_addr) = &bind_addr {
            log::info!(target: "citadel", "Citadel server established on {local_bind_addr:?}");
        } else {
            log::info!(target: "citadel", "Citadel client established")
        }

        let client_config = if let Some(config) = client_config {
            config
        } else {
            T::default_client_config().await?
        };

        let time_tracker = TimeTracker::new();
        let session_manager = CitadelSessionManager::new(
            local_node_type,
            to_kernel.clone(),
            account_manager.clone(),
            time_tracker,
            client_config.clone(),
            stun_servers.clone(),
            turn_servers,
        );

        let nat_type = T::identify_nat_type(stun_servers).await?;

        let inner = CitadelNodeInner {
            underlying_proto,
            local_node_type,
            primary_socket,
            bind_address: bind_addr,
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
        this: CitadelNode<R, T>,
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

        let localset_opt = crate::proto::misc::threading::create_localset();
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

            citadel_io::time::timeout(Duration::from_millis(1000), sess_mgr.shutdown())
                .await
                .map_err(|err| NetworkError::generic(err.to_string()))?;

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

    /// In impersonal mode, each hypernode needs to check for incoming connections on the primary port.
    /// Once a TcpStream is established, it is passed into the underlying HdpSessionManager and a Session
    /// is created to handle the stream.
    /// In personal mode, if a new connection needs to be forged with another node, then a new SO_REUSE socket
    /// will need to be created that is bound to the local primary port and connected to the adjacent hypernode's
    /// primary port. That socket will be created in the underlying HdpSessionManager during the connection process
    async fn listen_primary(
        server: CitadelNode<R, T>,
        _tt: TimeTracker,
        to_kernel: UnboundedSender<NodeResult<R>>,
        server_only_session_init_settings: ServerOnlySessionInitSettings,
    ) -> Result<(), NetworkError> {
        let primary_port_future = {
            let mut this = inner_mut!(server);
            let listener = this.primary_socket.take().unwrap().into_inner();
            let bind_address = this.bind_address.clone().unwrap();
            let session_manager = this.session_manager.clone();
            let local_nat_type = this.nat_type.clone();
            drop(this);
            Self::primary_session_creator_loop(
                bind_address,
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
        local_bind_addr: T::Addr,
        to_kernel: UnboundedSender<NodeResult<R>>,
        local_nat_type: NatType,
        session_manager: CitadelSessionManager<R, T>,
        mut socket: T::Listener,
        server_only_session_init_settings: ServerOnlySessionInitSettings,
    ) -> Result<(), NetworkError> {
        loop {
            match socket.next().await {
                Some(Ok((stream, peer_addr))) => {
                    log::trace!(target: "citadel", "Received stream from {peer_addr:?}");
                    let local_bind_addr = T::to_socket_addr(&local_bind_addr);
                    let peer_addr = T::to_socket_addr(&peer_addr);

                    log::trace!(target: "citadel", "[Server] Starting connection with remote={peer_addr:?}");

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
                                        "HDP Server dropping connection to {peer_addr:?}. Reason: {err}"
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
                    return Err(error!(ErrorCode::KernelPrimaryListenerDied));
                }
            }
        }
    }

    async fn outbound_kernel_request_handler(
        this: CitadelNode<R, T>,
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
                log::error!(target: "citadel", "TO_KERNEL_TX Error: {err:?}");
                Err(error!(ErrorCode::KernelDisconnected))
            } else {
                Ok(())
            }
        }

        while let Some((outbound_request, ticket_id)) = outbound_send_request_rx.recv().await {
            if let Some(cid) = outbound_request.session_cid() {
                if cid == 0 {
                    send_error(
                        &to_kernel_tx,
                        ticket_id,
                        error!(
                            ErrorCode::KernelZeroCidRequest,
                            format!("{outbound_request:?}")
                        ),
                    )?;
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
                            sessions: ActiveSessions {
                                sessions: session_manager.get_active_sessions(),
                                local_nat_type: local_nat_type.clone(),
                            },
                        }))
                    {
                        send_error(
                            &to_kernel_tx,
                            ticket_id,
                            NetworkError::generic(err.to_string()),
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
