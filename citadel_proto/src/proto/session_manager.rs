//! # Session Manager for Citadel Protocol
//!
//! The Session Manager is responsible for handling and maintaining stateful connections between peers
//! in the Citadel Protocol. It manages both client-server and peer-to-peer connections, handling
//! session establishment, maintenance, and termination.
//!
//! ## Features
//!
//! * Session lifecycle management (creation, maintenance, termination)
//! * Handles both provisional and established connections
//! * Manages peer-to-peer communication and group broadcasts
//! * Supports secure file transfers with configurable security levels
//! * Implements connection upgrades from provisional to full sessions
//! * Provides message group functionality for group communications
//! * Handles virtual connections and connection state transitions
//! * Supports both UDP and TCP transport protocols
//!
//! ## Important Notes
//!
//! * Session management is thread-safe and handles concurrent connections
//! * Sessions are identified by unique CIDs (Connection IDs)
//! * Provisional connections are temporary and must be upgraded to full sessions
//! * Clean shutdown procedures ensure proper resource cleanup
//! * Implements timeout mechanisms for connection management
//!
//! ## Related Components
//!
//! * `CitadelSession`: Handles individual session state and operations
//! * `HyperNodePeerLayer`: Manages peer-to-peer communications
//! * `GroupBroadcast`: Implements group messaging functionality
//! * `PeerSignal`: Handles peer-to-peer signaling
//! * `NodeRemote`: Manages remote node connections
//! * `packet_processor`: Processes various packet types
//! * `AccountManager`: Manages user authentication and credentials
//!

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use bytes::BytesMut;

use citadel_crypt::ratchets::Ratchet;
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::prelude::{ConnectProtocol, UserIdentifierExt};
use citadel_wire::hypernode_type::NodeType;
use citadel_wire::nat_identification::NatType;
use netbeam::time_tracker::TimeTracker;

use crate::auth::AuthenticationRequest;
use crate::constants::{DO_CONNECT_EXPIRE_TIME_MS, KEEP_ALIVE_TIMEOUT_NS};
use crate::error::NetworkError;
use crate::macros::{FutureRequirements, SyncContextRequirements};
use crate::prelude::Disconnect;
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::misc::underlying_proto::ServerUnderlyingProtocol;
use crate::proto::node::CitadelNode;
use crate::proto::node_result::NodeResult;
use crate::proto::outbound_sender::{unbounded, UnboundedReceiver, UnboundedSender};
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::includes::{Duration, Instant};
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::peer_layer::{
    CitadelNodePeerLayer, CitadelNodePeerLayerInner, MailboxTransfer, PeerConnectionType,
    PeerResponse, PeerSignal,
};
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::{
    CitadelSession, ClientOnlySessionInitSettings, HdpSessionInitMode,
    ServerOnlySessionInitSettings, SessionInitParams, SessionState,
};
use crate::proto::state_container::{VirtualConnectionType, VirtualTargetType};
use citadel_crypt::scramble::streaming_crypt_scrambler::ObjectSource;
use citadel_io::tokio::sync::broadcast::Sender;
use citadel_types::crypto::{PreSharedKey, SecurityLevel};
use citadel_types::proto::ConnectMode;
use citadel_types::proto::SessionSecuritySettings;
use citadel_types::proto::TransferType;
use citadel_types::proto::{
    GroupMemberAlterMode, MemberState, MessageGroupKey, MessageGroupOptions, UdpMode,
};
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::exports::tokio_rustls::rustls::ClientConfig;
use std::sync::Arc;

define_outer_struct_wrapper!(CitadelSessionManager, HdpSessionManagerInner, <R: Ratchet>, <R>);

/// Used for handling stateful connections between two peer
pub struct HdpSessionManagerInner<R: Ratchet> {
    local_node_type: NodeType,
    pub(crate) sessions: HashMap<u64, (Sender<()>, CitadelSession<R>)>,
    account_manager: AccountManager<R, R>,
    pub(crate) hypernode_peer_layer: CitadelNodePeerLayer<R>,
    server_remote: Option<NodeRemote<R>>,
    incoming_cxn_count: usize,
    /// Connections which have no implicated CID go herein. They are strictly expected to be
    /// in the state of NeedsRegister. Once they leave that state, they are eventually polled
    /// by the [CitadelSessionManager] and thereafter placed inside an appropriate session
    pub provisional_connections: HashMap<SocketAddr, (Instant, Sender<()>, CitadelSession<R>)>,
    kernel_tx: UnboundedSender<NodeResult<R>>,
    time_tracker: TimeTracker,
    clean_shutdown_tracker_tx: UnboundedSender<()>,
    clean_shutdown_tracker: Option<UnboundedReceiver<()>>,
    client_config: Arc<rustls::ClientConfig>,
    stun_servers: Option<Vec<String>>,
}

impl<R: Ratchet> CitadelSessionManager<R> {
    /// Creates a new [SessionManager] which handles individual connections
    pub fn new(
        local_node_type: NodeType,
        kernel_tx: UnboundedSender<NodeResult<R>>,
        account_manager: AccountManager<R, R>,
        time_tracker: TimeTracker,
        client_config: Arc<rustls::ClientConfig>,
        stun_servers: Option<Vec<String>>,
    ) -> Self {
        let incoming_cxn_count = 0;
        let (clean_shutdown_tracker_tx, clean_shutdown_tracker_rx) = unbounded();
        let inner = HdpSessionManagerInner {
            clean_shutdown_tracker_tx,
            clean_shutdown_tracker: Some(clean_shutdown_tracker_rx),
            hypernode_peer_layer: CitadelNodePeerLayer::new(
                account_manager.get_persistence_handler().clone(),
            ),
            server_remote: None,
            local_node_type,
            sessions: HashMap::new(),
            incoming_cxn_count,
            account_manager,
            provisional_connections: HashMap::new(),
            kernel_tx,
            time_tracker,
            client_config,
            stun_servers,
        };

        Self::from(inner)
    }

    /// Loads the server remote, and gets the time tracker for the calling [CitadelNode]
    /// Used during the init stage
    pub(crate) fn load_server_remote_get_tt(&self, server_remote: NodeRemote<R>) -> TimeTracker {
        let mut this = inner_mut!(self);
        this.server_remote = Some(server_remote);
        this.time_tracker
    }

    /// Determines if `cid` is connected
    pub async fn can_proceed_with_new_incoming_connection(&self, cid: u64) -> bool {
        let await_for_drop_rx = {
            let this = inner!(self);

            if let Some(sess) = this.sessions.get(&cid).map(|(_, sess)| sess).or_else(|| {
                this.provisional_connections
                    .values()
                    .find(|(_, _, sess)| sess.session_cid.get().unwrap_or_default() == cid)
                    .map(|(_, _, sess)| sess)
            }) {
                let current_state = sess.state.get();
                if current_state == SessionState::Connected {
                    citadel_logging::warn!(target: "citadel", "Session {cid} is already connected");
                    // Session is firmly connected, and not in the process of disconnecting
                    return false;
                }

                // If the session is not connected (implied per above), and, the session is not disconnecting, it is in the process of connecting
                if current_state != SessionState::Disconnecting {
                    citadel_logging::warn!(target: "citadel", "Session {cid} is already in the process of connecting (i.e., provisional)");
                    return false;
                }

                // If the drop listener is already some, that means the session is in the process of disconnecting,
                // AND, another connection attempt is in progress. Since we were not the first to initiate the connection
                // we must yield to the earlier connection attempt and not allow this session to proceed.
                //
                // Note: Must not have a TOCTOU race condition here
                let (await_for_drop_tx, await_for_drop_rx) =
                    citadel_io::tokio::sync::oneshot::channel();
                if sess
                    .drop_listener
                    .atomic_set_if_none(await_for_drop_tx)
                    .is_some()
                {
                    citadel_logging::warn!(target: "citadel", "Session {cid} is already in the process of disconnecting, however, must yield to earlier connection attempt");
                    return false;
                }

                await_for_drop_rx
            } else {
                // No session exists, so we can proceed with the connection attempt
                return true;
            }
        };

        // Session exists, but, if it's in the process of disconnecting, we wait for it to disconnect by polling and/or waiting for the drop listener to be dropped
        let wait_for_drop = async move {
            citadel_logging::debug!(target: "citadel", "🔄 Session attempt for {cid} is awaiting for clean disconnection of prior connection");
            let _ = await_for_drop_rx.await;
        };

        // Timeout after 5s to ensure we don't wait indefinitely. We brute force disconnect the session if it doesn't disconnect within the timeout.
        let timeout = async move {
            citadel_io::tokio::time::sleep(Duration::from_secs(5)).await;
        };

        // Wait for the session to disconnect or timeout
        citadel_io::tokio::select! {
            _ = wait_for_drop => true,
            _ = timeout => {
                citadel_logging::warn!(target: "citadel", "Session attempt for {cid} failed to disconnect within the timeout. Force clearing");
                let mut this = inner_mut!(self);
                this.sessions.remove(&cid);
                this.provisional_connections.retain(|_, sess| sess.2.session_cid.get().unwrap_or(0) != cid);
                true
            },
        }
    }

    /// Called by the higher-level [CitadelNode] async writer loop
    /// `nid_local` is only needed in case a provisional id is needed.
    /// This is initiated by the local HyperNode's request to connect to an external server
    /// `proposed_credentials`: Must be Some if session_cid is None!
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_connection(
        &self,
        local_node_type: NodeType,
        local_nat_type: NatType,
        init_mode: HdpSessionInitMode,
        ticket: Ticket,
        connect_mode: Option<ConnectMode>,
        listener_underlying_proto: ServerUnderlyingProtocol,
        udp_mode: Option<UdpMode>,
        keep_alive_timeout_ns: Option<i64>,
        security_settings: SessionSecuritySettings,
        default_client_config: &Arc<ClientConfig>,
        session_password: PreSharedKey,
    ) -> Result<impl FutureRequirements<Output = Result<(), NetworkError>>, NetworkError> {
        let (session_manager, new_session, peer_addr, primary_stream) = {
            let session_manager_clone = self.clone();

            let (
                remote,
                primary_stream,
                local_bind_addr,
                kernel_tx,
                account_manager,
                tt,
                on_drop,
                peer_addr,
                cnac,
                peer_only_connect_mode,
                proposed_credentials,
                peer_layer,
                stun_servers,
            ) = {
                let (
                    remote,
                    kernel_tx,
                    account_manager,
                    tt,
                    on_drop,
                    peer_addr,
                    cnac,
                    proposed_credentials,
                    peer_layer,
                    stun_servers,
                ) = {
                    let (peer_addr, cnac, proposed_credentials) = {
                        match &init_mode {
                            HdpSessionInitMode::Register(peer_addr, proposed_credentials) => {
                                (*peer_addr, None, proposed_credentials.clone())
                            }

                            HdpSessionInitMode::Connect(auth_request) => match auth_request {
                                AuthenticationRequest::Passwordless {
                                    server_addr,
                                    username,
                                } => (
                                    *server_addr,
                                    None,
                                    ProposedCredentials::transient(username.clone()),
                                ),

                                AuthenticationRequest::Credentialed { id, password } => {
                                    let acc_mgr = {
                                        let inner = inner!(self);
                                        inner.account_manager.clone()
                                    };

                                    let cnac = id.search(&acc_mgr).await?.ok_or(
                                        NetworkError::InternalError("Client does not exist"),
                                    )?;
                                    let conn_info = cnac.get_connect_info();
                                    let peer_addr = conn_info.addr;

                                    let proposed_credentials = cnac
                                        .generate_connect_credentials(password.clone())
                                        .await
                                        .map_err(|err| NetworkError::Generic(err.into_string()))?;

                                    (peer_addr, Some(cnac), proposed_credentials)
                                }
                            },
                        }
                    };

                    let mut this = inner_mut!(self);
                    let on_drop = this.clean_shutdown_tracker_tx.clone();
                    let remote = this.server_remote.clone().unwrap();
                    let kernel_tx = this.kernel_tx.clone();
                    let account_manager = this.account_manager.clone();
                    let tt = this.time_tracker;
                    let peer_layer = this.hypernode_peer_layer.clone();
                    let stun_servers = this.stun_servers.clone();

                    if let Some((init_time, ..)) = this.provisional_connections.get(&peer_addr) {
                        // Localhost is already trying to connect. However, it's possible that the entry has expired,
                        // especially on IOS/droid where the background timer just stops completely
                        if init_time.elapsed() > DO_CONNECT_EXPIRE_TIME_MS {
                            // remove the entry, since it's expired anyways
                            let _ = this.provisional_connections.remove(&peer_addr);
                        } else {
                            return Err(NetworkError::Generic(format!(
                                "Localhost is already trying to connect to {peer_addr}"
                            )));
                        }
                    }

                    (
                        remote,
                        kernel_tx,
                        account_manager,
                        tt,
                        on_drop,
                        peer_addr,
                        cnac,
                        proposed_credentials,
                        peer_layer,
                        stun_servers,
                    )
                };

                let peer_only_connect_mode =
                    ConnectProtocol::Quic(listener_underlying_proto.maybe_get_identity());

                // create conn to peer
                let primary_stream = CitadelNode::<R>::create_session_transport_init(
                    peer_addr,
                    default_client_config,
                )
                .await
                .map_err(|err| NetworkError::SocketError(err.to_string()))?;
                let local_bind_addr = primary_stream
                    .local_addr()
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
                (
                    remote,
                    primary_stream,
                    local_bind_addr,
                    kernel_tx,
                    account_manager,
                    tt,
                    on_drop,
                    peer_addr,
                    cnac,
                    peer_only_connect_mode,
                    proposed_credentials,
                    peer_layer,
                    stun_servers,
                )
            };

            //let peer_only_connect_mode = match listener_underlying_proto { UnderlyingProtocol::Tcp => ConnectProtocol::Tcp, UnderlyingProtocol::Tls(_, domain) => ConnectProtocol::Tls(domain) };
            let client_only_settings = ClientOnlySessionInitSettings {
                init_mode,
                connect_mode,
                cnac,
                proposed_credentials,
                udp_mode: udp_mode.unwrap_or_default(),
                keep_alive_timeout_ns: keep_alive_timeout_ns.unwrap_or(KEEP_ALIVE_TIMEOUT_NS),
                security_settings,
                peer_only_connect_proto: peer_only_connect_mode,
            };

            let init_time = Instant::now();

            let session_init_params = SessionInitParams {
                local_nat_type,
                remote_peer: peer_addr,
                on_drop,
                citadel_remote: remote,
                local_bind_addr,
                local_node_type,
                kernel_tx,
                session_manager: session_manager_clone.clone(),
                account_manager,
                time_tracker: tt,
                init_ticket: ticket,
                client_config: default_client_config.clone(),
                hypernode_peer_layer: peer_layer,
                client_only_settings: Some(client_only_settings),
                stun_servers,
                init_time,
                session_password,
                server_only_session_init_settings: None,
            };

            let (stopper, new_session) = CitadelSession::new(session_init_params)?;

            if let Some((_prev_conn_init_time, _stopper, lingering_session)) = inner_mut!(self)
                .provisional_connections
                .insert(peer_addr, (init_time, stopper, new_session.clone()))
            {
                // If the previous connection was not dropped, then we need to drop it
                log::warn!(target: "citadel", "Found a previous lingering connection to {peer_addr}. Dropping it ...");
                lingering_session.shutdown();
            }

            (
                session_manager_clone,
                new_session,
                peer_addr,
                primary_stream,
            )
        };

        Ok(Box::pin(Self::execute_session_with_safe_shutdown(
            session_manager,
            new_session,
            peer_addr,
            primary_stream,
        )))
    }

    /// Ensures that the session is removed even if there is a technical error in the underlying stream
    /// TODO: Make this code less hacky, and make the removal process cleaner. Use RAII on HdpSessionInner?
    #[cfg_attr(feature = "localhost-testing", tracing::instrument(
        level = "trace",
        target = "citadel",
        skip_all,
        ret,
        err,
        fields(session_cid=new_session.session_cid.get(), is_server=new_session.is_server, peer_addr=peer_addr.to_string()
        )
    ))]
    async fn execute_session_with_safe_shutdown(
        session_manager: CitadelSessionManager<R>,
        new_session: CitadelSession<R>,
        peer_addr: SocketAddr,
        tcp_stream: GenericNetworkStream,
    ) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "Beginning pre-execution of session");
        let mut err = None;
        let init_time = new_session.init_time;
        let res = new_session.execute(tcp_stream, peer_addr).await;
        new_session.state.set(SessionState::Disconnecting);

        match &res {
            Ok(cid_opt) | Err((_, cid_opt)) => {
                if let Some(cid) = *cid_opt {
                    //log::trace!(target: "citadel", "[safe] Deleting full connection from CID {} (IP: {})", cid, &peer_addr);
                    session_manager.clear_session(cid, init_time);
                    session_manager.clear_provisional_session(&peer_addr, init_time);
                } else {
                    //log::trace!(target: "citadel", "[safe] deleting provisional connection to {}", &peer_addr);
                    session_manager.clear_provisional_session(&peer_addr, init_time);
                }
            }
        }

        if let Err(err_inner) = res {
            err = Some(err_inner.0);
        }

        let sess_mgr = inner!(session_manager);
        // the final step is to take all virtual conns inside the session, and remove them from other sessions
        let sess = new_session;

        let pers = sess.account_manager.get_persistence_handler().clone();
        let peer_layer = sess_mgr.hypernode_peer_layer.clone();
        let mut state_container = inner_mut_state!(sess.state_container);

        if let Some(cnac) = state_container.cnac.as_ref() {
            // we do not need to save here. When the ratchet is reloaded, it will be zeroed out anyways.
            // the only reason we call this is to ensure that FCM packets that get protected on their way out
            // don't cause false-positives on the anti-replay-attack container
            // Especially needed for FCM
            // The only time the static HR won't get refreshed if a lingering connection gets cleaned-up
            if sess.do_static_hr_refresh_atexit.get() {
                let _ = cnac.refresh_static_ratchet();
            }

            if cnac.is_transient() {
                // delete
                let cid = cnac.get_cid();
                let task = async move { pers.delete_cnac_by_cid(cid).await };
                spawn!(task);
                log::trace!(target: "citadel", "Deleting passwordless CNAC ...");
            }
        }

        // the following shutdown sequence is valid for only for the HyperLAN server
        // This final sequence alerts all CIDs in the network
        if sess.is_server {
            // if the account was newly registered, it is possible that session_cid is none
            // if this is the case, ignore safe-shutdown of the session since no possible vconns
            // exist
            if let Some(session_cid) = sess.session_cid.get() {
                let task = async move { peer_layer.on_session_shutdown(session_cid).await };

                spawn!(task);

                let timestamp = sess.time_tracker.get_global_time_ns();
                let security_level = state_container
                    .session_security_settings
                    .map(|r| r.security_level)
                    .unwrap_or(SecurityLevel::Standard);

                state_container.active_virtual_connections.drain().for_each(|(peer_id, vconn)| {
                    let peer_cid = peer_id;
                    // toggling this off ensures that any higher-level channels are disabled
                    vconn.is_active.store(false, Ordering::SeqCst);
                    if peer_cid != session_cid && peer_cid != 0 {
                        let vconn = vconn.connection_type;
                        if let VirtualConnectionType::LocalGroupPeer { session_cid: _, peer_cid: _ } = vconn {
                            if peer_cid != session_cid {
                                log::trace!(target: "citadel", "Alerting {peer_cid} that {session_cid} disconnected");
                                let peer_conn_type = PeerConnectionType::LocalGroupPeer {
                                    session_cid,
                                    peer_cid,
                                };
                                let signal = PeerSignal::Disconnect {
                                    peer_conn_type,
                                    disconnect_response: Some(PeerResponse::Disconnected(format!("{peer_cid} disconnected from {session_cid} forcibly"))),
                                };
                                if let Err(_err) = sess_mgr.send_signal_to_peer_direct(peer_cid, |peer_ratchet| {
                                    super::packet_crafter::peer_cmd::craft_peer_signal(peer_ratchet, signal, Ticket(0), timestamp, security_level)
                                }) {
                                    //log::error!(target: "citadel", "Unable to send shutdown signal to {}: {:?}", peer_cid, err);
                                }

                                if let Some(peer_sess) = sess_mgr.sessions.get(&peer_cid) {
                                    let peer_sess = &peer_sess.1;
                                    let mut peer_state_container = inner_mut_state!(peer_sess.state_container);
                                    if peer_state_container.active_virtual_connections.remove(&session_cid).is_none() {
                                        log::warn!(target: "citadel", "While dropping session {session_cid}, attempted to remove vConn to {peer_cid}, but peer did not have the vConn listed. Report to developers");
                                    }
                                }
                            }
                        }
                    }
                });
            }
        } else {
            // if we are ending a client session, we just need to ensure that the P2P streams go-down
            log::trace!(target: "citadel", "Ending any active P2P connections");
            //sess.queue_worker.signal_shutdown();
            state_container.end_connections();
        }

        sess.drop_listener.set(None);

        if let Some(err) = err {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// This future should be joined up higher at the [node] layer
    pub async fn run_peer_container(
        citadel_session_manager: CitadelSessionManager<R>,
    ) -> Result<(), NetworkError> {
        let peer_container = { inner!(citadel_session_manager).hypernode_peer_layer.clone() };
        peer_container.create_executor().await.await
    }

    /// When the primary port listener receives a new connection, the stream gets sent here for handling
    #[allow(unused_results)]
    pub fn process_new_inbound_connection(
        &self,
        local_bind_addr: SocketAddr,
        local_nat_type: NatType,
        peer_addr: SocketAddr,
        primary_stream: GenericNetworkStream,
        server_only_session_init_settings: ServerOnlySessionInitSettings,
    ) -> Result<impl FutureRequirements<Output = Result<(), NetworkError>>, NetworkError> {
        let this_dc = self.clone();
        let mut this = inner_mut!(self);
        let on_drop = this.clean_shutdown_tracker_tx.clone();
        let remote = this.server_remote.clone().unwrap();
        let client_config = this.client_config.clone();
        let peer_layer = this.hypernode_peer_layer.clone();
        let stun_servers = this.stun_servers.clone();

        // Regardless if the IpAddr existed as a client before, we must treat the connection temporarily as provisional
        // However, two concurrent provisional connections from the same IP cannot be connecting at once
        let local_node_type = this.local_node_type;
        let provisional_ticket = Ticket(this.incoming_cxn_count as _);
        this.incoming_cxn_count += 1;

        let init_time = Instant::now();

        let session_init_params = SessionInitParams {
            on_drop,
            local_nat_type,
            citadel_remote: remote,
            local_bind_addr,
            local_node_type,
            kernel_tx: this.kernel_tx.clone(),
            session_manager: self.clone(),
            account_manager: this.account_manager.clone(),
            time_tracker: this.time_tracker,
            remote_peer: peer_addr,
            init_ticket: provisional_ticket,
            client_config,
            hypernode_peer_layer: peer_layer,
            client_only_settings: None,
            stun_servers,
            init_time,
            session_password: server_only_session_init_settings
                .declared_pre_shared_key
                .clone()
                .unwrap_or_default(),
            server_only_session_init_settings: Some(server_only_session_init_settings),
        };

        let (stopper, new_session) = CitadelSession::new(session_init_params)?;
        this.provisional_connections
            .insert(peer_addr, (init_time, stopper, new_session.clone()));
        drop(this);

        let session = Self::execute_session_with_safe_shutdown(
            this_dc,
            new_session,
            peer_addr,
            primary_stream,
        );

        Ok(session)
    }

    /// dispatches an outbound command
    pub fn process_outbound_broadcast_command(
        &self,
        ticket: Ticket,
        session_cid: u64,
        command: GroupBroadcast,
    ) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(existing_session) = this.sessions.get(&session_cid) {
            inner_mut_state!(existing_session.1.state_container)
                .process_outbound_broadcast_command(ticket, &command)
        } else {
            Err(NetworkError::Generic(format!("Hypernode session for {session_cid} does not exist! Not going to handle group broadcast signal {command:?} ...")))
        }
    }

    /// When the [CitadelNode] receives an outbound request, the request flows here. It returns where the packet must be sent to
    #[allow(clippy::too_many_arguments)]
    pub fn process_outbound_file(
        &self,
        ticket: Ticket,
        max_group_size: Option<usize>,
        source: Box<dyn ObjectSource>,
        session_cid: u64,
        virtual_target: VirtualTargetType,
        security_level: SecurityLevel,
        transfer_type: TransferType,
    ) -> Result<(), NetworkError> {
        let this = inner!(self);

        let local_encryption_level = None;

        if let Some(existing_session) = this.sessions.get(&session_cid) {
            existing_session.1.process_outbound_file(
                ticket,
                max_group_size,
                source,
                virtual_target,
                security_level,
                transfer_type,
                local_encryption_level,
                None,
                |_| {},
            )
        } else {
            Err(NetworkError::Generic(format!(
                "Hypernode session for {session_cid} does not exist! Not going to send data ..."
            )))
        }
    }

    pub fn revfs_pull(
        &self,
        ticket: Ticket,
        session_cid: u64,
        v_conn: VirtualConnectionType,
        virtual_path: PathBuf,
        delete_on_pull: bool,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        let lock = inner!(self);
        if let Some((_, sess)) = lock.sessions.get(&session_cid) {
            sess.revfs_pull(ticket, v_conn, virtual_path, delete_on_pull, security_level)
        } else {
            Err(NetworkError::Generic(format!(
                "Hypernode session for {session_cid} does not exist! Not going to process request ..."
            )))
        }
    }

    pub fn revfs_delete(
        &self,
        ticket: Ticket,
        session_cid: u64,
        v_conn: VirtualConnectionType,
        virtual_path: PathBuf,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        let lock = inner!(self);
        if let Some((_, sess)) = lock.sessions.get(&session_cid) {
            sess.revfs_delete(ticket, v_conn, virtual_path, security_level)
        } else {
            Err(NetworkError::Generic(format!(
                "Hypernode session for {session_cid} does not exist! Not going to process request ..."
            )))
        }
    }

    /// Returns true if the process continued successfully
    pub fn initiate_update_entropy_bank_subroutine(
        &self,
        virtual_target: VirtualTargetType,
        ticket: Ticket,
    ) -> Result<(), NetworkError> {
        let session_cid = virtual_target.get_session_cid();
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&session_cid) {
            let sess = &sess.1;
            let mut state_container = inner_mut_state!(sess.state_container);
            state_container.initiate_rekey(virtual_target, Some(ticket))
        } else {
            Err(NetworkError::Generic(format!(
                "Unable to initiate entropy_bank update subroutine for {session_cid} (not an active session)"
            )))
        }
    }

    /// Returns true if the process initiated successfully
    pub fn initiate_deregistration_subroutine(
        &self,
        session_cid: u64,
        connection_type: VirtualConnectionType,
        ticket: Ticket,
    ) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&session_cid) {
            let sess = &sess.1;
            sess.initiate_deregister(connection_type, ticket)
        } else {
            Err(NetworkError::Generic(format!(
                "Unable to initiate deregister subroutine for {session_cid} (not an active session)"
            )))
        }
    }

    pub fn check_online_status(&self, users: &[u64]) -> Vec<bool> {
        let this = inner!(self);
        users
            .iter()
            .map(|user| this.sessions.contains_key(user))
            .collect()
    }

    /// Sends the command outbound. Returns true if sent, false otherwise
    /// In the case that this return false, further interaction should be avoided
    pub async fn dispatch_peer_command(
        &self,
        session_cid: u64,
        ticket: Ticket,
        peer_command: PeerSignal,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        let sess = {
            let this = inner!(self);
            if let Some(sess) = this.sessions.get(&session_cid) {
                sess.1.clone()
            } else {
                return Err(NetworkError::msg(format!("Session for {session_cid} not found in session manager. Failed to dispatch peer command {peer_command:?}")));
            }
        };

        sess.dispatch_peer_command(ticket, peer_command, security_level)
            .await
    }

    /// Returns a list of active sessions
    pub fn get_active_sessions(&self) -> Vec<u64> {
        let this = inner!(self);
        this.sessions.keys().copied().collect()
    }

    /// This upgrades a provisional connection to a full connection. Returns true if the upgrade
    /// succeeded, false otherwise
    /// Adds the internal queues to the hypernode_peer_layer. This function thus MUST be called during the
    /// DO_CONNECT stage
    /// This will return false if the provisional connection was already removed. This can happen to really
    /// slow connections, or during background execution on android/ios
    pub fn upgrade_connection(&self, socket_addr: SocketAddr, session_cid: u64) -> bool {
        let mut this = inner_mut!(self);
        if let Some((_, stopper, session)) = this.provisional_connections.remove(&socket_addr) {
            //let _ = this.hypernode_peer_layer.register_peer(session_cid, true);
            if let Some(lingering_conn) = this.sessions.insert(session_cid, (stopper, session)) {
                // sometimes (especially on cellular networks), when the network changes due to
                // changing cell towers (or between WIFI/Cellular modes), the session lingers
                // without cleaning itself up. It will automatically drop by itself, however,
                // sometimes when the client attempts to re-connect, the old session will still
                // be in place, and hence removing the old session when attempting to upgrade
                // from a provisional to a protected connection must be allowed. As such, issue a warning here,
                // then return true to allow the new connection to proceed instead of returning false
                // due to overlapping connection
                log::warn!(target: "citadel", "Cleaned up lingering session for {session_cid}");
                let prev_conn = &lingering_conn.1;
                prev_conn.do_static_hr_refresh_atexit.set(false);
            }

            true
        } else {
            false
        }
    }

    /// Returns true if the disconnect was a success, false if not. An error returns if something else occurs
    pub fn initiate_disconnect(
        &self,
        session_cid: u64,
        ticket: Ticket,
    ) -> Result<bool, NetworkError> {
        let this = inner!(self);
        let res = match this.sessions.get(&session_cid) {
            Some(session) => session.1.initiate_disconnect(ticket),
            None => Ok(false),
        };

        let will_perform_dc = res?;

        if !will_perform_dc {
            // Already disconnected. Send a message to the kernel
            this.kernel_tx
                .unbounded_send(NodeResult::Disconnect(Disconnect {
                    ticket,
                    cid_opt: Some(session_cid),
                    success: true,
                    v_conn_type: Some(VirtualConnectionType::LocalGroupServer { session_cid }),
                    message: "Already disconnected".to_string(),
                }))?;
        }

        Ok(will_perform_dc)
    }

    /// Clears a session from the internal map
    pub fn clear_session(&self, cid: u64, init_time: Instant) {
        let mut this = inner_mut!(self);
        this.clear_session(cid, init_time);
    }

    /// When the registration process completes, and before sending the kernel a message, this should be called on BOTH ends
    pub fn clear_provisional_session(&self, addr: &SocketAddr, init_time: Instant) {
        log::trace!(target: "citadel", "Attempting to clear provisional session ...");
        let mut this = inner_mut!(self);
        if let Some((prev_init_time, _, _)) = this.provisional_connections.get(addr) {
            if *prev_init_time == init_time {
                this.provisional_connections.remove(addr);
            } else {
                log::warn!(target: "citadel", "Attempted to remove a connection {addr:?} that was provisional yet for a different process");
            }
        }
    }

    /// Creates a new message group. Returns a key if successful
    pub async fn create_message_group_and_notify(
        &self,
        timestamp: i64,
        ticket: Ticket,
        session_cid: u64,
        peers_to_notify: Vec<u64>,
        security_level: SecurityLevel,
        options: MessageGroupOptions,
    ) -> Option<MessageGroupKey> {
        let peer_layer = { inner!(self).hypernode_peer_layer.clone() };

        let key = peer_layer
            .create_new_message_group(session_cid, &peers_to_notify, options)
            .await?;
        // notify all the peers
        for peer_cid in peers_to_notify {
            let this = inner!(self);
            if let Err(err) = this.send_signal_to_peer_direct(peer_cid, |peer_ratchet| {
                let signal = GroupBroadcast::Invitation {
                    sender: session_cid,
                    key,
                };
                super::packet_crafter::peer_cmd::craft_group_message_packet(
                    peer_ratchet,
                    &signal,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                )
            }) {
                log::warn!(target: "citadel", "Unable to send signal to peer {peer_cid}: {err}");
            }
        }

        Some(key)
    }

    /// Returns true if the removal was a success
    pub async fn remove_message_group(
        &self,
        cid_host: u64,
        timestamp: i64,
        ticket: Ticket,
        key: MessageGroupKey,
        security_level: SecurityLevel,
    ) -> bool {
        let peer_layer = { inner!(self).hypernode_peer_layer.clone() };

        if let Some(group) = peer_layer.remove_message_group(key).await {
            let this = inner!(self);
            for peer_cid in group.concurrent_peers.keys() {
                if *peer_cid != cid_host {
                    if let Err(err) = this.send_signal_to_peer_direct(*peer_cid, |peer_ratchet| {
                        let signal = GroupBroadcast::Disconnected { key };
                        super::packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_ratchet,
                            &signal,
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    }) {
                        log::warn!(target: "citadel", "Unable to send d/c signal to peer {peer_cid}: {err}");
                    }
                }
            }

            true
        } else {
            false
        }
    }

    /// Removes the supplied peers from the group. Each peer that is successfully removed will receive a group disconnect signal
    /// This will additionally alert each remaining member
    #[allow(clippy::too_many_arguments)]
    pub async fn kick_from_message_group(
        &self,
        mode: GroupMemberAlterMode,
        session_cid: u64,
        timestamp: i64,
        ticket: Ticket,
        key: MessageGroupKey,
        peers: Vec<u64>,
        security_level: SecurityLevel,
    ) -> Result<bool, NetworkError> {
        let peer_layer = { inner!(self).hypernode_peer_layer.clone() };

        let mut to_broadcast_dc = vec![];
        let mut to_broadcast_left = vec![];
        let dc_signal = GroupBroadcast::Disconnected { key };

        let left_signal = match peer_layer.remove_peers_from_message_group(key, peers).await {
            Ok((peers_removed, peers_remaining)) => {
                log::trace!(target: "citadel", "Peers removed: {:?}", &peers_removed);
                // We only notify the members when kicking, not leaving
                if mode == GroupMemberAlterMode::Kick {
                    // notify all the peers removed
                    for peer in &peers_removed {
                        if *peer != session_cid {
                            to_broadcast_dc.push(*peer);
                        }
                    }
                }

                for peer in peers_remaining {
                    if peer != session_cid {
                        to_broadcast_left.push(peer);
                    }
                }

                GroupBroadcast::MemberStateChanged {
                    key,
                    state: MemberState::LeftGroup {
                        cids: peers_removed,
                    },
                }
            }

            Err(_) => {
                log::error!(target: "citadel", "Unable to kick peers from message group");
                return Ok(false);
            }
        };

        // if we get here, dispatch any messages
        let len = to_broadcast_dc.len();
        let peers_and_statuses_dc = to_broadcast_dc
            .into_iter()
            .zip(std::iter::repeat_n(true, len));
        let _ = self
            .send_group_broadcast_signal_to(
                timestamp,
                ticket,
                peers_and_statuses_dc,
                true,
                dc_signal,
                security_level,
            )
            .await
            .map_err(NetworkError::Generic)?;

        let len = to_broadcast_left.len();
        let peers_and_statuses_left = to_broadcast_left
            .into_iter()
            .zip(std::iter::repeat_n(true, len));
        let _ = self
            .send_group_broadcast_signal_to(
                timestamp,
                ticket,
                peers_and_statuses_left,
                true,
                left_signal,
                security_level,
            )
            .await
            .map_err(NetworkError::Generic)?;

        Ok(true)
    }

    /// Broadcasts a message to a target group
    /// Note: uses mail_if_offline: true. This allows a member to disconnect, but to still receive messages later-on
    pub async fn broadcast_signal_to_group(
        &self,
        session_cid: u64,
        timestamp: i64,
        ticket: Ticket,
        key: MessageGroupKey,
        signal: GroupBroadcast,
        security_level: SecurityLevel,
    ) -> Result<bool, String> {
        let peer_layer = { inner!(self).hypernode_peer_layer.clone() };

        if let Some(peers_to_broadcast_to) = peer_layer.get_peers_in_message_group(key).await {
            let broadcastees = peers_to_broadcast_to
                .iter()
                .filter(|peer| **peer != session_cid)
                .map(|r| (*r, true));
            log::trace!(target: "citadel", "[Server/Group] peers_and_statuses: {broadcastees:?}");
            let (_success, failed) = self
                .send_group_broadcast_signal_to(
                    timestamp,
                    ticket,
                    broadcastees,
                    true,
                    signal,
                    security_level,
                )
                .await?;
            Ok(failed.is_empty())
        } else {
            Ok(false)
        }
    }

    /// sends a signal to the peer using the correct PQC and Drill cryptosystem
    /// NOTE: THIS WILL PANIC if `target_cid` == the implicated cid from the closure that calls this
    pub fn send_signal_to_peer(
        &self,
        target_cid: u64,
        ticket: Ticket,
        signal: PeerSignal,
        timestamp: i64,
        security_level: SecurityLevel,
    ) -> bool {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&target_cid) {
            let sess = &sess.1;
            if let Some(to_primary_stream) = sess.to_primary_stream.as_ref() {
                let accessor = EndpointCryptoAccessor::C2S(sess.state_container.clone());
                return accessor
                    .borrow_hr(None, |hr, _| {
                        let packet = super::packet_crafter::peer_cmd::craft_peer_signal(
                            hr,
                            signal,
                            ticket,
                            timestamp,
                            security_level,
                        );
                        to_primary_stream
                            .unbounded_send(packet)
                            .map_err(|err| err.to_string())
                    })
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
            }
        }

        false
    }

    /// Ensures the mailbox and tracked event queue are loaded into the [PeerLayer]
    pub async fn register_session_with_peer_layer(
        &self,
        session_cid: u64,
    ) -> Result<Option<MailboxTransfer>, NetworkError> {
        let peer_layer = { inner!(self).hypernode_peer_layer.clone() };

        peer_layer.register_peer(session_cid).await
    }

    /// Removes a virtual connection `session_cid` from `peer_cid`
    pub fn disconnect_virtual_conn(
        &self,
        session_cid: u64,
        peer_cid: u64,
        on_internal_disconnect: impl FnOnce(&R) -> BytesMut,
    ) -> Result<(), String> {
        if session_cid == peer_cid {
            return Err("Implicated CID cannot equal peer cid".to_string());
        }

        let this = inner!(self);
        if let Some(peer_sess) = this.sessions.get(&peer_cid) {
            let sess = &peer_sess.1;
            let to_primary = sess.to_primary_stream.as_ref().unwrap();

            let accessor = EndpointCryptoAccessor::C2S(sess.state_container.clone());
            accessor
                .borrow_hr(None, |hr, state_container| {
                    let removed = state_container
                        .active_virtual_connections
                        .remove(&session_cid);
                    if removed.is_some() {
                        let packet = on_internal_disconnect(hr);
                        to_primary
                            .unbounded_send(packet)
                            .map_err(|err| err.to_string())
                    } else {
                        Ok(())
                    }
                })
                .map_err(|err| err.into_string())?
        } else {
            Ok(())
        }
    }

    pub fn route_packet_to(
        &self,
        target_cid: u64,
        packet: impl FnOnce(&R) -> BytesMut,
    ) -> Result<(), String> {
        let lock = inner!(self);
        let (_, sess_ref) = lock
            .sessions
            .get(&target_cid)
            .ok_or_else(|| format!("Target cid {target_cid} does not exist (route err)"))?;
        let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
        let accessor = EndpointCryptoAccessor::C2S(sess_ref.state_container.clone());
        accessor.borrow_hr(None, |hr, _| {
            log::trace!(target: "citadel", "Routing packet through primary stream -> {target_cid}");
            let packet = packet(hr);
            peer_sender.unbounded_send(packet).map_err(|err| err.to_string())
        }).map_err(|err| err.into_string())?
    }

    /// Stores the `signal` inside the internal timed-queue for `session_cid`, and then sends `packet` to `target_cid`.
    /// After `timeout`, the closure `on_timeout` is executed
    #[allow(clippy::too_many_arguments)]
    pub async fn route_signal_primary(
        &self,
        peer_layer: &mut CitadelNodePeerLayerInner<R>,
        session_cid: u64,
        target_cid: u64,
        ticket: Ticket,
        signal: PeerSignal,
        packet: impl FnOnce(&R) -> BytesMut,
        timeout: Duration,
        on_timeout: impl Fn(PeerSignal) + SyncContextRequirements,
    ) -> Result<(), String> {
        if session_cid == target_cid {
            return Err("Target CID cannot be equal to the implicated CID".to_string());
        }

        let (account_manager, peer_sess) = {
            let this = inner!(self);
            (
                this.account_manager.clone(),
                this.sessions.get(&target_cid).map(|r| r.1.clone()),
            )
        };

        log::trace!(target: "citadel", "Checking if {target_cid} is registered locally ... {signal:?}");
        if account_manager
            .hyperlan_cid_is_registered(target_cid)
            .await
            .map_err(|err| err.into_string())?
        {
            let pers = account_manager.get_persistence_handler().clone();

            // get the target cid's session
            if let Some(ref sess_ref) = peer_sess {
                peer_layer
                    .insert_tracked_posting(session_cid, timeout, ticket, signal, on_timeout)
                    .await;
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let accessor = EndpointCryptoAccessor::C2S(sess_ref.state_container.clone());

                accessor.borrow_hr(None, |hr, _| {
                    log::trace!(target: "citadel", "Routing packet through primary stream ({session_cid} -> {target_cid})");
                    let packet = packet(hr);
                    peer_sender.unbounded_send(packet).map_err(|err| err.to_string())
                }).map_err(|err| err.into_string())?
            } else {
                // session is not active, but user is registered (thus offline). Setup return ticket tracker on session_cid
                // and deliver to the mailbox of target_cid, that way target_cid receives mail on connect. TODO: external svc route, if available
                {
                    peer_layer
                        .insert_tracked_posting(
                            session_cid,
                            timeout,
                            ticket,
                            signal.clone(),
                            on_timeout,
                        )
                        .await;
                }
                CitadelNodePeerLayer::try_add_mailbox(&pers, target_cid, signal)
                    .await
                    .map_err(|err| err.into_string())
            }
        } else {
            Err(format!("CID {target_cid} is not registered locally"))
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), NetworkError> {
        let (mut recv, len) = {
            let mut inner = inner_mut!(self);
            if let Some(recv) = inner.clean_shutdown_tracker.take() {
                let len = inner.sessions.len();
                for sender in inner.sessions.values().map(|r| &r.0) {
                    let _ = sender.send(());
                }
                (recv, len)
            } else {
                return Err(NetworkError::InternalError(
                    "UnboundedReceiver not loaded in session manager",
                ));
            }
        };

        for _ in 0..len {
            recv.recv().await.ok_or(NetworkError::InternalError(
                "Unable to receive shutdown signal",
            ))?;
        }

        log::trace!(target: "citadel", "All sessions dropped");
        Ok(())
    }

    /// Sends a [GroupBroadcast] message to `peer_cid`. Ensures the target is mutual before sending
    /// `mail_if_offline`: Deposits mail if the target is offline
    /// NOTE: it is the duty of the calling closure to ensure that the [MessageGroup] exists!
    /// NOTE: This does not check to see if the two peers can send to each other. That is up to the caller to ensure that
    pub async fn send_group_broadcast_signal_to(
        &self,
        timestamp: i64,
        ticket: Ticket,
        peers_and_statuses: impl Iterator<Item = (u64, bool)>,
        mail_if_offline: bool,
        signal: GroupBroadcast,
        security_level: SecurityLevel,
    ) -> Result<(Vec<u64>, Vec<u64>), String> {
        let mut peers_failed = Vec::new();
        let mut peers_okay = Vec::new();
        let mut to_mail = Vec::new();

        let pers = {
            let this = inner!(self);
            for (peer, is_registered) in peers_and_statuses {
                if is_registered {
                    if this
                        .send_signal_to_peer_direct(peer, |peer_ratchet| {
                            super::packet_crafter::peer_cmd::craft_group_message_packet(
                                peer_ratchet,
                                &signal,
                                ticket,
                                C2S_IDENTITY_CID,
                                timestamp,
                                security_level,
                            )
                        })
                        .is_err()
                    {
                        // on error, try adding to mailbox
                        if mail_if_offline {
                            to_mail.push(peer);
                        }
                    } else {
                        // okay
                        peers_okay.push(peer);
                    }
                } else {
                    peers_failed.push(peer);
                }
            }

            this.account_manager.get_persistence_handler().clone()
        };

        // TODO: optimize this into a single operation
        for peer in to_mail {
            CitadelNodePeerLayer::try_add_mailbox(
                &pers,
                peer,
                PeerSignal::BroadcastConnected {
                    session_cid: peer,
                    group_broadcast: signal.clone(),
                },
            )
            .await
            .map_err(|err| err.into_string())?;
            peers_okay.push(peer);
        }

        Ok((peers_okay, peers_failed))
    }

    /// NOTE: The order flips in the response.
    /// Further, the PeerResponse changes state: it becomes Some() instead of None upon reply
    /// Returns the target_cid's Session to handle updates on the internal state as necessary
    /// Also returns the [TrackedPosting] that was posted when the signal initially crossed through
    /// the HyperLAN Server
    #[inline]
    pub async fn route_signal_response_primary(
        &self,
        session_cid: u64,
        target_cid: u64,
        ticket: Ticket,
        session: &CitadelSession<R>,
        packet: impl FnOnce(&R) -> BytesMut,
        post_send: impl FnOnce(
            &CitadelSession<R>,
            PeerSignal,
        ) -> Result<PrimaryProcessorResult, NetworkError>,
    ) -> Result<Result<PrimaryProcessorResult, NetworkError>, String> {
        // Instead of checking for registration, check the `session_cid`'s timed queue for a ticket corresponding to Ticket.
        let tracked_posting = {
            session
                .hypernode_peer_layer
                .inner
                .write()
                .await
                .remove_tracked_posting_inner(target_cid, ticket)
        };
        if let Some(tracked_posting) = tracked_posting {
            // since the posting was valid, we just need to forward the signal to `session_cid`
            let this = inner!(self);
            if let Some(target_sess) = this.sessions.get(&target_cid) {
                //let ret = target_sess.clone();

                let sess_ref = &target_sess.1;
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let accessor = EndpointCryptoAccessor::C2S(sess_ref.state_container.clone());

                accessor
                    .borrow_hr(None, |hr, _| {
                        let packet = packet(hr);
                        peer_sender
                            .unbounded_send(packet)
                            .map_err(|err| err.to_string())
                    })
                    .map_err(|err| err.into_string())??;

                Ok((post_send)(sess_ref, tracked_posting))
            } else {
                // session no longer exists. Could have been that the `session_cid` responded too late. Send an error back, saying it expired
                Err(format!(
                    "Session for {target_cid} is not active, and thus no room for consent"
                ))
            }
        } else {
            // the tracked posting doesn't exist. It may have expired. In either case, the potential session is invalid
            Err(format!(
                "Tracked posting {ticket} for {target_cid} -> {session_cid} does not exist"
            ))
        }
    }
}

impl<R: Ratchet> HdpSessionManagerInner<R> {
    /// Clears a session from the SessionManager
    pub fn clear_session(&mut self, cid: u64, init_time: Instant) {
        if let Some((_, session)) = self.sessions.get(&cid) {
            if session.init_time == init_time {
                self.sessions.remove(&cid);
                log::info!(target: "citadel", "Session for {cid} cleared");
            } else {
                log::warn!(target: "citadel", "Attempted to remove a connection {cid:?} that was for a different process");
            }
        }
    }

    // for use by the server. This skips the whole ticket-tracking processes intermediate to the routing above
    pub fn send_signal_to_peer_direct(
        &self,
        target_cid: u64,
        packet: impl FnOnce(&R) -> BytesMut,
    ) -> Result<(), NetworkError> {
        if let Some(peer_sess) = self.sessions.get(&target_cid) {
            let peer_sess = &peer_sess.1;
            let peer_sender = peer_sess
                .to_primary_stream
                .as_ref()
                .ok_or(NetworkError::InternalError("Peer stream absent"))?;
            let accessor = EndpointCryptoAccessor::C2S(peer_sess.state_container.clone());

            accessor.borrow_hr(None, |hr, _| {
                let packet = packet(hr);
                peer_sender
                    .unbounded_send(packet)
                    .map_err(|err| NetworkError::msg(err.to_string()))
            })?
        } else {
            Err(NetworkError::Generic(format!(
                "unable to find peer sess {target_cid}"
            )))
        }
    }
}
