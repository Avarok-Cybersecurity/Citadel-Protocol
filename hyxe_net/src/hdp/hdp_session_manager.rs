use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use bytes::BytesMut;

use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::prelude::SecurityLevel;
use hyxe_wire::hypernode_type::NodeType;
use hyxe_wire::nat_identification::NatType;
use netbeam::time_tracker::TimeTracker;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::external_services::fcm::data_structures::RawExternalPacket;
use hyxe_user::external_services::fcm::fcm_instance::FCMInstance;
use hyxe_user::misc::AccountError;
use hyxe_user::prelude::ConnectProtocol;
use hyxe_user::auth::proposed_credentials::ProposedCredentials;

use crate::constants::{DO_CONNECT_EXPIRE_TIME_MS, KEEP_ALIVE_TIMEOUT_NS, UDP_MODE};
use crate::error::NetworkError;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::hdp::hdp_packet_processor::includes::{Duration, Instant};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::{GroupBroadcast, GroupMemberAlterMode, MemberState};
use crate::hdp::hdp_packet_processor::PrimaryProcessorResult;
use crate::hdp::hdp_node::{ConnectMode, HdpServer, NodeRemote, HdpServerResult, Ticket};
use crate::hdp::hdp_session::{HdpSession, HdpSessionInitMode};
use crate::hdp::misc::net::GenericNetworkStream;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::misc::underlying_proto::UnderlyingProtocol;
use crate::hdp::outbound_sender::{unbounded, UnboundedReceiver, UnboundedSender};
use tokio::sync::broadcast::Sender;
use crate::hdp::peer::message_group::MessageGroupKey;
use crate::hdp::peer::peer_layer::{HyperNodePeerLayer, MailboxTransfer, PeerConnectionType, PeerResponse, PeerSignal, UdpMode};
use crate::hdp::state_container::{VirtualConnectionType, VirtualTargetType};
use crate::kernel::RuntimeFuture;
use crate::macros::{ContextRequirements, SyncContextRequirements};
use crate::auth::AuthenticationRequest;
use hyxe_wire::exports::tokio_rustls::rustls::ClientConfig;
use std::sync::Arc;
use hyxe_wire::exports::tokio_rustls::rustls;

define_outer_struct_wrapper!(HdpSessionManager, HdpSessionManagerInner);

/// Used for handling stateful connections between two peer
pub struct HdpSessionManagerInner {
    local_node_type: NodeType,
    sessions: HashMap<u64, (Sender<()>, HdpSession)>,
    account_manager: AccountManager,
    pub(crate) hypernode_peer_layer: HyperNodePeerLayer,
    server_remote: Option<NodeRemote>,
    incoming_cxn_count: usize,
    /// Connections which have no implicated CID go herein. They are strictly expected to be
    /// in the state of NeedsRegister. Once they leave that state, they are eventually polled
    /// by the [HdpSessionManager] and thereafter placed inside an appropriate session
    provisional_connections: HashMap<SocketAddr, (Instant, Sender<()>, HdpSession)>,
    fcm_post_registrations: HashSet<FcmPeerRegisterTicket>,
    kernel_tx: UnboundedSender<HdpServerResult>,
    time_tracker: TimeTracker,
    clean_shutdown_tracker_tx: UnboundedSender<()>,
    clean_shutdown_tracker: Option<UnboundedReceiver<()>>,
    client_config: Arc<rustls::ClientConfig>
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
struct FcmPeerRegisterTicket {
    initiator: u64,
    receiver: u64
}

impl FcmPeerRegisterTicket {
    fn create_bidirectional(a: u64, b: u64) -> (Self, Self) {
        (FcmPeerRegisterTicket { initiator: a, receiver: b }, FcmPeerRegisterTicket { initiator: b, receiver: a })
    }
}

impl HdpSessionManager {
    /// Creates a new [SessionManager] which handles individual connections
    pub fn new(local_node_type: NodeType, kernel_tx: UnboundedSender<HdpServerResult>, account_manager: AccountManager, time_tracker: TimeTracker, client_config: Arc<rustls::ClientConfig>) -> Self {
        let incoming_cxn_count = 0;
        let (clean_shutdown_tracker_tx, clean_shutdown_tracker_rx) = unbounded();
        let inner = HdpSessionManagerInner {
            clean_shutdown_tracker_tx,
            clean_shutdown_tracker: Some(clean_shutdown_tracker_rx),
            fcm_post_registrations: Default::default(),
            hypernode_peer_layer: HyperNodePeerLayer::new(account_manager.get_persistence_handler().clone()),
            server_remote: None,
            local_node_type,
            sessions: HashMap::new(),
            incoming_cxn_count,
            account_manager,
            provisional_connections: HashMap::new(),
            kernel_tx,
            time_tracker,
            client_config
        };

        Self::from(inner)
    }

    /// Loads the server remote, and gets the time tracker for the calling [HdpServer]
    /// Used during the init stage
    pub(crate) fn load_server_remote_get_tt(&self, server_remote: NodeRemote) -> TimeTracker {
        let mut this = inner_mut!(self);
        this.server_remote = Some(server_remote);
        this.time_tracker.clone()
    }

    /// Determines if `cid` is connected
    pub fn session_active(&self, cid: u64) -> bool {
        let this = inner!(self);
        this.sessions.contains_key(&cid)
    }

    /// Obtains the HdpSession. Beware of locking!
    pub fn get_session_by_cid(&self, cid: u64) -> Option<HdpSession> {
        let this = inner!(self);
        this.sessions.get(&cid).map(|r| r.1.clone())
    }

    /// Called by the higher-level [HdpServer] async writer loop
    /// `nid_local` is only needed incase a provisional id is needed.
    ///
    /// This is initiated by the local HyperNode's request to connect to an external server
    /// `proposed_credentials`: Must be Some if implicated_cid is None!
    #[allow(unused_results)]
    pub async fn initiate_connection(&self, local_node_type: NodeType, local_nat_type: NatType, init_mode: HdpSessionInitMode, ticket: Ticket, connect_mode: Option<ConnectMode>, listener_underlying_proto: UnderlyingProtocol, fcm_keys: Option<FcmKeys>, udp_mode: Option<UdpMode>, keep_alive_timeout_ns: Option<i64>, security_settings: SessionSecuritySettings, default_client_config: &Arc<ClientConfig>) -> Result<Pin<Box<dyn RuntimeFuture>>, NetworkError> {
        let (session_manager, new_session, peer_addr, primary_stream) = {
            let session_manager_clone = self.clone();

            let (remote, primary_stream, local_bind_addr, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, peer_only_connect_mode, proposed_credentials, peer_layer) = {
                let (remote, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, proposed_credentials, peer_layer) = {
                    let (peer_addr, cnac, proposed_credentials) = {
                        match &init_mode {
                            HdpSessionInitMode::Register(peer_addr, proposed_credentials) => (*peer_addr, None, proposed_credentials.clone()),

                            HdpSessionInitMode::Connect(auth_request) => {
                                match auth_request {
                                    AuthenticationRequest::Passwordless { server_addr } => {
                                        (*server_addr, None, ProposedCredentials::passwordless())
                                    }

                                    AuthenticationRequest::Credentialed { id, password } => {
                                        let acc_mgr = {
                                            let inner = inner!(self);
                                            inner.account_manager.clone()
                                        };

                                        let cnac = id.search(&acc_mgr).await?.ok_or(NetworkError::InternalError("Client does not exist"))?;
                                        let nac = cnac.get_nac();
                                        let conn_info = nac.get_conn_info().ok_or(NetworkError::InternalError("IP address not loaded internally this account"))?;
                                        let peer_addr = conn_info.addr;

                                        let proposed_credentials = cnac.generate_connect_credentials(password.clone()).await.map_err(|err| NetworkError::Generic(err.into_string()))?;

                                        (peer_addr, Some(cnac), proposed_credentials)
                                    }
                                }
                            }
                        }
                    };

                    let mut this = inner_mut!(self);
                    let on_drop = this.clean_shutdown_tracker_tx.clone();
                    let remote = this.server_remote.clone().unwrap();
                    let kernel_tx = this.kernel_tx.clone();
                    let account_manager = this.account_manager.clone();
                    let tt = this.time_tracker.clone();
                    let peer_layer = this.hypernode_peer_layer.clone();


                    if let Some((init_time, ..)) = this.provisional_connections.get(&peer_addr) {
                        // Localhost is already trying to connect. However, it's possible that the entry has expired,
                        // especially on IOS/droid where the background timer just stops completely
                        if init_time.elapsed() > DO_CONNECT_EXPIRE_TIME_MS {
                            // remove the entry, since it's expired anyways
                            this.provisional_connections.remove(&peer_addr);
                        } else {
                            return Err(NetworkError::Generic(format!("Localhost is already trying to connect to {}", peer_addr)));
                        }
                    }

                    (remote, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, proposed_credentials, peer_layer)
                };

                let peer_only_connect_mode = ConnectProtocol::Quic(listener_underlying_proto.maybe_get_identity());

                // create conn to peer
                let primary_stream = HdpServer::create_session_transport_init(peer_addr, default_client_config).await
                    .map_err(|err| NetworkError::SocketError(err.to_string()))?;
                let local_bind_addr = primary_stream.local_addr().map_err(|err| NetworkError::Generic(err.to_string()))?;
                (remote, primary_stream, local_bind_addr, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, peer_only_connect_mode, proposed_credentials, peer_layer)
            };

            //let peer_only_connect_mode = match listener_underlying_proto { UnderlyingProtocol::Tcp => ConnectProtocol::Tcp, UnderlyingProtocol::Tls(_, domain) => ConnectProtocol::Tls(domain) };

            let (stopper, new_session) = HdpSession::new(init_mode, local_nat_type, peer_only_connect_mode, cnac, peer_addr, proposed_credentials, on_drop,remote, local_bind_addr, local_node_type, kernel_tx, session_manager_clone.clone(), account_manager, tt, ticket, fcm_keys, udp_mode.unwrap_or(UDP_MODE), keep_alive_timeout_ns.unwrap_or(KEEP_ALIVE_TIMEOUT_NS), security_settings, connect_mode, default_client_config.clone(), peer_layer)?;

            inner_mut!(self).provisional_connections.insert(peer_addr, (Instant::now(), stopper, new_session.clone()));

            (session_manager_clone, new_session, peer_addr, primary_stream)
        };


        Ok(Box::pin(Self::execute_session_with_safe_shutdown(session_manager, new_session, peer_addr, primary_stream)))
    }

    /// Ensures that the session is removed even if there is a technical error in the underlying stream
    /// TODO: Make this code less hacky, and make the removal process cleaner. Use RAII on HdpSessionInner?
    async fn execute_session_with_safe_shutdown(session_manager: HdpSessionManager, new_session: HdpSession, peer_addr: SocketAddr, tcp_stream: GenericNetworkStream) -> Result<(), NetworkError> {
        log::info!("Beginning pre-execution of session");
        match new_session.execute(tcp_stream, peer_addr).await {
            Ok(cid_opt) | Err((_, cid_opt)) => {
                if let Some(cid) = cid_opt {
                    //log::info!("[safe] Deleting full connection from CID {} (IP: {})", cid, &peer_addr);
                    session_manager.clear_session(cid);
                    session_manager.clear_provisional_session(&peer_addr);
                } else {
                    //log::info!("[safe] deleting provisional connection to {}", &peer_addr);
                    session_manager.clear_provisional_session(&peer_addr);
                }
            }
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
                let _ = cnac.refresh_static_hyper_ratchet();
            }

            if cnac.passwordless() {
                // delete
                let cnac = cnac.clone();
                let task = async move {
                    pers.delete_cnac(cnac).await
                };
                let _ = spawn!(task);
                log::info!("Deleting passwordless CNAC ...");
            }
        }

        // the following shutdown sequence is valid for only for the HyperLAN server
        // This final sequence alerts all CIDs in the network
        if sess.is_server {
            // if the account was newly registered, it is possible that implicated_cid is none
            // if this is the case, ignore safe-shutdown of the session since no possible vconns
            // exist
            if let Some(implicated_cid) = sess.implicated_cid.get() {
                let task = async move {
                    peer_layer.on_session_shutdown(implicated_cid).await
                };

                let _ = spawn!(task);

                let timestamp = sess.time_tracker.get_global_time_ns();
                let security_level = state_container.session_security_settings.clone().map(|r| r.security_level).unwrap_or(SecurityLevel::LOW);

                state_container.active_virtual_connections.drain().for_each(|(peer_id, vconn)| {
                    let peer_cid = peer_id;
                    // toggling this off ensures that any higher-level channels are disabled
                    vconn.is_active.store(false, Ordering::SeqCst);
                    if peer_cid != implicated_cid && peer_cid != 0 {
                        let vconn = vconn.connection_type;
                        match vconn {
                            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, _) => {
                                if peer_cid != implicated_cid {
                                    log::info!("Alerting {} that {} disconnected", peer_cid, implicated_cid);
                                    let peer_conn_type = PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, peer_cid);
                                    let signal = PeerSignal::Disconnect(peer_conn_type, Some(PeerResponse::Disconnected(format!("{} disconnected from {} forcibly", peer_cid, implicated_cid))));
                                    if let Err(_err) = sess_mgr.send_signal_to_peer_direct(peer_cid, |peer_hyper_ratchet| {
                                        super::hdp_packet_crafter::peer_cmd::craft_peer_signal(peer_hyper_ratchet, signal, Ticket(0), timestamp, security_level)
                                    }) {
                                        //log::error!("Unable to send shutdown signal to {}: {:?}", peer_cid, err);
                                    }

                                    if let Some(peer_sess) = sess_mgr.sessions.get(&peer_cid) {
                                        let ref peer_sess = peer_sess.1;
                                        let mut peer_state_container = inner_mut_state!(peer_sess.state_container);
                                        if let None = peer_state_container.active_virtual_connections.remove(&implicated_cid) {
                                            log::warn!("While dropping session {}, attempted to remove vConn to {}, but peer did not have the vConn listed. Report to developers", implicated_cid, peer_cid);
                                        }
                                    }
                                }
                            }

                            // TODO: HyperWAN conns
                            _ => {}
                        }
                    }
                });
            }
        } else {
            // if we are ending a client session, we just need to ensure that the P2P streams go-down
            log::info!("Ending any active P2P connections");
            //sess.queue_worker.signal_shutdown();
            state_container.end_connections();
        }

        Ok(())
    }

    // This future should be joined up higher at the [HdpServer] layer
    pub async fn run_peer_container(hdp_session_manager: HdpSessionManager) -> Result<(), NetworkError> {
        let peer_container = {
            inner!(hdp_session_manager).hypernode_peer_layer.clone()
        };

        peer_container.await
    }

    /// When the primary port listener receives a new connection, the stream gets sent here for handling
    #[allow(unused_results)]
    pub fn process_new_inbound_connection(&self, local_bind_addr: SocketAddr, local_nat_type: NatType, peer_addr: SocketAddr, primary_stream: GenericNetworkStream) -> Result<Pin<Box<dyn RuntimeFuture>>, NetworkError> {
        let this_dc = self.clone();
        let mut this = inner_mut!(self);
        let on_drop = this.clean_shutdown_tracker_tx.clone();
        let remote = this.server_remote.clone().unwrap();
        let client_config = this.client_config.clone();
        let peer_layer = this.hypernode_peer_layer.clone();

        if let Some((init_time, ..)) = this.provisional_connections.get(&peer_addr) {
            if init_time.elapsed() > DO_CONNECT_EXPIRE_TIME_MS {
                this.provisional_connections.remove(&peer_addr);
            } else {
                return Err(NetworkError::Generic(format!("Peer from {} is already a provisional connection. Denying attempt", &peer_addr)));
            }
        }

        // Regardless if the IpAddr existed as a client before, we must treat the connection temporarily as provisional
        // However, two concurrent provisional connections from the same IP cannot be connecting at once
        let local_node_type = this.local_node_type;
        let provisional_ticket = Ticket(this.incoming_cxn_count as _);
        this.incoming_cxn_count += 1;

        let (stopper, new_session) = HdpSession::new_incoming(on_drop, local_nat_type, remote, local_bind_addr, local_node_type, this.kernel_tx.clone(), self.clone(), this.account_manager.clone(), this.time_tracker.clone(), peer_addr.clone(), provisional_ticket, client_config, peer_layer);
        this.provisional_connections.insert(peer_addr.clone(), (Instant::now(), stopper, new_session.clone()));
        std::mem::drop(this);

        // Note: Must send TICKET on finish
        //self.insert_provisional_expiration(peer_addr, provisional_ticket);
        let session = Self::execute_session_with_safe_shutdown(this_dc, new_session,peer_addr, primary_stream);

        Ok(Box::pin(session))
    }

    /// dispatches an outbound command
    pub fn process_outbound_broadcast_command(&self, ticket: Ticket, implicated_cid: u64, ref command: GroupBroadcast) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(existing_session) = this.sessions.get(&implicated_cid) {
            inner_mut_state!(existing_session.1.state_container).process_outbound_broadcast_command(ticket, command)
        } else {
            Err(NetworkError::Generic(format!("Hypernode session for {} does not exist! Not going to handle group broadcast signal {:?} ...", implicated_cid, command)))
        }
    }

    /// When the [HdpServer] receives an outbound request, the request flows here. It returns where the packet must be sent to
    pub fn process_outbound_file(&self, ticket: Ticket, max_group_size: Option<usize>, file: PathBuf, implicated_cid: u64, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(existing_session) = this.sessions.get(&implicated_cid) {
            existing_session.1.process_outbound_file(ticket, max_group_size, file, virtual_target, security_level)
        } else {
            Err(NetworkError::Generic(format!("Hypernode session for {} does not exist! Not going to send data ...", implicated_cid)))
        }
    }

    /// Returns true if the process continued successfully
    pub fn initiate_update_drill_subroutine(&self, virtual_target: VirtualTargetType, ticket: Ticket) -> Result<(), NetworkError> {
        let implicated_cid = virtual_target.get_implicated_cid();
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&implicated_cid) {
            let ref sess = sess.1;
            let timestamp = sess.time_tracker.get_global_time_ns();
            let mut state_container = inner_mut_state!(sess.state_container);
            state_container.initiate_drill_update(timestamp, virtual_target, Some(ticket))
        } else {
            Err(NetworkError::Generic(format!("Unable to initiate drill update subroutine for {} (not an active session)", implicated_cid)))
        }
    }

    /// Returns true if the process initiated successfully
    pub fn initiate_deregistration_subroutine(&self, implicated_cid: u64, connection_type: VirtualConnectionType, ticket: Ticket) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&implicated_cid) {
            let ref sess = sess.1;
            sess.initiate_deregister(connection_type, ticket)
        } else {
            Err(NetworkError::Generic(format!("Unable to initiate deregister subroutine for {} (not an active session)", implicated_cid)))
        }
    }

    ///
    pub fn check_online_status(&self, users: &Vec<u64>) -> Vec<bool> {
        let this = inner!(self);
        users.iter().map(|user| this.sessions.contains_key(user)).collect()
    }

    /// Sends the command outbound. Returns true if sent, false otherwise
    /// In the case that this return false, further interaction should be avoided
    pub async fn dispatch_peer_command(&self, implicated_cid: u64, ticket: Ticket, peer_command: PeerSignal, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let sess = {
            let this = inner!(self);
            if let Some(sess) = this.sessions.get(&implicated_cid) {
                let sess = sess.1.clone();
                sess
            } else {
                return Err(NetworkError::msg(format!("Session for {} not found in session manager. Failed to dispatch peer command {:?}", implicated_cid, peer_command)))
            }
        };

        sess.dispatch_peer_command(ticket, peer_command, security_level).await
    }

    /// Returns a list of active sessions
    pub fn get_active_sessions(&self) -> Vec<u64> {
        let this = inner!(self);
        this.sessions.keys().map(|r| *r).collect()
    }

    /// This upgrades a provisional connection to a full connection. Returns true if the upgrade
    /// succeeded, false otherwise
    ///
    /// Adds the internal queues to the hypernode_peer_layer. This function thus MUST be called during the
    /// DO_CONNECT stage
    ///
    /// This will return false if the provisional connection was already removed. This can happen to really
    /// slow connections, or during background execution on android/ios
    pub fn upgrade_connection(&self, socket_addr: SocketAddr, implicated_cid: u64) -> bool {
        let mut this = inner_mut!(self);
        if let Some((_, stopper, session)) = this.provisional_connections.remove(&socket_addr) {
            //let _ = this.hypernode_peer_layer.register_peer(implicated_cid, true);
            if let Some(lingering_conn) = this.sessions.insert(implicated_cid, (stopper, session)) {
                // sometimes (especially on cellular networks), when the network changes due to
                // changing cell towers (or between WIFI/Cellular modes), the session lingers
                // without cleaning itself up. It will automatically drop by itself, however,
                // sometimes when the client attempts to re-connect, the old session will still
                // be in place, and hence removing the old session when attemping to upgrade
                // from a provisional to a protected connection must be allowed. As such, issue a warning here,
                // then return true to allow the new connection to proceed instead of returning false
                // due to overlapping connection
                log::warn!("Cleaned up lingering session for {}", implicated_cid);
                let ref prev_conn = lingering_conn.1;
                prev_conn.do_static_hr_refresh_atexit.set(false);
            }

            true
        } else {
            false
        }
    }

    /// Returns true if the disconnect was a success, false if not. An error returns if something else occurs
    pub fn initiate_disconnect(&self, implicated_cid: u64, virtual_peer: VirtualConnectionType, ticket: Ticket) -> Result<bool, NetworkError> {
        let this = inner!(self);
        match this.sessions.get(&implicated_cid) {
            Some(session) => {
                session.1.initiate_disconnect(ticket, virtual_peer)
            }

            None => {
                Ok(false)
            }
        }
    }

    /// Clears a session from the internal map
    pub fn clear_session(&self, cid: u64) {
        let mut this = inner_mut!(self);
        this.clear_session(cid);
    }

    /// When the registration process completes, and before sending the kernel a message, this should be called on BOTH ends
    pub fn clear_provisional_session(&self, addr: &SocketAddr) {
        //log::info!("Attempting to clear provisional session ...");
        if inner_mut!(self).provisional_connections.remove(addr).is_none() {
            log::warn!("Attempted to remove a connection {:?} that wasn't provisional", addr);
        }
    }

    /// Sends to user, but does not block. Once the send is complete, will run ``on_send_complete``, which gives the sender the option to return a packet back to the initiator
    ///
    /// This is usually to send packets to another client who may or may not have an endpoint crypt container yet. It doesn't matter here, since we're only using the base ratchet
    ///
    /// Since the user may or may not be online, we use the static aux ratchet
    #[allow(unused_results)]
    pub async fn fcm_post_register_to(&self, implicated_cid: u64, peer_cid: u64, is_response: bool, packet_crafter: impl FnOnce(&HyperRatchet) -> RawExternalPacket, on_send_complete: impl FnOnce(Result<(), AccountError>) + ContextRequirements) -> Result<(), NetworkError> {
        let this_ref = self.clone();

        if implicated_cid != peer_cid {
            let (account_manager, tickets) = {
                let this = inner!(self);
                let tickets = FcmPeerRegisterTicket::create_bidirectional(implicated_cid, peer_cid);
                if !is_response {
                    if this.fcm_post_registrations.contains(&tickets.0) || this.fcm_post_registrations.contains(&tickets.1) {
                        return Err(NetworkError::InvalidRequest("A concurrent registration request between the two peers is already occurring"))
                    }
                }

                let account_manager = this.account_manager.clone();
                std::mem::drop(this);
                (account_manager, tickets)
            };

            let peer_cnac = account_manager.get_client_by_cid(peer_cid).await?.ok_or(NetworkError::InvalidRequest("Peer CID does not exist"))?;
            let (keys, static_aux_ratchet) = {
                let inner = peer_cnac.read();
                let keys = inner.crypt_container.fcm_keys.clone();
                let static_aux_ratchet = inner.crypt_container.toolset.get_static_auxiliary_ratchet().clone();

                (keys, static_aux_ratchet)
            };

            let fcm_instance = FCMInstance::new(keys.ok_or(NetworkError::InvalidRequest("Client cannot receive FCM messages at this time"))?, account_manager.fcm_client().clone());
            let packet = packet_crafter(&static_aux_ratchet);

            {
                let mut this = inner_mut!(this_ref);

                if is_response {
                    // remove the tickets
                    this.fcm_post_registrations.remove(&tickets.0);
                    this.fcm_post_registrations.remove(&tickets.1);
                } else {
                    // add the tickets
                    this.fcm_post_registrations.insert(tickets.0);
                    this.fcm_post_registrations.insert(tickets.1);
                }

                std::mem::drop(this);
            }


            on_send_complete(fcm_instance.send_to_fcm_user(packet).await.map(|_| ()));
            Ok(())
        } else {
            Err(NetworkError::InvalidRequest("implicated cid == peer_cid"))
        }
    }

    /// Creates a new message group. Returns a key if successful
    pub fn create_message_group_and_notify(&self, timestamp: i64, ticket: Ticket, implicated_cid: u64, peers_to_notify: Vec<u64>, security_level: SecurityLevel) -> Option<MessageGroupKey> {
        let this = inner!(self);
        let key = this.hypernode_peer_layer.create_new_message_group(implicated_cid, &peers_to_notify)?;
        // notify all the peers
        for peer_cid in peers_to_notify {
            if let Err(err) = this.send_signal_to_peer_direct(peer_cid, |peer_hyper_ratchet| {
                let signal = GroupBroadcast::Invitation(key);
                super::hdp_packet_crafter::peer_cmd::craft_group_message_packet(peer_hyper_ratchet, &signal, ticket, C2S_ENCRYPTION_ONLY, timestamp, security_level)
            }) {
                log::warn!("Unable to send signal to peer {}: {}", peer_cid, err.to_string());
            }
        }

        Some(key)
    }

    /// Returns true if the removal was a success
    pub fn remove_message_group(&self, cid_host: u64, timestamp: i64, ticket: Ticket, key: MessageGroupKey, security_level: SecurityLevel) -> bool {
        let this = inner!(self);
        if let Some(group) = this.hypernode_peer_layer.remove_message_group(key) {
            for peer_cid in group.concurrent_peers.keys() {
                if *peer_cid != cid_host {
                    if let Err(err) = this.send_signal_to_peer_direct(*peer_cid, |peer_hyper_ratchet| {
                        let signal = GroupBroadcast::Disconnected(key);
                        super::hdp_packet_crafter::peer_cmd::craft_group_message_packet(peer_hyper_ratchet, &signal, ticket, C2S_ENCRYPTION_ONLY, timestamp, security_level)
                    }) {
                        log::warn!("Unable to send d/c signal to peer {}: {}", peer_cid, err.to_string());
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
    pub async fn kick_from_message_group(&self, mode: GroupMemberAlterMode, implicated_cid: u64, timestamp: i64, ticket: Ticket, key: MessageGroupKey, peers: Vec<u64>, security_level: SecurityLevel) -> Result<bool, NetworkError> {
        let peer_layer = {
            inner!(self).hypernode_peer_layer.clone()
        };

        let mut to_broadcast_dc = vec![];
        let mut to_broadcast_left = vec![];
        let dc_signal = GroupBroadcast::Disconnected(key);

        let left_signal = match peer_layer.remove_peers_from_message_group(key, peers) {
            Ok((peers_removed, peers_remaining)) => {
                log::info!("Peers removed: {:?}", &peers_removed);
                // We only notify the members when kicking, not leaving
                if mode == GroupMemberAlterMode::Kick {
                    // notify all the peers removed
                    for peer in &peers_removed {
                        if *peer != implicated_cid {
                            to_broadcast_dc.push(*peer);
                        }
                    }
                }

                for peer in peers_remaining {
                    if peer != implicated_cid {
                        to_broadcast_left.push(peer);
                    }
                }

                GroupBroadcast::MemberStateChanged(key, MemberState::LeftGroup(peers_removed))
            }

            Err(_) => {
                log::error!("Unable to kick peers from message group");
                return Ok(false)
            }
        };

        // if we get here, dispatch any messages
        let len = to_broadcast_dc.len();
        let peers_and_statuses_dc = to_broadcast_dc.into_iter().zip(std::iter::repeat(true).take(len));
        let _ = self.send_group_broadcast_signal_to(timestamp, ticket, peers_and_statuses_dc, true, dc_signal, security_level).await.map_err(|err| NetworkError::Generic(err))?;

        let len = to_broadcast_left.len();
        let peers_and_statuses_left = to_broadcast_left.into_iter().zip(std::iter::repeat(true).take(len));
        let _ = self.send_group_broadcast_signal_to(timestamp, ticket, peers_and_statuses_left, true, left_signal, security_level).await.map_err(|err| NetworkError::Generic(err))?;


        Ok(true)
    }

    /// Broadcasts a message to a target group
    /// Note: uses mail_if_offline: true. This allows a member to disconnect, but to still receive messages later-on
    pub async fn broadcast_signal_to_group(&self, implicated_cid: u64, timestamp: i64, ticket: Ticket, key: MessageGroupKey, signal: GroupBroadcast, security_level: SecurityLevel) -> Result<bool, String> {
        let peer_layer = {
            inner!(self).hypernode_peer_layer.clone()
        };

        if let Some(peers_to_broadcast_to) = peer_layer.get_peers_in_message_group(key) {
            let can_broadcast = peers_to_broadcast_to.iter().map(|peer| *peer != implicated_cid).collect::<Vec<bool>>();
            let peers_and_statuses = peers_to_broadcast_to.into_iter().zip(can_broadcast);
            let _ = self.send_group_broadcast_signal_to(timestamp, ticket, peers_and_statuses, true, signal, security_level).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// sends a signal to the peer using the correct PQC and Drill cryptosystem
    /// NOTE: THIS WILL PANIC if `target_cid` == the implicated cid from the closure that calls this
    pub fn send_signal_to_peer(&self, target_cid: u64, ticket: Ticket, signal: PeerSignal, timestamp: i64, security_level: SecurityLevel) -> bool {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&target_cid) {
            let ref sess = sess.1;
            if let Some(to_primary_stream) = sess.to_primary_stream.as_ref() {
                if let Some(cnac) = inner_state!(sess.state_container).cnac.as_ref() {
                    return cnac.borrow_hyper_ratchet(None, |hyper_ratchet_opt| {
                        if let Some(hyper_ratchet) = hyper_ratchet_opt {
                            let packet = super::hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, signal, ticket, timestamp, security_level);
                            to_primary_stream.unbounded_send(packet).is_ok()
                        } else {
                            false
                        }
                    });
                }
            }
        }

        false
    }

    /// Ensures the mailbox and tracked event queue are loaded into the [PeerLayer]
    pub async fn register_session_with_peer_layer(&self, implicated_cid: u64) -> Result<Option<MailboxTransfer>, NetworkError> {
        let peer_layer = {
            inner!(self).hypernode_peer_layer.clone()
        };

        peer_layer.register_peer(implicated_cid).await
    }

    /// Removes a virtual connection `implicated_cid` from `peer_cid`
    pub fn disconnect_virtual_conn(&self, implicated_cid: u64, peer_cid: u64, on_internal_disconnect: impl FnOnce(&HyperRatchet) -> BytesMut) -> Result<(), String> {
        if implicated_cid == peer_cid {
            return Err("Implicated CID cannot equal peer cid".to_string())
        }

        let this = inner!(self);
        if let Some(peer_sess) = this.sessions.get(&peer_cid) {
            let ref sess = peer_sess.1;
            let to_primary = sess.to_primary_stream.as_ref().unwrap();

            let mut state_container = inner_mut_state!(sess.state_container);
            let peer_cnac = state_container.cnac.clone().ok_or_else(||String::from("Peer CNAC does not exist"))?;

            if state_container.active_virtual_connections.remove(&implicated_cid).is_some() {
                let packet_opt = peer_cnac.borrow_hyper_ratchet(None, |peer_latest_hyper_ratchet_opt| {
                    if let Some(peer_latest_hyper_ratchet) = peer_latest_hyper_ratchet_opt {
                        Some(on_internal_disconnect(peer_latest_hyper_ratchet))
                    } else {
                        None
                    }
                });

                if let Some(packet) = packet_opt {
                    to_primary.unbounded_send(packet).map_err(|err| err.to_string())
                } else {
                    Err("Unable to obtain peer drill".to_string())
                }
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn route_packet_to(&self, target_cid: u64, packet: impl FnOnce(&HyperRatchet) -> BytesMut) -> Result<(), String> {
        let lock = inner!(self);
        let (_, sess_ref) = lock.sessions.get(&target_cid).ok_or_else(|| format!("Target cid {} does not exist (route err)", target_cid))?;
        let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
        let ref peer_cnac = inner_state!(sess_ref.state_container).cnac.clone().ok_or_else(|| String::from("Peer CNAC not loaded"))?;

        peer_cnac.borrow_hyper_ratchet(None, |hyper_ratchet_opt| {
            if let Some(peer_latest_hyper_ratchet) = hyper_ratchet_opt {
                log::info!("Routing packet through primary stream -> {}", target_cid);
                let packet = packet(peer_latest_hyper_ratchet);
                peer_sender.unbounded_send(packet).map_err(|err| err.to_string())
            } else {
                Err(format!("Unable to acquire peer drill for {}", target_cid))
            }
        })
    }

    /// Stores the `signal` inside the internal timed-queue for `implicated_cid`, and then sends `packet` to `target_cid`.
    /// After `timeout`, the closure `on_timeout` is executed
    #[inline]
    pub async fn route_signal_primary(&self, implicated_cid: u64, target_cid: u64, ticket: Ticket, signal: PeerSignal, packet: impl FnOnce(&HyperRatchet) -> BytesMut, timeout: Duration, on_timeout: impl Fn(PeerSignal) + SyncContextRequirements) -> Result<(), String> {
        if implicated_cid == target_cid {
            return Err("Target CID cannot be equal to the implicated CID".to_string());
        }

        let account_manager = {
            inner!(self).account_manager.clone()
        };

        log::info!("Checking if {} is registered locally ... {:?}", target_cid, signal);
        if account_manager.hyperlan_cid_is_registered(target_cid).await.map_err(|err| err.into_string())? {
            let (sess, peer_layer) = {
                let this = inner!(self);
                let sess = this.sessions.get(&target_cid).map(|r| r.1.clone());
                let peer_layer = this.hypernode_peer_layer.clone();
                (sess, peer_layer)
            };

            // get the target cid's session
            if let Some(ref sess_ref) = sess {
                peer_layer.insert_tracked_posting(implicated_cid, timeout, ticket, signal, on_timeout);
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let ref peer_cnac = inner_state!(sess_ref.state_container).cnac.clone().ok_or_else(|| String::from("Peer CNAC not loaded"))?;

                peer_cnac.borrow_hyper_ratchet(None, |hyper_ratchet_opt| {
                    if let Some(peer_latest_hyper_ratchet) = hyper_ratchet_opt {
                        log::info!("Routing packet through primary stream ({} -> {})", implicated_cid, target_cid);
                        let packet = packet(peer_latest_hyper_ratchet);
                        peer_sender.unbounded_send(packet).map_err(|err| err.to_string())
                    } else {
                        Err(format!("Unable to acquire peer drill for {}", target_cid))
                    }
                })
            } else {
                // session is not active, but user is registered (thus offline). Setup return ticket tracker on implicated_cid
                // and deliver to the mailbox of target_cid, that way target_cid receives mail on connect. TODO: FCM route alternative, if available
                peer_layer.insert_tracked_posting(implicated_cid, timeout, ticket, signal.clone(), on_timeout);
                peer_layer.try_add_mailbox(target_cid, signal).await.map_err(|err| err.into_string())
            }
        } else {
            Err(format!("CID {} is not registered locally", target_cid))
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
                return Err(NetworkError::InternalError("UnboundedReceiver not loaded in session manager"))
            }
        };


        for _ in 0..len {
            recv.recv().await.ok_or(NetworkError::InternalError("Unable to receive shutdown signal"))?;
        }

        log::info!("All sessions dropped");
        Ok(())
    }

    /// Sends a [GroupBroadcast] message to `peer_cid`. Ensures the target is mutual before sending
    /// `mail_if_offline`: Deposits mail if the target is offline
    /// NOTE: it is the duty of the calling closure to ensure that the [MessageGroup] exists!
    /// NOTE: This does not check to see if the two peers can send to each other. That is up to the caller to ensure that
    ///
    pub async fn send_group_broadcast_signal_to(&self, timestamp: i64, ticket: Ticket, peers_and_statuses: impl Iterator<Item=(u64, bool)>, mail_if_offline: bool, signal: GroupBroadcast, security_level: SecurityLevel) -> Result<(Vec<u64>, Vec<u64>), String> {
        let mut peers_failed = Vec::new();
        let mut peers_okay = Vec::new();
        let mut to_mail = Vec::new();

        let peer_layer = {
            let this = inner!(self);
            for (peer, is_registered) in peers_and_statuses {
                if is_registered {
                    if this.send_signal_to_peer_direct(peer, |peer_hyper_ratchet| {
                        super::hdp_packet_crafter::peer_cmd::craft_group_message_packet(peer_hyper_ratchet, &signal, ticket, C2S_ENCRYPTION_ONLY, timestamp, security_level)
                    }).is_err() {
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

            this.hypernode_peer_layer.clone()
        };

        // TODO: optimize this into a single operation
        for peer in to_mail {
            peer_layer.try_add_mailbox(peer, PeerSignal::BroadcastConnected(signal.clone())).await.map_err(|err| err.into_string())?;
            peers_okay.push(peer);
        }

        Ok((peers_okay, peers_failed))
    }
}

impl HdpSessionManagerInner {
    /// Clears a session from the SessionManager
    pub fn clear_session(&mut self, cid: u64) {
        if let None = self.sessions.remove(&cid) {
            log::warn!("Tried removing a session (non-provisional), but did not find it ...");
        }
    }

    /// NOTE: The order flips in the response.
    /// Further, the PeerResponse changes state: it becomes Some() instead of None upon reply
    /// Returns the target_cid's Session to handle updates on the internal state as necessary
    /// Also returns the [TrackedPosting] that was posted when the signal initially crossed through
    /// the HyperLAN Server
    #[inline]
    pub fn route_signal_response_primary(&self, implicated_cid: u64, target_cid: u64, ticket: Ticket, packet: impl FnOnce(&HyperRatchet) -> BytesMut, post_send: impl FnOnce(&HdpSession, PeerSignal) -> Result<PrimaryProcessorResult, NetworkError>) -> Result<Result<PrimaryProcessorResult, NetworkError>, String> {
        // Instead of checking for registration, check the `implicated_cid`'s timed queue for a ticket corresponding to Ticket.
        if let Some(tracked_posting) = self.hypernode_peer_layer.remove_tracked_posting(target_cid, ticket) {
            // since the posting was valid, we just need to forward the signal to `implicated_cid`
            if let Some(target_sess) = self.sessions.get(&target_cid) {
                //let ret = target_sess.clone();

                let ref sess_ref = target_sess.1;
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let peer_cnac = inner_state!(sess_ref.state_container).cnac.clone().ok_or_else(|| String::from("Peer CNAC does not exist"))?;

                peer_cnac.borrow_hyper_ratchet(None, |peer_latest_hyper_ratchet_opt| {
                    if let Some(peer_latest_hyper_ratchet) = peer_latest_hyper_ratchet_opt {
                        let packet = packet(peer_latest_hyper_ratchet);
                        peer_sender.unbounded_send(packet).map_err(|err| err.to_string())
                    } else {
                        Err(format!("Unable to acquire peer drill for {}", target_cid))
                    }
                })?;

                Ok((post_send)(&sess_ref, tracked_posting))
            } else {
                // session no longer exists. Could have been that the `implicated_cid` responded too late. Send an error back, saying it expired
                Err(format!("Session for {} is not active, and thus no room for consent", target_cid))
            }
        } else {
            // the tracked posting doesn't exist. It may have expired. In either case, the potential session is invalid
            Err(format!("Tracked posting {} for {} -> {} does not exist", ticket, target_cid, implicated_cid))
        }
    }

    // for use by the server. This skips the whole ticket-tracking processes intermediate to the routing above
    pub fn send_signal_to_peer_direct(&self, target_cid: u64, packet: impl FnOnce(&HyperRatchet) -> BytesMut) -> Result<(), NetworkError> {
        if let Some(peer_sess) = self.sessions.get(&target_cid) {
            let ref peer_sess = peer_sess.1;
            let peer_sender = peer_sess.to_primary_stream.as_ref().ok_or_else(|| NetworkError::InternalError("Peer stream absent"))?;
            let peer_cnac = inner_state!(peer_sess.state_container).cnac.clone().ok_or_else(|| NetworkError::InternalError("Peer CNAC absent"))?;

            peer_cnac.borrow_hyper_ratchet(None, |latest_peer_hr_opt| {
                if let Some(peer_latest_hr) = latest_peer_hr_opt {
                    let packet = packet(peer_latest_hr);
                    peer_sender.unbounded_send(packet).map_err(|err| NetworkError::Generic(err.to_string()))
                } else {
                    Err(NetworkError::InternalError("Peer drill absent"))
                }
            })
        } else {
            Err(NetworkError::Generic(format!("unable to find peer sess {}", target_cid)))
        }
    }
}