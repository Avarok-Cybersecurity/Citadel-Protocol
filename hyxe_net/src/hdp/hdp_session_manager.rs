use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use bytes::BytesMut;

use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::prelude::SecurityLevel;
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::nat_identification::NatType;
use hyxe_nat::time_tracker::TimeTracker;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::external_services::fcm::data_structures::RawExternalPacket;
use hyxe_user::external_services::fcm::fcm_instance::FCMInstance;
use hyxe_user::misc::AccountError;
use hyxe_user::prelude::ConnectProtocol;
use hyxe_user::proposed_credentials::ProposedCredentials;

use crate::constants::{DO_CONNECT_EXPIRE_TIME_MS, KEEP_ALIVE_TIMEOUT_NS, UDP_MODE};
use crate::error::NetworkError;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::hdp::hdp_packet_processor::includes::{Duration, Instant};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::{GroupBroadcast, GroupMemberAlterMode, MemberState};
use crate::hdp::hdp_packet_processor::PrimaryProcessorResult;
use crate::hdp::hdp_server::{ConnectMode, HdpServer, HdpServerRemote, HdpServerResult, Ticket};
use crate::hdp::hdp_session::{HdpSession, HdpSessionInitMode};
use crate::hdp::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::misc::underlying_proto::UnderlyingProtocol;
use crate::hdp::outbound_sender::{Sender, unbounded, UnboundedReceiver, UnboundedSender};
use crate::hdp::outbound_sender::{OutboundPrimaryStreamSender, OutboundUdpSender};
use crate::hdp::peer::message_group::MessageGroupKey;
use crate::hdp::peer::peer_layer::{HyperNodePeerLayer, MailboxTransfer, PeerConnectionType, PeerResponse, PeerSignal, UdpMode};
use crate::hdp::state_container::{VirtualConnectionType, VirtualTargetType};
use crate::kernel::RuntimeFuture;
use crate::macros::{ContextRequirements, SyncContextRequirements};

define_outer_struct_wrapper!(HdpSessionManager, HdpSessionManagerInner);

/// Used for handling stateful connections between two peer
pub struct HdpSessionManagerInner {
    local_node_type: HyperNodeType,
    sessions: HashMap<u64, (Sender<()>, HdpSession)>,
    account_manager: AccountManager,
    pub(crate) hypernode_peer_layer: HyperNodePeerLayer,
    server_remote: Option<HdpServerRemote>,
    incoming_cxn_count: usize,
    /// Connections which have no implicated CID go herein. They are strictly expected to be
    /// in the state of NeedsRegister. Once they leave that state, they are eventually polled
    /// by the [HdpSessionManager] and thereafter placed inside an appropriate session
    provisional_connections: HashMap<SocketAddr, (Instant, Sender<()>, HdpSession)>,
    fcm_post_registrations: HashSet<FcmPeerRegisterTicket>,
    kernel_tx: UnboundedSender<HdpServerResult>,
    time_tracker: TimeTracker,
    clean_shutdown_tracker_tx: UnboundedSender<()>,
    clean_shutdown_tracker: Option<UnboundedReceiver<()>>
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
    pub fn new(local_node_type: HyperNodeType, kernel_tx: UnboundedSender<HdpServerResult>, account_manager: AccountManager, time_tracker: TimeTracker) -> Self {
        let incoming_cxn_count = 0;
        let (clean_shutdown_tracker_tx, clean_shutdown_tracker_rx) = unbounded();
        let inner = HdpSessionManagerInner {
            clean_shutdown_tracker_tx,
            clean_shutdown_tracker: Some(clean_shutdown_tracker_rx),
            fcm_post_registrations: Default::default(),
            hypernode_peer_layer: Default::default(),
            server_remote: None,
            local_node_type,
            sessions: HashMap::new(),
            incoming_cxn_count,
            account_manager,
            provisional_connections: HashMap::new(),
            kernel_tx,
            time_tracker
        };

        Self::from(inner)
    }

    /// Loads the server remote, and gets the time tracker for the calling [HdpServer]
    /// Used during the init stage
    pub(crate) fn load_server_remote_get_tt(&self, server_remote: HdpServerRemote) -> TimeTracker {
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

    /// Returns a set of the currently valid sessions
    /// TODO: Determine difference between a typical HyperLAN connection and a HyperWAN Server
    pub fn get_session_cids(&self) -> Option<Vec<u64>> {
        let this = inner!(self);
        if !this.sessions.is_empty() {
            Some(this.sessions.keys().cloned().collect())
        } else {
            None
        }
    }

    /// Called by the higher-level [HdpServer] async writer loop
    /// `nid_local` is only needed incase a provisional id is needed.
    ///
    /// This is initiated by the local HyperNode's request to connect to an external server
    /// `proposed_credentials`: Must be Some if implicated_cid is None!
    #[allow(unused_results)]
    pub async fn initiate_connection<T: ToSocketAddrs>(&self, local_node_type: HyperNodeType, local_nat_type: NatType, local_bind_addr_for_primary_stream: T, init_mode: HdpSessionInitMode, ticket: Ticket, proposed_credentials: ProposedCredentials, connect_mode: Option<ConnectMode>, listener_underlying_proto: UnderlyingProtocol, fcm_keys: Option<FcmKeys>, udp_mode: Option<UdpMode>, keep_alive_timeout_ns: Option<i64>, security_settings: SessionSecuritySettings) -> Result<Pin<Box<dyn RuntimeFuture>>, NetworkError> {
        let (session_manager, new_session, peer_addr, p2p_listener, primary_stream) = {
            let session_manager_clone = self.clone();

            let (remote, p2p_listener, primary_stream, local_bind_addr, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, peer_only_connect_mode) = {
                let (remote, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac) = {
                    let (peer_addr, cnac) = {
                        match init_mode.clone() {
                            HdpSessionInitMode::Register(peer_addr) => (peer_addr, None),

                            HdpSessionInitMode::Connect(implicated_cid) => {
                                let acc_mgr = {
                                    let inner = inner!(self);
                                    inner.account_manager.clone()
                                };

                                let cnac = acc_mgr.get_client_by_cid(implicated_cid).await?.ok_or(NetworkError::InternalError("Client does not exist"))?;
                                let nac = cnac.get_nac();
                                let conn_info = nac.get_conn_info().ok_or(NetworkError::InternalError("IP address not loaded internally this account"))?;
                                let peer_addr = conn_info.addr;
                                (peer_addr, Some(cnac))
                            }
                        }
                    };

                    let mut this = inner_mut!(self);
                    let on_drop = this.clean_shutdown_tracker_tx.clone();
                    let remote = this.server_remote.clone().unwrap();
                    let kernel_tx = this.kernel_tx.clone();
                    let account_manager = this.account_manager.clone();
                    let tt = this.time_tracker.clone();


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

                    (remote, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac)
                };

                let peer_only_connect_mode = ConnectProtocol::Quic(listener_underlying_proto.maybe_get_identity());

                // We must now create a TcpStream towards the peer
                let local_bind_addr = local_bind_addr_for_primary_stream.to_socket_addrs().map_err(|err| NetworkError::Generic(err.to_string()))?.next().unwrap() as SocketAddr;
                // NOTE! From now own, we are using QUIC for p2p streams for NAT traversal reasons. No more TCP hole punching
                let (p2p_listener, primary_stream) = HdpServer::create_session_transport_init(listener_underlying_proto.into_quic(), peer_addr).await
                    .map_err(|err| NetworkError::SocketError(err.to_string()))?;
                (remote, p2p_listener, primary_stream, local_bind_addr, kernel_tx, account_manager, tt, on_drop, peer_addr, cnac, peer_only_connect_mode)
            };

            //let peer_only_connect_mode = match listener_underlying_proto { UnderlyingProtocol::Tcp => ConnectProtocol::Tcp, UnderlyingProtocol::Tls(_, domain) => ConnectProtocol::Tls(domain) };

            let (stopper, new_session) = HdpSession::new(init_mode.clone(), local_nat_type, peer_only_connect_mode, cnac, peer_addr, proposed_credentials, on_drop,remote, local_bind_addr, local_node_type, kernel_tx, session_manager_clone.clone(), account_manager, tt, ticket, fcm_keys, udp_mode.unwrap_or(UDP_MODE), keep_alive_timeout_ns.unwrap_or(KEEP_ALIVE_TIMEOUT_NS), security_settings)?;

            match init_mode {
                HdpSessionInitMode::Connect(..) => {
                    inner_mut!(self).provisional_connections.insert(peer_addr, (Instant::now(), stopper, new_session.clone()));
                }

                HdpSessionInitMode::Register(peer_addr) => {
                    inner_mut!(self).provisional_connections.insert(peer_addr, (Instant::now(), stopper, new_session.clone()));
                }
            }

            (session_manager_clone, new_session, peer_addr, p2p_listener, primary_stream)
        };


        Ok(Box::pin(Self::execute_session_with_safe_shutdown(session_manager, new_session, peer_addr, Some(p2p_listener), primary_stream, connect_mode)))
    }

    /// Ensures that the session is removed even if there is a technical error in the underlying stream
    /// TODO: Make this code less hacky, and make the removal process cleaner. Use RAII on HdpSessionInner?
    async fn execute_session_with_safe_shutdown(session_manager: HdpSessionManager, new_session: HdpSession, peer_addr: SocketAddr, p2p_listener: Option<GenericNetworkListener>, tcp_stream: GenericNetworkStream, connect_mode: Option<ConnectMode>) -> Result<(), NetworkError> {
        log::info!("Beginning pre-execution of session");
        match new_session.execute(p2p_listener, tcp_stream, peer_addr, connect_mode).await {
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

        // TODO: Use RAII w/ HdpSessionInner & StateContainerInner ? Hmm ... seems good on PC/Linux/Mac,
        // but not good with android when connections really have the tendency to linger since background
        // async subroutines get shutoff

        let sess_mgr = inner!(session_manager);
        // the final step is to take all virtual conns inside the session, and remove them from other sessions
        let sess = new_session;

        if let Some(cnac) = sess.cnac.get() {
            // we do not need to save here. When the ratchet is reloaded, it will be zeroed out anyways.
            // the only reason we call this is to ensure that FCM packets that get protected on their way out
            // don't cause false-positives on the anti-replay-attack container
            // Especially needed for FCM
            // The only time the static HR won't get refreshed if a lingering connection gets cleaned-up
            if sess.do_static_hr_refresh_atexit.get() {
                let _ = cnac.refresh_static_hyper_ratchet();
            }
        }

        // the following shutdown sequence is valid for only for the HyperLAN server
        // This final sequence alerts all CIDs in the network
        if sess.is_server {
            // if the account was newly registered, it is possible that implicated_cid is none
            // if this is the case, ignore safe-shutdown of the session since no possible vconns
            // exist
            if let Some(implicated_cid) = sess.implicated_cid.get() {
                sess_mgr.hypernode_peer_layer.on_session_shutdown(implicated_cid);
                let timestamp = sess.time_tracker.get_global_time_ns();
                let security_level = sess.security_settings.get().map(|r| r.security_level).unwrap_or(SecurityLevel::LOW);
                let mut state_container = inner_mut!(sess.state_container);

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
                                        let mut peer_state_container = inner_mut!(peer_sess.state_container);
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
            sess.queue_worker.signal_shutdown();
            inner_mut!(sess.state_container).end_connections();
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
        let provisional_ticket = Ticket(this.incoming_cxn_count as u64);
        this.incoming_cxn_count += 1;

        let (stopper, new_session) = HdpSession::new_incoming(on_drop, local_nat_type, remote, local_bind_addr, local_node_type, this.kernel_tx.clone(), self.clone(), this.account_manager.clone(), this.time_tracker.clone(), peer_addr.clone(), provisional_ticket);
        this.provisional_connections.insert(peer_addr.clone(), (Instant::now(), stopper, new_session.clone()));
        std::mem::drop(this);

        // Note: Must send TICKET on finish
        //self.insert_provisional_expiration(peer_addr, provisional_ticket);
        let session = Self::execute_session_with_safe_shutdown(this_dc, new_session,peer_addr, None, primary_stream, None);

        Ok(Box::pin(session))
    }

    /// When the [HdpServer] receives an outbound request, the request flows here. It returns where the packet must be sent to
    pub fn process_outbound_packet(&self, ticket: Ticket, packet: SecBuffer, implicated_cid: u64, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(existing_session) = this.sessions.get(&implicated_cid) {
            existing_session.1.process_outbound_message(ticket, packet, virtual_target, security_level)
        } else {
            Err(NetworkError::Generic(format!("Hypernode session for {} does not exist! Not going to send data ...", implicated_cid)))
        }
    }

    /// dispatches an outbound command
    pub fn process_outbound_broadcast_command(&self, ticket: Ticket, implicated_cid: u64, command: GroupBroadcast) -> Result<(), NetworkError> {
        let this = inner!(self);
        if let Some(existing_session) = this.sessions.get(&implicated_cid) {
            existing_session.1.process_outbound_broadcast_command(ticket, command)
        } else {
            Err(NetworkError::Generic(format!("Hypernode session for {} does not exist! Not going to handle group broadcast signal ...", implicated_cid)))
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
            let mut state_container = inner_mut!(sess.state_container);
            sess.initiate_drill_update(timestamp, virtual_target, &mut state_container, Some(ticket))
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
                return Err(NetworkError::InternalError("Session not found in session manager"))
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
            //log::info!("Attempted to remove a connection that wasn't provisional. Check the program logic ...");
            return;
        }
    }

    /// Deliver a signal to an in-memory mailbox
    pub fn deliver_signal_to_mailbox(&self, target_cid: u64, signal: PeerSignal) -> bool {
        let this = inner!(self);
        this.hypernode_peer_layer.try_add_mailbox(true, target_cid, signal)
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
                        return Err(NetworkError::InvalidExternalRequest("A concurrent registration request between the two peers is already occurring"))
                    }
                }

                let account_manager = this.account_manager.clone();
                std::mem::drop(this);
                (account_manager, tickets)
            };

            let peer_cnac = account_manager.get_client_by_cid(peer_cid).await?.ok_or(NetworkError::InvalidExternalRequest("Peer CID does not exist"))?;
            let (keys, static_aux_ratchet) = {
                let inner = peer_cnac.read();
                let keys = inner.crypt_container.fcm_keys.clone();
                let static_aux_ratchet = inner.crypt_container.toolset.get_static_auxiliary_ratchet().clone();

                (keys, static_aux_ratchet)
            };

            let fcm_instance = FCMInstance::new(keys.ok_or(NetworkError::InvalidExternalRequest("Client cannot receive FCM messages at this time"))?, account_manager.fcm_client().clone());
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
            Err(NetworkError::InvalidExternalRequest("implicated cid == peer_cid"))
        }
    }

    /// Sends to user, but does not block. Once the send is complete, will run ``on_send_complete``, which gives the sender the option to return a packet back to the initiator
    ///
    /// This is usually to send packets to another client who may or may not have an endpoint crypt container yet. It doesn't matter here, since we're only using the base ratchet
    ///
    /// Since the user may or may not be online, we use the static aux ratchet
    #[allow(unused_results)]
    pub async fn fcm_send_to_as_server(&self, implicated_cid: u64, peer_cid: u64, packet_crafter: impl FnOnce(&HyperRatchet) -> RawExternalPacket, on_send_complete: impl FnOnce(Result<(), AccountError>) + ContextRequirements) -> Result<(), NetworkError> {
        let this = inner!(self);
        if implicated_cid != peer_cid {
            let account_manager = this.account_manager.clone();
            std::mem::drop(this);

            let peer_cnac = account_manager.get_client_by_cid(peer_cid).await?.ok_or(NetworkError::InvalidExternalRequest("Peer CID does not exist"))?;
            peer_cnac.visit(|inner| {
                let keys = inner.crypt_container.fcm_keys.clone();
                let static_aux_ratchet = inner.crypt_container.toolset.get_static_auxiliary_ratchet().clone();
                std::mem::drop(inner);

                async move {
                    let fcm_instance = FCMInstance::new(keys.ok_or(NetworkError::InvalidExternalRequest("Client cannot receive FCM messages at this time"))?, account_manager.fcm_client().clone());
                    let packet = packet_crafter(&static_aux_ratchet);
                    on_send_complete(fcm_instance.send_to_fcm_user(packet).await.map(|_| ()));
                    Ok(())
                }
            }).await
        } else {
            Err(NetworkError::InvalidExternalRequest("implicated cid == peer_cid"))
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
    pub fn kick_from_message_group(&self, mode: GroupMemberAlterMode, implicated_cid: u64, timestamp: i64, ticket: Ticket, key: MessageGroupKey, peers: Vec<u64>, security_level: SecurityLevel) -> bool {
        let this = inner!(self);
        match this.hypernode_peer_layer.remove_peers_from_message_group(key, peers) {
            Ok((peers_removed, peers_remaining)) => {
                log::info!("Peers removed: {:?}", &peers_removed);
                // We only notify the members when kicking, not leaving
                if mode != GroupMemberAlterMode::Leave {
                    // notify all the peers removed
                    let signal = GroupBroadcast::Disconnected(key);
                    for peer in &peers_removed {
                        if *peer != implicated_cid {
                            if let Err(err) = this.send_group_broadcast_signal_to(timestamp, ticket, *peer, false, signal.clone(), security_level) {
                                log::warn!("Unable to send group broadcast signal from {} to {}: {}", key.cid, peer, err);
                            }
                        }
                    }
                }

                let signal = GroupBroadcast::MemberStateChanged(key, MemberState::LeftGroup(peers_removed));
                for peer in peers_remaining {
                    if peer != implicated_cid {
                        if let Err(err) = this.send_group_broadcast_signal_to(timestamp, ticket, peer, false, signal.clone(), security_level) {
                            log::warn!("Unable to send group broadcast signal from {} to {}: {}", key.cid, peer, err);
                        }
                    }
                }

                true
            }

            Err(_) => {
                log::error!("Unable to kick peers from message group");
                false
            }
        }
    }

    /// Broadcasts a message to a target group
    /// Note: uses mail_if_offline: true. This allows a member to disconnect, but to still receive messages later-on
    /// In the future, a SQL server should be used to store these messages, as they may get pretty lengthy
    pub fn broadcast_signal_to_group(&self, implicated_cid: u64, timestamp: i64, ticket: Ticket, key: MessageGroupKey, signal: GroupBroadcast, security_level: SecurityLevel) -> bool {
        let this = inner!(self);
        if let Some(peers_to_broadcast_to) = this.hypernode_peer_layer.get_peers_in_message_group(key) {
            for peer in peers_to_broadcast_to {
                // we only broadcast to the peers not equal to the calling one
                if peer != implicated_cid {
                    let signal = signal.clone();
                    if let Err(err) = this.send_group_broadcast_signal_to(timestamp, ticket, peer, true, signal, security_level) {
                        log::warn!("Unable to send group broadcast signal from {} to {}: {}", key.cid, peer, err);
                    }
                }
            }

            true
        } else {
            false
        }
    }

    /// Routes a packet to a session's endpoint. Note: If the calling session's CID
    /// is equal to `cid`, a deadlock will occur.
    ///
    /// Returns true if sent successfully
    pub fn route_packet_to_primary_stream(&self, cid: u64, ticket_opt: Option<Ticket>, packet: BytesMut) -> bool {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&cid) {
            let ref sess = sess.1;
            sess.send_to_primary_stream(ticket_opt, packet).is_ok()
        } else {
            false
        }
    }

    /// sends a signal to the peer using the correct PQC and Drill cryptosystem
    /// NOTE: THIS WILL PANIC if `target_cid` == the implicated cid from the closure that calls this
    pub fn send_signal_to_peer(&self, target_cid: u64, ticket: Ticket, signal: PeerSignal, timestamp: i64, security_level: SecurityLevel) -> bool {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&target_cid) {
            let ref sess = sess.1;
            if let Some(to_primary_stream) = sess.to_primary_stream.as_ref() {
                if let Some(cnac) = sess.cnac.get() {
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

    /// Returns a sink that allows sending data outbound
    pub fn get_handle_to_udp_sender(&self, cid: u64) -> Option<OutboundUdpSender> {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&cid) {
            let ref sess = sess.1;
            let state_container = inner!(sess.state_container);
            state_container.udp_primary_outbound_tx.clone()
        } else {
            None
        }
    }

    /// Returns a sink that allows sending data outbound
    pub fn get_handle_to_tcp_sender(&self, cid: u64) -> Option<OutboundPrimaryStreamSender> {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&cid) {
            let ref sess = sess.1;
            sess.to_primary_stream.clone()
        } else {
            None
        }
    }

    // Returns both UDP and TCP handles (useful for when the server detects that, during the POST_CONNECT response phase,
    // that client B consented to client A.
    pub fn get_tcp_udp_senders(&self, cid: u64) -> Option<(OutboundPrimaryStreamSender, OutboundUdpSender)> {
        let this = inner!(self);
        if let Some(sess) = this.sessions.get(&cid) {
            let ref sess = sess.1;
            let tcp_sender = sess.to_primary_stream.clone()?;
            let state_container = inner!(sess.state_container);
            let udp_sender = state_container.udp_primary_outbound_tx.clone()?;
            Some((tcp_sender, udp_sender))
        } else {
            None
        }
    }

    /// Ensures the mailbox and tracked event queue are loaded into the [PeerLayer]
    pub fn register_session_with_peer_layer(&self, implicated_cid: u64) -> Option<MailboxTransfer> {
        let mut this = inner_mut!(self);
        this.hypernode_peer_layer.register_peer(implicated_cid, false)
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
            let peer_cnac = sess.cnac.get().unwrap();

            let mut state_container = inner_mut!(sess.state_container);
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

    /// Stores the `signal` inside the internal timed-queue for `implicated_cid`, and then sends `packet` to `target_cid`.
/// After `timeout`, the closure `on_timeout` is executed
    #[inline]
    pub async fn route_signal_primary(&self, implicated_cid: u64, target_cid: u64, ticket: Ticket, signal: PeerSignal, packet: impl FnOnce(&HyperRatchet) -> BytesMut, timeout: Duration, on_timeout: impl Fn(PeerSignal) + SyncContextRequirements) -> Result<(), String> {
        let account_manager = {
            let this = inner!(self);

            if implicated_cid == target_cid {
                return Err("Target CID cannot be equal to the implicated CID".to_string());
            }

            let account_manager = this.account_manager.clone();
            std::mem::drop(this);
            account_manager
        };

        if account_manager.hyperlan_cid_is_registered(target_cid).await.map_err(|err| err.into_string())? {
            let this = inner!(self);
            // get the target cid's session
            if let Some(sess) = this.sessions.get(&target_cid) {
                this.hypernode_peer_layer.insert_tracked_posting(implicated_cid, timeout, ticket, signal, on_timeout);
                let ref sess_ref = sess.1;
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let peer_cnac = sess_ref.cnac.get().unwrap();

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
                this.hypernode_peer_layer.insert_tracked_posting(implicated_cid, timeout, ticket, signal.clone(), on_timeout);
                if this.hypernode_peer_layer.try_add_mailbox(true, target_cid, signal) {
                    Ok(())
                } else {
                    Err(format!("Peer {} is offline. Furthermore, that peer's mailbox is not accepting signals at this time", target_cid))
                }
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
                    let _ = sender.try_send(());
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
    pub fn route_signal_response_primary(&self, implicated_cid: u64, target_cid: u64, ticket: Ticket, packet: impl FnOnce(&HyperRatchet) -> BytesMut, post_send: impl FnOnce(&HdpSession, PeerSignal) -> PrimaryProcessorResult) -> Result<PrimaryProcessorResult, String> {
        // Instead of checking for registration, check the `implicated_cid`'s timed queue for a ticket corresponding to Ticket.
        if let Some(tracked_posting) = self.hypernode_peer_layer.remove_tracked_posting(target_cid, ticket) {
            // since the posting was valid, we just need to forward the signal to `implicated_cid`
            if let Some(target_sess) = self.sessions.get(&target_cid) {
                //let ret = target_sess.clone();

                let ref sess_ref = target_sess.1;
                let peer_sender = sess_ref.to_primary_stream.as_ref().unwrap();
                let peer_cnac = sess_ref.cnac.get().unwrap();

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
            let peer_cnac = peer_sess.cnac.get().ok_or_else(|| NetworkError::InternalError("Peer CNAC absent"))?;

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

    /// Sends a [GroupBroadcast] message to `peer_cid`. Ensures the target is mutual before sending
    /// `mail_if_offline`: Deposits mail if the target is offline
    /// NOTE: it is the duty of the calling closure to ensure that the [MessageGroup] exists!
    /// NOTE: This does not check to see if the two peers can send to each other. That is up to the caller to ensure that
    ///
    pub fn send_group_broadcast_signal_to(&self, timestamp: i64, ticket: Ticket, peer_cid: u64, mail_if_offline: bool, signal: GroupBroadcast, security_level: SecurityLevel) -> Result<(), String> {
        if self.send_signal_to_peer_direct(peer_cid, |peer_hyper_ratchet| {
            super::hdp_packet_crafter::peer_cmd::craft_group_message_packet(peer_hyper_ratchet, &signal, ticket, C2S_ENCRYPTION_ONLY, timestamp, security_level)
        }).is_err() {
            if mail_if_offline {
                // TODO: Fcm send
                if !self.hypernode_peer_layer.try_add_mailbox(true, peer_cid, PeerSignal::BroadcastConnected(signal)) {
                        log::warn!("Unable to add broadcast signal to mailbox")
                }
            }
        }

        Ok(())
    }
}