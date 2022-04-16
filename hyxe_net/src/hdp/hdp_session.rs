use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

//use async_std::prelude::*;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt, TryStreamExt, TryFutureExt};
use tokio::time::Instant;
use tokio_util::codec::LengthDelimitedCodec;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::fcm::fcm_ratchet::{FcmAliceToBobTransfer, FcmRatchetConstructor};
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::hyper_ratchet::constructor::{ConstructorType, HyperRatchetConstructor};
use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::toolset::Toolset;
use hyxe_fs::io::SyncIO;
use hyxe_wire::hypernode_type::NodeType;
use netbeam::time_tracker::TimeTracker;
use hyxe_wire::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::external_services::fcm::kem::FcmPostRegister;
use hyxe_user::network_account::ConnectProtocol;
use hyxe_user::auth::proposed_credentials::ProposedCredentials;
use hyxe_user::re_imports::scramble_encrypt_file;

use crate::constants::{DRILL_UPDATE_FREQUENCY_LOW_BASE, FIREWALL_KEEP_ALIVE_UDP, GROUP_EXPIRE_TIME_MS, HDP_HEADER_BYTE_LEN, INITIAL_RECONNECT_LOCKOUT_TIME_NS, KEEP_ALIVE_INTERVAL_MS, KEEP_ALIVE_TIMEOUT_NS, LOGIN_EXPIRATION_TIME};
use crate::error::NetworkError;
use crate::hdp::file_transfer::VirtualFileMetadata;
use crate::hdp::hdp_packet::{HdpPacket, packet_flags};
use crate::hdp::hdp_packet_crafter::{self, GroupTransmitter, RatchetPacketCrafterContainer};
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
//use futures_codec::Framed;
use crate::hdp::hdp_packet_processor::{self, PrimaryProcessorResult};
use crate::hdp::hdp_packet_processor::includes::{Duration, SocketAddr};
use crate::hdp::hdp_node::{ConnectMode, NodeRemote, HdpServerResult, Ticket};
use crate::hdp::hdp_session_manager::HdpSessionManager;
use crate::hdp::misc;
use crate::hdp::misc::clean_shutdown::{CleanShutdownSink, CleanShutdownStream};
use crate::hdp::misc::dual_rwlock::DualRwLock;
use crate::hdp::misc::net::GenericNetworkStream;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
//use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender, channel, TrySendError};
use crate::hdp::outbound_sender::{channel, SendError, unbounded, UnboundedReceiver, UnboundedSender};
use crate::hdp::outbound_sender::{OutboundPrimaryStreamReceiver, OutboundPrimaryStreamSender, OutboundUdpSender};
use crate::hdp::peer::p2p_conn_handler::P2PInboundHandle;
use crate::hdp::peer::peer_layer::{PeerResponse, PeerSignal, UdpMode, HyperNodePeerLayer};
use crate::hdp::session_queue_handler::{DRILL_REKEY_WORKER, FIREWALL_KEEP_ALIVE, KEEP_ALIVE_CHECKER, PROVISIONAL_CHECKER, QueueWorkerResult, QueueWorkerTicket, RESERVED_CID_IDX, SessionQueueWorker, SessionQueueWorkerHandle};
use crate::hdp::state_container::{FileKey, GroupKey, OutboundFileTransfer, OutboundTransmitterContainer, StateContainer, StateContainerInner, VirtualConnectionType, VirtualTargetType};
use crate::hdp::state_subcontainers::drill_update_container::calculate_update_frequency;
use crate::hdp::time::TransferStats;
use hyxe_user::backend::PersistenceHandler;
use crate::hdp::misc::dual_cell::DualCell;
use std::ops::Deref;
use crate::hdp::misc::dual_late_init::DualLateInit;
use crate::kernel::RuntimeFuture;
use std::pin::Pin;
use hyxe_crypt::prelude::ConstructorOpts;
use crate::hdp::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::hdp::hdp_packet_processor::raw_primary_packet::{check_proxy, ReceivePortType};
use crate::hdp::state_subcontainers::preconnect_state_container::UdpChannelSender;
use hyxe_wire::nat_identification::NatType;
use hyxe_wire::exports::NewConnection;
use crate::hdp::misc::udp_internal_interface::{UdpSplittableTypes, UdpStream};
use atomic::Atomic;
use crate::auth::AuthenticationRequest;
use hyxe_wire::exports::tokio_rustls::rustls;

//use crate::define_struct;

// Defines the primary structure which wraps the inner device
//define_outer_struct_wrapper!(HdpSession, HdpSessionInner);


/// Allows a connection stream to be worked on by a single worker
pub struct HdpSession {
    #[cfg(not(feature = "multi-threaded"))]
    pub inner: std::rc::Rc<HdpSessionInner>,
    #[cfg(feature = "multi-threaded")]
    pub inner: std::sync::Arc<HdpSessionInner>,
}

impl HdpSession {
    pub fn strong_count(&self) -> usize {
        #[cfg(not(feature = "multi-threaded"))]
            {
                std::rc::Rc::strong_count(&self.inner)
            }

        #[cfg(feature = "multi-threaded")]
            {
                std::sync::Arc::strong_count(&self.inner)
            }
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn as_weak(&self) -> std::rc::Weak<HdpSessionInner> {
        std::rc::Rc::downgrade(&self.inner)
    }

    #[cfg(feature = "multi-threaded")]
    pub fn as_weak(&self) -> std::sync::Weak<HdpSessionInner> {
        std::sync::Arc::downgrade(&self.inner)
    }

    #[cfg(feature = "multi-threaded")]
    pub fn upgrade_weak(this: &std::sync::Weak<HdpSessionInner>) -> Option<Self> {
        this.upgrade().map(|inner| Self { inner })
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn upgrade_weak(this: &std::rc::Weak<HdpSessionInner>) -> Option<Self> {
        this.upgrade().map(|inner| Self { inner })
    }
}

impl From<HdpSessionInner> for HdpSession {
    fn from(inner: HdpSessionInner) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
            {
                Self { inner: std::rc::Rc::new(inner) }
            }

        #[cfg(feature = "multi-threaded")]
            {
                Self { inner: std::sync::Arc::new(inner) }
            }
    }
}

impl Deref for HdpSession {
    type Target = HdpSessionInner;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl Clone for HdpSession {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}


//define_struct!(HdpSession, HdpSessionInner);

/// Structure for holding and keep track of packets, as well as basic connection information
#[allow(unused)]
pub struct HdpSessionInner {
    pub(super) implicated_cid: DualCell<Option<u64>>,
    pub(super) kernel_ticket: DualCell<Ticket>,
    pub(super) remote_peer: SocketAddr,
    // Sends results directly to the kernel
    pub(super) kernel_tx: UnboundedSender<HdpServerResult>,
    pub(super) to_primary_stream: DualLateInit<Option<OutboundPrimaryStreamSender>>,
    // Setting this will determine what algorithm is used during the DO_CONNECT stage
    pub(super) session_manager: HdpSessionManager,
    pub(super) state: Arc<Atomic<SessionState>>,
    pub(super) state_container: StateContainer,
    pub(super) account_manager: AccountManager,
    pub(super) time_tracker: TimeTracker,
    pub(super) local_node_type: NodeType,
    pub(super) remote_node_type: Option<NodeType>,
    pub(super) local_bind_addr: SocketAddr,
    pub(super) do_static_hr_refresh_atexit: DualCell<bool>,
    pub(super) dc_signal_sender: DualRwLock<Option<UnboundedSender<HdpServerResult>>>,
    pub(super) is_server: bool,
    pub(super) stopper_tx: DualRwLock<tokio::sync::broadcast::Sender<()>>,
    pub(super) queue_handle: DualLateInit<SessionQueueWorkerHandle>,
    pub(super) fcm_keys: Option<FcmKeys>,
    pub(super) peer_only_connect_protocol: DualRwLock<Option<ConnectProtocol>>,
    pub(super) primary_stream_quic_conn: DualRwLock<Option<NewConnection>>,
    pub(super) local_nat_type: NatType,
    pub(super) adjacent_nat_type: DualLateInit<Option<NatType>>,
    pub(super) connect_mode: DualRwLock<Option<ConnectMode>>,
    pub(super) client_config: Arc<rustls::ClientConfig>,
    pub(super) hypernode_peer_layer: HyperNodePeerLayer,
    on_drop: UnboundedSender<()>,
}

/// allows each session worker to check the state of the session
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SessionState {
    /// In impersonal mode, the primary socket may receive a new stream. This category implies that
    /// the next packet should be a welcome packet with information implying if it is already registered
    /// or if it needs to register
    SocketJustOpened,
    /// If the endpoint does not have an implicated CID with the current node, then registration must occur.
    /// This will imply the use of standard encryption to get the hyperencrypted drill over the wire
    NeedsRegister,
    /// The system just initiated, and needs to begin the session
    NeedsConnect,
    /// The system has begun the connection process, and is now waiting for a response from the remote server
    ConnectionProcess,
    /// The hypernode is connected to the remote peer, and can now send information
    Connected,
    /// The hypernode is disconnected. Data cannot flow through
    Disconnected,
}

#[derive(Debug, Clone)]
#[allow(variant_size_differences)]
pub enum HdpSessionInitMode {
    Connect(AuthenticationRequest),
    Register(SocketAddr, ProposedCredentials),
}

impl HdpSession {
    /// Creates a new session.
    /// 'implicated_cid': Supply None if you expect to register. If Some, will check the account manager
    pub(crate) fn new(init_mode: HdpSessionInitMode, local_nat_type: NatType, peer_only_connect_proto: ConnectProtocol, cnac: Option<ClientNetworkAccount>, remote_peer: SocketAddr, proposed_credentials: ProposedCredentials, on_drop: UnboundedSender<()>, hdp_remote: NodeRemote, local_bind_addr: SocketAddr, local_node_type: NodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, time_tracker: TimeTracker, kernel_ticket: Ticket, mut fcm_keys: Option<FcmKeys>, udp_mode: UdpMode, keep_alive_timeout_ns: i64, security_settings: SessionSecuritySettings, connect_mode: Option<ConnectMode>, client_config: Arc<rustls::ClientConfig>, hypernode_peer_layer: HyperNodePeerLayer) -> Result<(tokio::sync::broadcast::Sender<()>, Self), NetworkError> {
        let (cnac, state, implicated_cid) = match &init_mode {
            HdpSessionInitMode::Connect(auth) => {
                match auth {
                    AuthenticationRequest::Credentialed { .. } => {
                        let cnac = cnac.ok_or(NetworkError::InvalidRequest("Client does not exist"))?;
                        let cid = cnac.get_cid();
                        fcm_keys = fcm_keys.or_else(|| cnac.get_fcm_keys()); // use the provided FCM, otherwise, use the default FCM keys
                        (Some(cnac), Arc::new(Atomic::new(SessionState::NeedsConnect)), Some(cid))
                    }

                    AuthenticationRequest::Passwordless { .. } => {
                        // register will redirect to preconnect afterwords
                        (None, Arc::new(Atomic::new(SessionState::NeedsRegister)), None)
                    }
                }
            }

            HdpSessionInitMode::Register(..) => {
                (None, Arc::new(Atomic::new(SessionState::NeedsRegister)), None)
            }
        };

        let timestamp = time_tracker.get_global_time_ns();
        let (stopper_tx, _stopper_rx) = tokio::sync::broadcast::channel(10);

        let mut inner = HdpSessionInner {
            hypernode_peer_layer,
            connect_mode: DualRwLock::from(connect_mode),
            primary_stream_quic_conn: DualRwLock::from(None),
            local_nat_type,
            adjacent_nat_type: DualLateInit::default(),
            do_static_hr_refresh_atexit: true.into(),
            dc_signal_sender: DualRwLock::from(Some(kernel_tx.clone())),
            peer_only_connect_protocol: Some(peer_only_connect_proto).into(),
            on_drop,
            local_bind_addr,
            local_node_type,
            remote_node_type: None,
            kernel_tx: kernel_tx.clone(),
            implicated_cid: DualCell::new(implicated_cid),
            time_tracker,
            kernel_ticket: kernel_ticket.into(),
            to_primary_stream: DualLateInit::default(),
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, keep_alive_timeout_ns, state.clone(), cnac, time_tracker.clone(), Some(security_settings), false,TransferStats::new(timestamp, 0), udp_mode),
            session_manager,
            remote_peer,
            state,
            account_manager,
            is_server: false,
            stopper_tx: stopper_tx.clone().into(),
            queue_handle: DualLateInit::default(),
            fcm_keys,
            client_config
        };

        inner.store_proposed_credentials(proposed_credentials);

        Ok((stopper_tx, Self::from(inner)))
    }

    /// During impersonal mode, a new connection may come inbound. Unlike above in Self::new, we do not yet have the implicated cid nor nid.
    /// We must then expect a welcome packet
    ///
    /// When this is called, the connection is implied to be in impersonal mode. As such, the calling closure should have a way of incrementing
    /// the provisional ticket.
    pub(crate) fn new_incoming(on_drop: UnboundedSender<()>, local_nat_type: NatType, hdp_remote: NodeRemote, local_bind_addr: SocketAddr, local_node_type: NodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, time_tracker: TimeTracker, remote_peer: SocketAddr, provisional_ticket: Ticket, client_config: Arc<rustls::ClientConfig>, hypernode_peer_layer: HyperNodePeerLayer) -> (tokio::sync::broadcast::Sender<()>, Self) {
        let (stopper_tx, _stopper_rx) = tokio::sync::broadcast::channel(10);
        let state = Arc::new(Atomic::new(SessionState::SocketJustOpened));

        let timestamp = time_tracker.get_global_time_ns();

        let inner = HdpSessionInner {
            hypernode_peer_layer,
            connect_mode: DualRwLock::from(None),
            primary_stream_quic_conn: DualRwLock::from(None),
            local_nat_type,
            adjacent_nat_type: DualLateInit::default(),
            do_static_hr_refresh_atexit: true.into(),
            dc_signal_sender: DualRwLock::from(Some(kernel_tx.clone())),
            peer_only_connect_protocol: None.into(),
            on_drop,
            local_bind_addr,
            local_node_type,
            remote_node_type: None,
            implicated_cid: DualCell::new(None),
            time_tracker,
            kernel_ticket: provisional_ticket.into(),
            remote_peer,
            kernel_tx: kernel_tx.clone(),
            session_manager: session_manager.clone(),
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, KEEP_ALIVE_TIMEOUT_NS, state.clone(), None, time_tracker.clone(), None, true,TransferStats::new(timestamp, 0), UdpMode::Disabled),
            to_primary_stream: DualLateInit::default(),
            state,
            account_manager,
            is_server: true,
            stopper_tx: stopper_tx.clone().into(),
            queue_handle: DualLateInit::default(),
            fcm_keys: None,
            client_config
        };

        (stopper_tx, Self::from(inner))
    }

    /// Once the [HdpSession] is created, it can then be executed to begin handling a periodic connection handler.
    /// This will automatically stop running once the internal state is set to Disconnected
    ///
    /// `tcp_stream`: this goes to the adjacent HyperNode
    /// `p2p_listener`: This is TCP listener bound to the same local_addr as tcp_stream. Required for TCP hole-punching
    pub async fn execute(&self, mut primary_stream: GenericNetworkStream, peer_addr: SocketAddr) -> Result<Option<u64>, (NetworkError, Option<u64>)> {
        log::info!("HdpSession is executing ...");
        let this = self.clone();
        let this_outbound = self.clone();
        let this_inbound = self.clone();
        let this_queue_worker = self.clone();
        let this_close = self.clone();

        let (session_future, handle_zero_state, implicated_cid) = {
            let quic_conn_opt = primary_stream.take_quic_connection();
            let (writer, reader) = misc::net::safe_split_stream(primary_stream);

            let (primary_outbound_tx, primary_outbound_rx) = unbounded();
            let primary_outbound_tx = OutboundPrimaryStreamSender::from(primary_outbound_tx);
            let primary_outbound_rx = OutboundPrimaryStreamReceiver::from(primary_outbound_rx);

            // if the primary stream uses QUIC, load this inside for both client and server
            if let Some(quic_conn) = quic_conn_opt {
                *inner_mut!(this.primary_stream_quic_conn) = Some(quic_conn);
            }


            //let (obfuscator, packet_opt) = HeaderObfuscator::new(this.is_server);
            //let sess_id = this_ref.kernel_ticket;

            this.to_primary_stream.set_once(Some(primary_outbound_tx.clone()));

            let timestamp = this.time_tracker.get_global_time_ns();
            let local_nid = this.account_manager.get_local_nid();
            let cnac_opt = inner_state!(this.state_container).cnac.clone();
            let implicated_cid = this.implicated_cid.clone();
            let persistence_handler = this.account_manager.get_persistence_handler().clone();

            let stopper = inner!(this.stopper_tx).subscribe();

            // Ensure the tx forwards to the writer
            let writer_future = Self::outbound_stream(primary_outbound_rx, writer);
            let reader_future = Self::execute_inbound_stream(reader, this_inbound, None);
            //let timer_future = Self::execute_timer(this.clone());
            let queue_worker_future = Self::execute_queue_worker(this_queue_worker);
            let stopper_future = Self::stopper(stopper);
            let handle_zero_state = Self::handle_zero_state(None, persistence_handler, primary_outbound_tx.clone(), this_outbound, this.state.load(Ordering::SeqCst), timestamp, local_nid, cnac_opt);

            let session_future = spawn_handle!(async move {
                            tokio::select! {
                                res0 = writer_future => res0,
                                res1 = reader_future => res1,
                                res2 = stopper_future => res2
                            }
                        });

            //let session_future = futures::future::try_join4(writer_future, reader_future, timer_future, socket_loader_future);


            // this will automatically drop when getting polled, because it tries upgrading a Weak reference to the session
            // as such, if it cannot, it will end the future. We do this to ensure there is no deadlocking.
            // We now spawn this future independently in order to fix a deadlocking bug in multi-threaded mode. By spawning a
            // separate task, we solve the issue of re-entrancing of mutex
            //#[cfg(feature = "multi-threaded")]
            let _ = spawn!(queue_worker_future);

            (session_future, handle_zero_state, implicated_cid)
        };


        if let Err(err) = handle_zero_state.await {
            log::error!("Unable to proceed past session zero-state. Stopping session: {:?}", &err);
            return Err((err, implicated_cid.get()));
        }

        let res = session_future.await.map_err(|err| (NetworkError::Generic(err.to_string()), None))?;

        match res {
            Ok(_) => {
                log::info!("Done EXECUTING sess (Ok(())) | cid: {:?} | is_server: {}", this_close.implicated_cid.get(), this_close.is_server);
                Ok(implicated_cid.get())
            }

            Err(err) => {
                let ticket = this_close.kernel_ticket.get();
                let reason = err.to_string();
                let cid = implicated_cid.get();

                log::info!("Session {} connected to {} is ending! Reason: {}. (strong count: {})", ticket.0, peer_addr, reason.as_str(), this_close.strong_count());

                this_close.send_session_dc_signal(Some(ticket), false, "Inbound stream ending");

                Err((err, cid))
            }
        }
    }

    async fn stopper(mut receiver: tokio::sync::broadcast::Receiver<()>) -> Result<(), NetworkError> {
        receiver.recv().await.map_err(|err| NetworkError::Generic(err.to_string()))?;
        Err(NetworkError::InternalError("Session stopper-rx triggered"))
    }

    /// Executes each session in parallel (or concurrent if using a LocalSet)
    pub async fn session_future_receiver(mut p2p_session_rx: UnboundedReceiver<Pin<Box<dyn RuntimeFuture>>>) -> Result<(), NetworkError> {
        while let Some(session) = p2p_session_rx.recv().await {
            let _ = spawn!(session);
        }

        Ok(())
    }

    /// Before going through the usual loopy business, check to see if we need to initiate either a stage0 REGISTER or CONNECT packet
    async fn handle_zero_state(zero_packet: Option<BytesMut>, persistence_handler: PersistenceHandler, to_outbound: OutboundPrimaryStreamSender, session: HdpSession, state: SessionState, timestamp: i64, local_nid: u64, cnac: Option<ClientNetworkAccount>) -> Result<(), NetworkError> {
        if let Some(zero) = zero_packet {
            to_outbound.unbounded_send(zero).map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;
        }

        match state {
            SessionState::NeedsRegister => {
                log::info!("Beginning registration subroutine!");
                let potential_cids_alice = persistence_handler.client_only_generate_possible_cids().await.map_err(|err| NetworkError::Generic(err.into_string()))?;
                let session_ref = session;
                let mut state_container = inner_mut_state!(session_ref.state_container);
                let session_security_settings = state_container.session_security_settings.clone().unwrap();
                let passwordless = state_container.register_state.passwordless.clone().ok_or_else(|| NetworkError::InternalError("Passwordless state not loaded"))?;
                // we supply 0,0 for cid and new drill vers by default, even though it will be reset by bob
                let alice_constructor = HyperRatchetConstructor::new_alice(ConstructorOpts::new_vec_init(Some(session_security_settings.crypto_params), (session_security_settings.security_level.value() + 1) as usize), 0, 0, Some(session_security_settings.security_level)).ok_or(NetworkError::InternalError("Unable to construct Alice ratchet"))?;

                state_container.register_state.last_packet_time = Some(Instant::now());
                let transfer = alice_constructor.stage0_alice();

                let stage0_register_packet = crate::hdp::hdp_packet_crafter::do_register::craft_stage0(session_security_settings.crypto_params.into(), timestamp, local_nid, transfer, potential_cids_alice, passwordless);
                if let Err(err) = to_outbound.unbounded_send(stage0_register_packet).map_err(|_| NetworkError::InternalError("Writer stream corrupted")) {
                    return Err(err);
                }

                state_container.register_state.constructor = Some(alice_constructor);
                log::info!("Successfully sent stage0 register packet outbound");
            }

            SessionState::NeedsConnect => {
                Self::begin_connect(&session, cnac.as_ref().unwrap())?;
            }

            // This implies this node received a new incoming connection. It is up to the other node, Alice, to send a stage 0 packet
            SessionState::SocketJustOpened => {
                log::info!("No actions needed on primary TCP port; beginning outbound listening subroutine ...");
                // If somebody makes a connection to this node, but doesn't send anything, we need a way to remove
                // such a stale connection. By setting the value below, we ensure the possibility that the session
                // timer removes it
                inner_mut_state!(session.state_container).connect_state.last_packet_time = Some(Instant::now());
            }

            _ => {
                log::error!("Invalid initial state. Check program logic");
                std::process::exit(-1);
            }
        }

        Ok(())
    }

    pub(crate) fn begin_connect(session: &HdpSession, cnac: &ClientNetworkAccount) -> Result<(), NetworkError> {
        log::info!("Beginning pre-connect subroutine!");
        let session_ref = session;
        let connect_mode = inner!(session.connect_mode).clone().ok_or_else(||NetworkError::InternalError("Connect mode not loaded"))?;
        let mut state_container = inner_mut_state!(session_ref.state_container);

        let udp_mode = state_container.udp_mode;
        let timestamp = session_ref.time_tracker.get_global_time_ns();
        let session_security_settings = state_container.session_security_settings.clone().unwrap();
        let peer_only_connect_mode = session_ref.peer_only_connect_protocol.get().unwrap();
        // reset the toolset's ARA
        let ref static_aux_hr = cnac.refresh_static_hyper_ratchet();
        // security level inside static hr may not be what the declared session security level for this session is. Session security level can be no higher than the initial static HR level, since the chain requires recursion from the initial value
        let _ = static_aux_hr.verify_level(Some(session_security_settings.security_level)).map_err(|err| NetworkError::Generic(err.into_string()))?;
        let opts = static_aux_hr.get_next_constructor_opts().into_iter().take((session_security_settings.security_level.value() + 1) as usize).collect();
        //static_aux_hr.verify_level(Some(security_level)).map_err(|_| NetworkError::Generic(format!("Invalid security level. Maximum security level for this account is {:?}", static_aux_hr.get_default_security_level())))?;
        let alice_constructor = HyperRatchetConstructor::new_alice(opts, cnac.get_cid(), 0, Some(session_security_settings.security_level)).ok_or(NetworkError::InternalError("Unable to construct Alice ratchet"))?;
        let transfer = alice_constructor.stage0_alice();
        let max_usable_level = static_aux_hr.get_default_security_level();
        let nat_type = session_ref.local_nat_type.clone();

        if udp_mode == UdpMode::Enabled {
            state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
        }

        // NEXT STEP: check preconnect, and update internal security-level recv side to the security level found in transfer to ensure all future packages are at that security-level
        let syn = hdp_packet_crafter::pre_connect::craft_syn(static_aux_hr, transfer, nat_type, udp_mode, timestamp, state_container.keep_alive_timeout_ns, max_usable_level, session_security_settings, peer_only_connect_mode, connect_mode);

        state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
        state_container.pre_connect_state.constructor = Some(alice_constructor);
        state_container.connect_state.connect_mode = Some(connect_mode);

        session.send_to_primary_stream(None, syn)?;

        log::info!("Successfully sent SYN pre-connect packet");
        Ok(())
    }

    // tcp_conn_awaiter must be provided in order to know when the begin loading the UDP conn for the user. The TCP connection must first be loaded in order to place the udp conn inside the virtual_conn hashmap
    pub(crate) fn udp_socket_loader(this: HdpSession, v_target: VirtualTargetType, udp_conn: UdpSplittableTypes, addr: TargettedSocketAddr, ticket: Ticket, tcp_conn_awaiter: Option<tokio::sync::oneshot::Receiver<()>>) {
        let this_weak = this.as_weak();
        std::mem::drop(this);
        let task = async move {
            let (listener, udp_sender_future, stopper_rx) = {
                let this = HdpSession::upgrade_weak(&this_weak).ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let sess = this;

                // we supply the natted ip since it is where we expect to receive packets
                // whether local is server or not, we should expect to receive packets from natted
                let hole_punched_socket = addr.receive_address;
                let hole_punched_addr_ip = hole_punched_socket.ip();

                let local_bind_addr = udp_conn.local_addr().unwrap();

                let (outbound_sender_tx, outbound_sender_rx) = unbounded();
                let udp_sender = OutboundUdpSender::new(outbound_sender_tx, local_bind_addr, hole_punched_socket);
                let (stopper_tx, stopper_rx) = tokio::sync::oneshot::channel::<()>();

                std::mem::drop(sess);
                if let Some(tcp_conn_awaiter) = tcp_conn_awaiter {
                    tcp_conn_awaiter.await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                }

                let sess = HdpSession::upgrade_weak(&this_weak).ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let accessor = match v_target {
                    VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => {
                        let mut state_container = inner_mut_state!(sess.state_container);
                        state_container.udp_primary_outbound_tx = Some(udp_sender.clone());

                        if let Some(channel) = state_container.insert_udp_channel(C2S_ENCRYPTION_ONLY, v_target, ticket, udp_sender, stopper_tx) {
                            let cnac = state_container.cnac.clone().ok_or(NetworkError::InternalError("CNAC not loaded (required for UDP socket_loader stage)"))?;
                            if let Some(sender) = state_container.pre_connect_state.udp_channel_oneshot_tx.tx.take() {
                                sender.send(channel).map_err(|_| NetworkError::InternalError("Unable to send UdpChannel through"))?;
                                EndpointCryptoAccessor::C2S(cnac, sess.state_container.clone())
                            } else {
                                log::error!("Tried loading UDP channel, but, the state container had no UDP sender");
                                return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"))
                            }
                        } else {
                            log::error!("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                            return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."))
                        }
                    }

                    VirtualConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => {
                        let mut state_container = inner_mut_state!(sess.state_container);
                        if let Some(channel) = state_container.insert_udp_channel(target_cid, v_target, ticket, udp_sender, stopper_tx) {
                            if let Some(kem_state) = state_container.peer_kem_states.get_mut(&target_cid) {
                                // Below will fail if UDP mode is off, as desired
                                if let Some(sender) = kem_state.udp_channel_sender.tx.take() {
                                    // below will fail if the user drops the receiver at the kernel-level
                                    sender.send(channel).map_err(|_| NetworkError::InternalError("Unable to send UdpChannel through"))?;
                                    EndpointCryptoAccessor::P2P(target_cid, sess.state_container.clone())
                                } else {
                                    log::error!("Tried loading UDP channel, but, the state container had no UDP sender");
                                    return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"))
                                }
                            } else {
                                log::error!("Tried loading the peer kem state, but was absent");
                                return Err(NetworkError::InternalError("Tried loading the peer kem state, but was absent"))
                            }
                        } else {
                            log::error!("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                            return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."))
                        }
                    }

                    _ => {
                        return Err(NetworkError::InternalError("Invalid virtual target"));
                    }
                };

                // unlike TCP, we will not use [LengthDelimitedCodec] because there is no guarantee that packets
                // will arrive in order
                let (writer, reader) = udp_conn.split();

                let listener = Self::listen_wave_port(sess.clone(), hole_punched_addr_ip, local_bind_addr.port(), reader, accessor.clone());

                log::info!("Server established UDP Port {}", local_bind_addr);

                //futures.push();
                let udp_sender_future = Self::udp_outbound_sender(outbound_sender_rx, addr, writer, accessor);
                (listener, udp_sender_future, stopper_rx)
            };

            log::info!("[Q-UDP] Initiated UDP subsystem...");

            let stopper = async move {
                stopper_rx.await.map_err(|err| NetworkError::Generic(err.to_string()))
            };

            tokio::select! {
                res0 = listener => res0,
                res1 = udp_sender_future => res1,
                res2 = stopper => res2
            }
        };

        let _ = spawn!(task);
    }

    pub async fn outbound_stream(primary_outbound_rx: OutboundPrimaryStreamReceiver, writer: CleanShutdownSink<GenericNetworkStream, LengthDelimitedCodec, Bytes>) -> Result<(), NetworkError> {
        primary_outbound_rx.0.map(|r| Ok(r.freeze())).forward(writer).map_err(|err| NetworkError::Generic(err.to_string())).await
    }

    /// NOTE: We need to have at least one owning/strong reference to the session. Having the inbound stream own a single strong count makes the most sense
    pub async fn execute_inbound_stream(mut reader: CleanShutdownStream<GenericNetworkStream, LengthDelimitedCodec, Bytes>, ref this_main: HdpSession, p2p_handle: Option<P2PInboundHandle>) -> Result<(), NetworkError> {
        log::info!("HdpSession async inbound-stream subroutine executed");
        let (ref remote_peer, ref local_primary_port, ref implicated_cid, ref kernel_tx, ref primary_stream, p2p) = if let Some(p2p) = p2p_handle {
            (p2p.remote_peer, p2p.local_bind_port, p2p.implicated_cid, p2p.kernel_tx, p2p.to_primary_stream, true)
        } else {
            let borrow = this_main;
            let remote_peer = borrow.remote_peer.clone();
            let local_primary_port = borrow.local_bind_addr.port();
            let implicated_cid = borrow.implicated_cid.clone();
            let kernel_tx = borrow.kernel_tx.clone();
            let primary_stream = borrow.to_primary_stream.clone().unwrap();
            (remote_peer, local_primary_port, implicated_cid, kernel_tx, primary_stream, false)
        };

        fn evaulute_result(result: Result<PrimaryProcessorResult, NetworkError>, primary_stream: &OutboundPrimaryStreamSender, kernel_tx: &UnboundedSender<HdpServerResult>) -> std::io::Result<()> {
            match result {
                Ok(PrimaryProcessorResult::ReplyToSender(return_packet)) => {
                    HdpSession::send_to_primary_stream_closure(primary_stream, kernel_tx, return_packet, None)
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.into_string()))
                }

                Err(reason) => {
                    log::error!("[PrimaryProcessor] session ending: {:?}", reason);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, reason.into_string()))
                }

                Ok(PrimaryProcessorResult::EndSession(reason)) => {
                    log::warn!("[PrimaryProcessor] session ending: {}", reason);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, reason))
                }

                Ok(PrimaryProcessorResult::Void) => {
                    // this implies that the packet processor found no reason to return a message
                    Ok(())
                }
            }
        }

        fn handle_session_terminating_error(err: std::io::Error, is_server: bool, p2p: bool) -> NetworkError {
            const _WINDOWS_FORCE_SHUTDOWN: i32 = 10054;
            const _RST: i32 = 104;
            const _ECONN_RST: i32 = 54; // for macs

            let error = err.raw_os_error().unwrap_or(-1);
            // error != WINDOWS_FORCE_SHUTDOWN && error != RST && error != ECONN_RST &&
            if error != -1 {
                log::error!("primary port reader error {}: {}. is server: {}. P2P: {}", error, err.to_string(), is_server, p2p);
            }

            NetworkError::Generic(err.to_string())
        }

        let (ref async_processor_tx, mut async_processor_rx) = tokio::sync::mpsc::unbounded_channel();

        let inbound_direct = async move {
            while let Some(packet) = reader.next().await {
                let packet = packet.map_err(|err| NetworkError::Generic(err.to_string()))?;

                if let Err(err) = evaulute_result(hdp_packet_processor::raw_primary_packet::process(implicated_cid.get(), this_main, remote_peer.clone(), *local_primary_port, packet, async_processor_tx), primary_stream, kernel_tx) {
                    return Err(handle_session_terminating_error(err, this_main.is_server, p2p))
                }
            }

            Ok(())
        };

        let futures_concurrent_executor = async move {
            let reader = async_stream::stream! {
                while let Some(value) = async_processor_rx.recv().await {
                    yield Ok(value);
                }
            };

            reader.try_for_each_concurrent(None, move |future| {
                async move {
                    evaulute_result(future.await, primary_stream, kernel_tx)
                }
            }).await.map_err(|err| {
                handle_session_terminating_error(err, this_main.is_server, p2p)
            })
        };

        tokio::select! {
            res0 = inbound_direct => res0,
            res1 = futures_concurrent_executor => res1
        }
    }

    pub(crate) fn send_to_primary_stream_closure(to_primary_stream: &OutboundPrimaryStreamSender, kernel_tx: &UnboundedSender<HdpServerResult>, msg: BytesMut, ticket: Option<Ticket>) -> Result<(), NetworkError> {
        if let Err(err) = to_primary_stream.unbounded_send(msg) {
            kernel_tx.unbounded_send(HdpServerResult::InternalServerError(ticket, err.to_string())).map_err(|err| NetworkError::Generic(err.to_string()))?;
            Err(NetworkError::InternalError("Primary stream closed"))
        } else {
            Ok(())
        }
    }

    async fn execute_queue_worker(this_main: HdpSession) -> Result<(), NetworkError> {
        log::info!("HdpSession async timer subroutine executed");

        let queue_worker = {
            //let this_interval = this_main.clone();
            let borrow = this_main;
            let (mut queue_worker, sender) = SessionQueueWorker::new(borrow.stopper_tx.get());
            inner_mut_state!(borrow.state_container).queue_handle.set_once(sender.clone());
            borrow.queue_handle.set_once(sender);

            queue_worker.load_state_container(borrow.state_container.clone());
            let time_tracker = borrow.time_tracker.clone();
            let time_tracker_2 = time_tracker.clone();

            let kernel_ticket = borrow.kernel_ticket.get();
            let is_server = borrow.is_server;
            std::mem::drop(borrow);

            // now, begin loading the subroutines
            //let mut loop_idx = 0;
            queue_worker.insert_reserved_fn(Some(QueueWorkerTicket::Oneshot(PROVISIONAL_CHECKER, RESERVED_CID_IDX)), LOGIN_EXPIRATION_TIME, |state_container| {
                if state_container.state.load(Ordering::SeqCst) != SessionState::Connected {
                    QueueWorkerResult::EndSession
                } else {
                    // remove it from being called again
                    QueueWorkerResult::Complete
                }
            });

            if !is_server {
                queue_worker.insert_reserved_fn(Some(QueueWorkerTicket::Periodic(DRILL_REKEY_WORKER, 0)), Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE), move |state_container| {
                    let time_tracker = time_tracker.clone();
                    let ticket = kernel_ticket;

                    if state_container.state.load(Ordering::Relaxed) == SessionState::Connected {
                        let timestamp = time_tracker.get_global_time_ns();

                        let security_level = state_container.session_security_settings.as_ref().map(|r| r.security_level).clone().unwrap();

                        let p2p_sessions = state_container.active_virtual_connections.iter().filter_map(|vconn| {
                            if vconn.1.endpoint_container.as_ref()?.endpoint_crypto.local_is_initiator && vconn.1.is_active.load(Ordering::SeqCst) && vconn.1.last_delivered_message_timestamp.load(Ordering::SeqCst).map(|r| r.elapsed() > Duration::from_millis(15000)).unwrap_or(true) {
                                Some(vconn.1.connection_type)
                            } else {
                                None
                            }
                        }).collect::<Vec<VirtualTargetType>>();

                        let virtual_target = VirtualTargetType::HyperLANPeerToHyperLANServer(C2S_ENCRYPTION_ONLY);
                        if let Ok(_) = state_container.initiate_drill_update(timestamp, virtual_target, Some(ticket)) {
                            // now, call for each p2p session
                            for vconn in p2p_sessions {
                                if let Err(err) = state_container.initiate_drill_update(timestamp, vconn, None) {
                                    log::warn!("Unable to initiate drill update for {:?}: {:?}", vconn, err);
                                }
                            }

                            QueueWorkerResult::AdjustPeriodicity(calculate_update_frequency(security_level.value(), &state_container.transfer_stats))
                        } else {
                            log::warn!("initiate_drill_update subroutine signalled failure");
                            QueueWorkerResult::EndSession
                        }
                    } else {
                        QueueWorkerResult::Incomplete
                    }
                });
            }

            queue_worker.insert_reserved_fn(Some(QueueWorkerTicket::Periodic(KEEP_ALIVE_CHECKER, 0)), Duration::from_millis(KEEP_ALIVE_INTERVAL_MS), move |state_container| {
                let timestamp = time_tracker_2.get_global_time_ns();
                if state_container.state.load(Ordering::SeqCst) == SessionState::Connected {
                    if state_container.keep_alive_timeout_ns != 0 {
                        if state_container.keep_alive_subsystem_timed_out(timestamp) && state_container.meta_expiry_state.expired() {
                            log::error!("The keep alive subsystem has timed out. Executing shutdown phase (skipping proper disconnect)");
                            QueueWorkerResult::EndSession
                        } else {
                            QueueWorkerResult::Incomplete
                        }
                    } else {
                        log::error!("Keep alive subsystem will not be used for this session as requested");
                        QueueWorkerResult::Complete
                    }
                } else {
                    // keep it running, as we may be in provisional mode
                    QueueWorkerResult::Incomplete
                }
            });

            // TODO: Rework UDP keep-alive subsystem to take QUIC into consideration.
            // QUIC already handles KA, but raw udp does not
            queue_worker.insert_reserved_fn(Some(QueueWorkerTicket::Periodic(FIREWALL_KEEP_ALIVE, 0)), FIREWALL_KEEP_ALIVE_UDP, move |state_container| {
                if state_container.state.load(Ordering::SeqCst) == SessionState::Connected {
                    if state_container.udp_mode == UdpMode::Disabled {
                        //log::info!("TCP only mode detected. Removing FIREWALL_KEEP_ALIVE subroutine");
                        return QueueWorkerResult::Complete;
                    }

                    let _ = state_container.udp_primary_outbound_tx.as_ref().unwrap().send_keep_alive();
                }

                QueueWorkerResult::Incomplete
            });

            queue_worker
        };

        //std::mem::drop(this_main);
        queue_worker.await
    }

    /// Similar to process_outbound_packet, but optimized to handle files
    // TODO: Reduce cognitive complexity
    pub fn process_outbound_file(&self, ticket: Ticket, max_group_size: Option<usize>, file: PathBuf, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let this = self;

        if this.state.load(Ordering::Relaxed) != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send data (ticket: {}, file: {:?}) outbound, but the session is not connected", ticket, file)))
        } else {
            // TODO: When io_uring is released for tokio, use async io
            if let Ok(std_file) = std::fs::File::open(&file) {
                let file_name = file.file_name().ok_or(NetworkError::InternalError("Invalid filename"))?.to_str().ok_or(NetworkError::InternalError("Invalid filename"))?;
                let file_name = String::from(file_name);
                let time_tracker = this.time_tracker.clone();
                let timestamp = this.time_tracker.get_global_time_ns();
                let (group_sender, group_sender_rx) = channel(5);
                let mut group_sender_rx = tokio_stream::wrappers::ReceiverStream::new(group_sender_rx);
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                // the above are the same for all vtarget types. Now, we need to get the proper drill and pqc

                let mut state_container = inner_mut_state!(this.state_container);
                let cnac = state_container.cnac.clone().ok_or(NetworkError::InvalidRequest("CNAC not loaded"))?;

                log::info!("Transmit file name: {}", &file_name);
                // the key cid must be differentiated from the target cid because the target_cid needs to be zero if
                // there is no proxying. the key cid cannot be zero; if client -> server, key uses implicated cid
                let (to_primary_stream, file_header, object_id, target_cid, key_cid, groups_needed) = match virtual_target {
                    VirtualTargetType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                        // if we are sending this just to the HyperLAN server (in the case of file uploads),
                        // then, we use this session's pqc, the cnac's latest drill, and 0 for target_cid
                        cnac.visit_mut(|mut inner| -> Result<_, NetworkError> {
                            let object_id = inner.crypt_container.get_and_increment_object_id();
                            let group_id_start = inner.crypt_container.get_and_increment_group_id();
                            let latest_hr = inner.crypt_container.get_hyper_ratchet(None).cloned().unwrap();

                            let to_primary_stream = this.to_primary_stream.clone().unwrap();
                            let target_cid = 0;
                            let (file_size, groups_needed) = scramble_encrypt_file(std_file, max_group_size, object_id, group_sender, stop_rx, security_level, latest_hr.clone(), HDP_HEADER_BYTE_LEN, target_cid, group_id_start, hdp_packet_crafter::group::craft_wave_payload_packet_into)
                                .map_err(|err| NetworkError::Generic(err.to_string()))?;

                            let file_metadata = VirtualFileMetadata {
                                object_id,
                                name: file_name,
                                date_created: "".to_string(),
                                author: inner.auth_store.full_name().to_string(),
                                plaintext_length: file_size,
                                group_count: groups_needed,
                            };

                            // if 1 group, we don't need to reserve any more group IDs. If 2, then we reserve just one. 3, then 2
                            let amt_to_reserve = groups_needed - 1;
                            inner.crypt_container.rolling_group_id += amt_to_reserve as u64;
                            let file_header = hdp_packet_crafter::file::craft_file_header_packet(&latest_hr, group_id_start, ticket, security_level, virtual_target, file_metadata, timestamp);
                            Ok((to_primary_stream, file_header, object_id, target_cid, implicated_cid, groups_needed))
                        })?
                    }

                    VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                        log::info!("Sending HyperLAN peer ({}) <-> HyperLAN Peer ({})", implicated_cid, target_cid);
                        // here, we don't use the base session's PQC. Instead, we use the vconn's pqc and
                        if let Some(vconn) = state_container.active_virtual_connections.get_mut(&target_cid) {
                            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                                let object_id = endpoint_container.endpoint_crypto.get_and_increment_object_id();
                                // reserve group ids
                                let start_group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();

                                let latest_usable_ratchet = endpoint_container.endpoint_crypto.get_hyper_ratchet(None).unwrap();

                                let preferred_primary_stream = endpoint_container.get_direct_p2p_primary_stream().cloned().unwrap_or_else(|| this.to_primary_stream.clone().unwrap());

                                let (file_size, groups_needed) = scramble_encrypt_file(std_file, max_group_size, object_id, group_sender, stop_rx, security_level, latest_usable_ratchet.clone(), HDP_HEADER_BYTE_LEN, target_cid, start_group_id, hdp_packet_crafter::group::craft_wave_payload_packet_into)
                                    .map_err(|err| NetworkError::Generic(err.to_string()))?;

                                let file_metadata = VirtualFileMetadata {
                                    object_id,
                                    name: file_name,
                                    date_created: "".to_string(),
                                    author: "".to_string(),
                                    plaintext_length: file_size,
                                    group_count: groups_needed,
                                };

                                let file_header = hdp_packet_crafter::file::craft_file_header_packet(latest_usable_ratchet, start_group_id, ticket, security_level, virtual_target, file_metadata, timestamp);

                                // if 1 group, we don't need to reserve any more group IDs. If 2, then we reserve just one. 3, then 2
                                let amt_to_reserve = groups_needed - 1;
                                endpoint_container.endpoint_crypto.rolling_group_id += amt_to_reserve as u64;

                                (preferred_primary_stream, file_header, object_id, target_cid, target_cid, groups_needed)
                            } else {
                                log::error!("Endpoint container not found");
                                return Err(NetworkError::InternalError("Endpoint container not found"));
                            }
                        } else {
                            log::error!("Unable to find active vconn for the channel");
                            return Err(NetworkError::InternalError("Virtual connection not found for channel"));
                        }
                    }

                    _ => {
                        log::error!("HyperWAN functionality not yet implemented");
                        return Err(NetworkError::InternalError("HyperWAN functionality not yet implemented"));
                    }
                };

                // now that the async cryptscrambler tasks have been spawned on the threadpool, we need to also
                // spawn tasks that read the [GroupSenders] from there. We also need to store an [OutboundFileMetadataTransmitter]
                // to store the stopper. After spawning them, the rest is under control. Note: for the async task that spawns here
                // should be given a Rc<RefCell<StateContainer>>. Finally, since two vpeers may send to the source we are sending
                // to, the GROUP HEADER ACK needs to return the group start idx. It is expected the adjacent node reserve enough groups
                // on its end to take into account

                // send the FILE_HEADER
                to_primary_stream.unbounded_send(file_header).map_err(|_| NetworkError::InternalError("Primary stream disconnected"))?;
                // create the outbound file container
                let kernel_tx = state_container.kernel_tx.clone();
                let (next_gs_alerter, next_gs_alerter_rx) = unbounded();
                let mut next_gs_alerter_rx = tokio_stream::wrappers::UnboundedReceiverStream::new(next_gs_alerter_rx);
                let (start, start_rx) = tokio::sync::oneshot::channel();
                let outbound_file_transfer_container = OutboundFileTransfer {
                    stop_tx: Some(stop_tx),
                    object_id,
                    ticket,
                    next_gs_alerter: next_gs_alerter.clone(),
                    start: Some(start),
                };
                let file_key = FileKey::new(key_cid, object_id);
                let _ = state_container.outbound_files.insert(file_key, outbound_file_transfer_container);
                // spawn the task that takes GroupSenders from the threadpool cryptscrambler
                std::mem::drop(state_container);

                let this = self.clone();
                let future = async move {
                    let ref this = this;
                    let ref next_gs_alerter = next_gs_alerter;
                    // this future will resolve when the sender drops in the file_crypt_scrambler
                    match start_rx.await {
                        Ok(false) => {
                            log::warn!("start_rx signalled to NOT begin streaming process. Ending async subroutine");
                            return;
                        }
                        Err(err) => {
                            log::error!("start_rx error occurred: {:?}", err);
                            return;
                        }

                        _ => {
                            log::info!("Outbound file transfer async subroutine signalled to begin!");
                        }
                    }

                    // TODO: planning/overhaul of file transmission process
                    // By now, the file container has been created remotely and locally
                    // We have been signalled to begin polling the group sender
                    // NOTE: polling the group_sender_rx (eventually) stops polling the
                    // async crypt scrambler. Up to 5 groups can be enqueued before stopping
                    // Once 5 groups have enqueued, the only way to continue is if the receiving
                    // end tells us it finished that group, and, we poll the next() group sender below.
                    //

                    let mut relative_group_id = 0;
                    // while waiting, we likely have a set of GroupSenders to process
                    while let Some(sender) = group_sender_rx.next().await {
                        match sender {
                            Ok(sender) => {
                                let (group_id, key) = {
                                    // construct the OutboundTransmitters
                                    let sess = this;
                                    if sess.state.load(Ordering::Relaxed) != SessionState::Connected {
                                        log::warn!("Since transmitting the file, the session ended");
                                        return;
                                    }

                                    let mut state_container = inner_mut_state!(sess.state_container);

                                    let proper_latest_hyper_ratchet = match virtual_target {
                                        VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => { cnac.get_hyper_ratchet(None) }
                                        VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, peer_cid) => {
                                            match StateContainerInner::get_peer_session_crypto(&mut state_container.active_virtual_connections, peer_cid) {
                                                Some(peer_sess_crypt) => {
                                                    peer_sess_crypt.get_hyper_ratchet(None).cloned()
                                                }

                                                None => {
                                                    log::warn!("Since transmitting the file, the peer session ended");
                                                    return;
                                                }
                                            }
                                        }

                                        _ => {
                                            log::error!("HyperWAN Functionality not implemented");
                                            return;
                                        }
                                    };

                                    if proper_latest_hyper_ratchet.is_none() {
                                        log::error!("Unable to unwrap HyperRatchet (X-05)");
                                        return;
                                    }

                                    let hyper_ratchet = proper_latest_hyper_ratchet.unwrap();

                                    let mut transmitter = GroupTransmitter::new_from_group_sender(to_primary_stream.clone(), sender, RatchetPacketCrafterContainer::new(hyper_ratchet.clone(), None), object_id, ticket, security_level, time_tracker.clone());
                                    // group_id is unique per session
                                    let group_id = transmitter.group_id;

                                    // We manually send the header. The tails get sent automatically
                                    log::info!("Sending GROUP HEADER through primary stream for group {}", group_id);
                                    if let Err(err) = sess.try_action(Some(ticket), || transmitter.transmit_group_header(virtual_target)) {
                                        log::error!("Unable to send through primary stream: {}", err.to_string());
                                        return;
                                    }
                                    let group_byte_len = transmitter.get_total_plaintext_bytes();


                                    let outbound_container = OutboundTransmitterContainer::new(Some(next_gs_alerter.clone()), transmitter, group_byte_len, groups_needed, relative_group_id, ticket);
                                    relative_group_id += 1;
                                    // The payload packets won't be sent until a GROUP_HEADER_ACK is received
                                    // the key is the target_cid coupled with the group id
                                    let key = GroupKey::new(key_cid, group_id);

                                    assert!(state_container.outbound_transmitters.insert(key, outbound_container).is_none());
                                    // We can't just add the outbound container. We need to wait til we get the signal to. When the > 50% WAVE_ACKs
                                    // are received, the OutboundFileContainer (which should have a group_notifier) should send a signal which we await for
                                    // here. Also: DROP `sess`!
                                    std::mem::drop(state_container);
                                    //sess.transfer_stats += TransferStats::new(timestamp, group_byte_len as isize);
                                    (group_id, key)
                                };

                                let kernel_tx2 = kernel_tx.clone();

                                this.queue_handle.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                                    if let Some(transmitter) = state_container.outbound_transmitters.get(&key) {
                                        // as long as a wave ACK has been received, proceed with the timeout check
                                        // The reason why is because this group may be loaded, but the previous one isn't done
                                        if transmitter.has_begun {
                                            let ref transmitter = transmitter.burst_transmitter.group_transmitter;
                                            if transmitter.has_expired(GROUP_EXPIRE_TIME_MS) {
                                                if state_container.meta_expiry_state.expired() {
                                                    log::error!("Outbound group {} has expired; dropping entire transfer", group_id);
                                                    //std::mem::drop(transmitter);
                                                    if let Some(mut outbound_container) = state_container.outbound_files.remove(&file_key) {
                                                        if let Some(stop) = outbound_container.stop_tx.take() {
                                                            if let Err(_) = stop.send(()) {
                                                                log::error!("Unable to send stop signal");
                                                            }
                                                        }
                                                    } else {
                                                        log::warn!("Attempted to remove {:?}, but was already absent from map", &file_key);
                                                    }

                                                    if let Err(_) = kernel_tx2.unbounded_send(HdpServerResult::InternalServerError(Some(ticket), format!("Timeout on ticket {}", ticket))) {
                                                        log::error!("[File] Unable to send kernel error signal. Ending session");
                                                        QueueWorkerResult::EndSession
                                                    } else {
                                                        QueueWorkerResult::Complete
                                                    }
                                                } else {
                                                    log::info!("[X-04] Other outbound groups being processed; patiently awaiting group {}", group_id);
                                                    QueueWorkerResult::Incomplete
                                                }
                                            } else {
                                                // it hasn't expired yet, and is still transmitting
                                                QueueWorkerResult::Incomplete
                                            }
                                        } else {
                                            // WAVE_ACK hasn't been received yet; try again later
                                            QueueWorkerResult::Incomplete
                                        }
                                    } else {
                                        // it finished
                                        QueueWorkerResult::Complete
                                    }
                                });

                                // When a wave ACK in the previous group comes, if the group is 50% or more done, the group_sender_rx will
                                // received a signal here

                                if let None = next_gs_alerter_rx.next().await {
                                    log::warn!("next_gs_alerter: steam ended");
                                    return;
                                }
                            }

                            Err(err) => {
                                let _ = kernel_tx.clone().unbounded_send(HdpServerResult::InternalServerError(Some(ticket), err.to_string()));
                            }
                        }
                    }
                };

                let _ = spawn!(future);

                Ok(())
            } else {
                Err(NetworkError::Generic(format!("File `{:?}` not found", file)))
            }
        }
    }

    #[allow(unused_results)]
    pub(crate) async fn dispatch_peer_command(&self, ticket: Ticket, peer_command: PeerSignal, security_level: SecurityLevel) -> Result<(), NetworkError> {
        log::info!("Dispatching peer command ...");
        let this = self;
        let timestamp = this.time_tracker.get_global_time_ns();
        let mut do_save = false;

        let (cnac, res) = {
            let mut state_container = inner_mut_state!(this.state_container);

            if let Some(cnac) = state_container.cnac.clone() {
                if let Some(to_primary_stream) = this.to_primary_stream.as_ref() {
                    // move into the closure without cloning the drill
                    let packet = cnac.visit_mut(|mut inner| {
                        let this_cid = inner.cid;
                        let signal_processed = match peer_command {
                            PeerSignal::DisconnectUDP(v_conn) => {
                                // disconnect UDP locally
                                log::info!("Closing UDP subsystem locally ...");
                                state_container.remove_udp_channel(v_conn.get_target_cid());
                                PeerSignal::DisconnectUDP(v_conn)
                            }
                            // case 1: user just initiated a post-register request that has Fcm enabled
                            PeerSignal::PostRegister(vconn, a, b, c, FcmPostRegister::Enable) => {
                                let target_cid = vconn.get_original_target_cid();
                                log::info!("[FCM] client {} requested FCM post-register with {}", inner.cid, target_cid);

                                if state_container.peer_kem_states.contains_key(&target_cid) || inner.fcm_crypt_container.contains_key(&target_cid) {
                                    return Err(NetworkError::InvalidRequest("Cannot register to the specified client because a concurrent registration process is already occurring, or already registered"));
                                }

                                // create constructor
                                // TODO: Extend FCM to include custom params (within reason, ofc)
                                let fcm_constructor = FcmRatchetConstructor::new_alice(inner.cid, 0, ConstructorOpts::default()).ok_or(NetworkError::InternalError("Unable to construct Alice ratchet"))?;
                                let fcm_post_register = FcmPostRegister::AliceToBobTransfer(fcm_constructor.stage0_alice().serialize_to_vector().unwrap(), inner.crypt_container.fcm_keys.clone().ok_or(NetworkError::InvalidRequest("Fcm not configured for this client"))?, this_cid);
                                // finally, store the constructor inside the state container
                                if let Some(_) = inner.kem_state_containers.insert(target_cid, ConstructorType::Fcm(fcm_constructor)) {
                                    log::error!("Overwrote pre-existing FCM KEM container. Report to developers")
                                }

                                do_save = true;
                                PeerSignal::PostRegister(vconn, a, b, c, fcm_post_register)
                            }

                            // case 2: local just accepted, fcm is enabled. But, signal was not sent via FCM. Instead, was sent via normal network
                            PeerSignal::PostRegister(vconn, a, b, Some(PeerResponse::Accept(Some(c))), FcmPostRegister::AliceToBobTransfer(transfer, peer_fcm_keys, _this_cid)) => {
                                let target_cid = vconn.get_original_target_cid();
                                let local_cid = inner.cid;
                                log::info!("[FCM] client {} accepted FCM post-register with {}", local_cid, target_cid);
                                if inner.fcm_crypt_container.contains_key(&target_cid) {
                                    return Err(NetworkError::InvalidRequest("Cannot register to the specified client because crypt container already exists"));
                                }

                                let fcm_keys_local = inner.crypt_container.fcm_keys.clone().ok_or(NetworkError::InvalidRequest("Local node does not have FCM keys to share with the endpoint"))?;

                                let bob_constructor = FcmRatchetConstructor::new_bob(ConstructorOpts::default(), FcmAliceToBobTransfer::deserialize_from_vector(&transfer[..]).map_err(|err| NetworkError::Generic(err.to_string()))?).ok_or(NetworkError::InvalidRequest("Invalid FCM ratchet constructor"))?;
                                let fcm_post_register = FcmPostRegister::BobToAliceTransfer(bob_constructor.stage0_bob().ok_or(NetworkError::InvalidRequest("Invalid FCM ratchet constructor"))?, fcm_keys_local.clone(), local_cid);
                                let fcm_ratchet = bob_constructor.finish_with_custom_cid(local_cid).ok_or(NetworkError::InvalidRequest("Invalid FCM Ratchet constructor"))?;
                                // no state container, we just add the peer crypt container straight-away
                                inner.fcm_crypt_container.insert(target_cid, PeerSessionCrypto::new_fcm(Toolset::new(local_cid, fcm_ratchet), false, peer_fcm_keys)); // local is NOT initiator in this case
                                do_save = true;

                                PeerSignal::PostRegister(vconn, a, b, Some(PeerResponse::Accept(Some(c))), fcm_post_register)
                            }

                            n => {
                                n
                            }
                        };

                        let hyper_ratchet = inner.crypt_container.get_hyper_ratchet(None).unwrap();
                        let packet = super::hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, signal_processed, ticket, timestamp, security_level);
                        Ok(packet)
                    })?;

                    (cnac, to_primary_stream.unbounded_send(packet).map_err(|err| NetworkError::SocketError(err.to_string())))
                } else {
                    return Err(NetworkError::InternalError("Invalid configuration"))
                }
            } else {
                return Err(NetworkError::InternalError("Invalid configuration"))
            }
        };

        if do_save {
            cnac.save().await?;
        }

        res
    }

    async fn listen_wave_port<S: UdpStream>(this: HdpSession, hole_punched_addr_ip: IpAddr, local_port: u16, mut stream: S, ref peer_session_accessor: EndpointCryptoAccessor) -> Result<(), NetworkError> {
        while let Some(res) = stream.next().await {
            match res {
                Ok((packet, remote_peer)) => {
                    log::info!("packet received on waveport {} has {} bytes (src: {:?})", local_port, packet.len(), &remote_peer);
                    if remote_peer.ip() != hole_punched_addr_ip {
                        log::warn!("The packet received is not part of the firewall session. Dropping");
                    } else {
                        let packet = HdpPacket::new_recv(packet, remote_peer, local_port);
                        this.process_inbound_packet_wave(packet, peer_session_accessor)?;
                    }
                }

                Err(err) => {
                    log::warn!("UDP Stream error: {:#?}", err);
                    break;
                }
            }
        }

        log::info!("Ending waveport listener on {}", local_port);

        Ok(())
    }

    async fn udp_outbound_sender<S: SinkExt<Bytes> + Unpin>(receiver: UnboundedReceiver<(u8, BytesMut)>, hole_punched_addr: TargettedSocketAddr, mut sink: S, peer_session_accessor: EndpointCryptoAccessor) -> Result<(), NetworkError> {
        let mut receiver = tokio_stream::wrappers::UnboundedReceiverStream::new(receiver);
        let target_cid = peer_session_accessor.get_target_cid();

        while let Some((cmd_aux, packet)) = receiver.next().await {
            let send_addr = hole_punched_addr.send_address;
            let packet = peer_session_accessor.borrow_hr(None, |hr, _| hdp_packet_crafter::udp::craft_udp_packet(hr, cmd_aux,packet, target_cid, SecurityLevel::LOW))?;
            log::trace!("About to send packet w/len {} | Dest: {:?}", packet.len(), &send_addr);
            sink.send(packet.freeze()).await.map_err(|_| NetworkError::InternalError("UDP sink unable to receive outbound requests"))?;
        }

        log::info!("Outbound wave sender ending");

        Ok(())
    }

    pub fn process_inbound_packet_wave(&self, packet: HdpPacket, accessor: &EndpointCryptoAccessor) -> Result<(), NetworkError> {
        if packet.get_length() < HDP_HEADER_BYTE_LEN {
            return Ok(());
        }

        if let Some((header, _)) = packet.parse() {
            // we only process streaming packets
            if header.cmd_aux != packet_flags::cmd::aux::udp::STREAM {
                // discard any keep alives
                return Ok(())
            }

            let hr_version = header.drill_version.get();
            let mut endpoint_cid_info = None;
            match check_proxy(self.implicated_cid.get(), header.cmd_primary, header.cmd_aux, header.session_cid.get(), header.target_cid.get(), self, &mut endpoint_cid_info, ReceivePortType::UnorderedUnreliable, packet) {
                Some(packet) => {
                    match hdp_packet_processor::udp_packet::process(self, packet, hr_version, accessor) {
                        Ok(PrimaryProcessorResult::Void) => {
                            Ok(())
                        }

                        Ok(PrimaryProcessorResult::EndSession(err)) => {
                            // stop the UDP stream
                            log::warn!("UDP session ending: {:?}", err);
                            Err(NetworkError::Generic(err.to_string()))
                        }

                        Err(err) => {
                            // stop the UDP stream
                            log::warn!("UDP session ending: {:?}", err);
                            Err(err)
                        }

                        _ => {
                            Ok(())
                        }
                    }
                }

                None => {
                    Ok(())
                }
            }
        } else {
            log::error!("A packet was unable to be parsed");
            Ok(())
        }
    }

    /// Returns true if the disconnect initiate was a success, false if not. An error returns if something else occurs
    pub fn initiate_disconnect(&self, ticket: Ticket, _target: VirtualConnectionType) -> Result<bool, NetworkError> {
        let session = self;
        if session.state.load(Ordering::Relaxed) != SessionState::Connected {
            log::error!("Must be connected to HyperLAN in order to start disconnect")
        }

        let state_container = inner_state!(session.state_container);

        let cnac = state_container.cnac.as_ref().unwrap();
        let hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();
        let timestamp = session.time_tracker.get_global_time_ns();
        let security_level = state_container.session_security_settings.as_ref().map(|r| r.security_level).clone().unwrap();
        let to_primary_stream = session.to_primary_stream.as_ref().unwrap();
        let ref to_kernel_tx = session.kernel_tx;

        let disconnect_stage0_packet = hdp_packet_crafter::do_disconnect::craft_stage0(&hyper_ratchet, ticket, timestamp, security_level);
        Self::send_to_primary_stream_closure(to_primary_stream, to_kernel_tx, disconnect_stage0_packet, Some(ticket))
            .and_then(|_| Ok(true))
    }
}

impl HdpSessionInner {
    /// Stores the proposed credentials into the register state container
    pub(crate) fn store_proposed_credentials(&mut self, proposed_credentials: ProposedCredentials) {
        let mut state_container = inner_mut_state!(self.state_container);
        state_container.register_state.passwordless = Some(proposed_credentials.is_passwordless());
        state_container.connect_state.proposed_credentials = Some(proposed_credentials);
    }

    /// When a successful login occurs, this function gets called. Must return any AsRef<[u8]> type
    pub(super) fn create_welcome_message(&self, cid: u64) -> String {
        format!("SatoriNET login::success. Welcome to the Post-quantum network. Implicated CID: {}", cid)
    }

    pub(super) fn create_register_success_message(&self) -> String {
        format!("SatoriNET register::success. Welcome to your new post-quantum network! Login to interact with your new network")
    }

    /// If the previous state was not a login fail, then the unwrap_or case will occur
    #[allow(unused)]
    pub(super) fn can_reconnect(&self) -> bool {
        let current_time = self.time_tracker.get_global_time_ns();
        // if there was no failure, the value will be much larger than the initial locckout time, thus returning true
        if let Some(fail_time) = inner_state!(self.state_container).connect_state.fail_time {
            // if the gap between the current time and the fail time is enough, then reconnection is possible
            current_time - fail_time > INITIAL_RECONNECT_LOCKOUT_TIME_NS
        } else {
            // No fail means reconnection is possible
            true
        }
    }

    /// This will panic if cannot be sent
    #[inline]
    pub fn send_to_kernel(&self, msg: HdpServerResult) -> Result<(), SendError<HdpServerResult>> {
        self.kernel_tx.unbounded_send(msg)
    }

    /// Will send the message to the primary stream, and will alert the kernel if the stream's connector is full
    pub fn send_to_primary_stream(&self, ticket: Option<Ticket>, msg: BytesMut) -> Result<(), NetworkError> {
        if let Some(tx) = self.to_primary_stream.as_ref() {
            match tx.unbounded_send(msg) {
                Ok(_) => {
                    Ok(())
                }

                Err(err) => {
                    self.send_to_kernel(HdpServerResult::InternalServerError(ticket, err.to_string()))
                        .map_err(|err| NetworkError::Generic(err.to_string()))?;
                    Err(NetworkError::InternalError("Unable to send through primary stream"))
                }
            }
        } else {
            Err(NetworkError::InternalError("Primary stream sender absent"))
        }
    }

    /// will try a running a function, and if an error occurs, will send error to Kernel
    pub fn try_action<T, E: ToString>(&self, ticket: Option<Ticket>, fx: impl FnOnce() -> Result<T, E>) -> Result<T, NetworkError> {
        match (fx)().map_err(|err| NetworkError::Generic(err.to_string())) {
            Err(err) => {
                self.send_to_kernel(HdpServerResult::InternalServerError(ticket, err.to_string()))
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
                Err(err)
            }

            res => res
        }
    }

    /// Stops the future from running
    pub fn shutdown(&self) {
        self.state.store(SessionState::Disconnected, Ordering::SeqCst);
        let _ = inner!(self.stopper_tx).send(());
    }

    pub(crate) fn initiate_deregister(&self, _virtual_connection_type: VirtualConnectionType, ticket: Ticket) -> Result<(), NetworkError> {
        log::info!("Initiating deregister process ...");
        let mut state_container = inner_mut_state!(self.state_container);
        let timestamp = self.time_tracker.get_global_time_ns();
        let cnac = state_container.cnac.as_ref().ok_or_else(|| NetworkError::InternalError("CNAC not loaded"))?;
        let security_level = state_container.session_security_settings.clone().map(|r| r.security_level).clone().unwrap();
        let ref hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();

        let stage0_packet = hdp_packet_crafter::do_deregister::craft_stage0(hyper_ratchet, timestamp, security_level);

        state_container.deregister_state.on_init(timestamp, ticket);
        self.send_to_primary_stream(Some(ticket), stage0_packet)
    }

    pub(crate) fn is_provisional(&self) -> bool {
        let state = self.state.load(Ordering::Relaxed);
        //self.implicated_cid.is_none()
        // SocketJustOpened is only the state for a session created from an incoming connection
        state == SessionState::SocketJustOpened || state == SessionState::NeedsConnect || state == SessionState::ConnectionProcess || state == SessionState::NeedsRegister
    }

    pub(crate) fn send_session_dc_signal<T: Into<String>>(&self, ticket: Option<Ticket>, disconnect_success: bool, msg: T) {
        if let Some(tx) = self.dc_signal_sender.take() {
            let _ = tx.unbounded_send(HdpServerResult::Disconnect(ticket.unwrap_or_else(|| self.kernel_ticket.get()), self.implicated_cid.get().map(|r| r as _).unwrap_or_else(|| self.kernel_ticket.get().0), disconnect_success, None, msg.into()));
        }
    }

    pub(crate) fn disable_dc_signal(&self) {
        let _ = self.dc_signal_sender.take();
    }
}

impl Drop for HdpSessionInner {
    fn drop(&mut self) {
        log::info!("*** Dropping HdpSession {:?} ***", self.implicated_cid.get());
        if let Err(_) = self.on_drop.unbounded_send(()) {
            //log::error!("Unable to cleanly alert node that session ended: {:?}", err);
        }

        let _ = inner!(self.stopper_tx).send(());

        self.send_session_dc_signal(None, false, "Session dropped");
    }
}