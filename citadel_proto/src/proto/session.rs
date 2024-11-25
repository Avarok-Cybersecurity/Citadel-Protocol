use std::fs::File;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

//use async_std::prelude::*;
use crate::proto::packet_processor::includes::Instant;
use bytes::{Bytes, BytesMut};
use citadel_io::tokio_util::codec::LengthDelimitedCodec;
use futures::{SinkExt, StreamExt, TryFutureExt, TryStreamExt};

use citadel_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_types::proto::UdpMode;
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::network_account::ConnectProtocol;
use citadel_wire::hypernode_type::NodeType;
use citadel_wire::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use netbeam::time_tracker::TimeTracker;

use crate::constants::{
    DRILL_UPDATE_FREQUENCY_LOW_BASE, FIREWALL_KEEP_ALIVE_UDP, GROUP_EXPIRE_TIME_MS,
    HDP_HEADER_BYTE_LEN, INITIAL_RECONNECT_LOCKOUT_TIME_NS, KEEP_ALIVE_INTERVAL_MS,
    KEEP_ALIVE_TIMEOUT_NS, LOGIN_EXPIRATION_TIME,
};
use crate::error::NetworkError;
use crate::proto::packet::{packet_flags, HdpPacket};
use crate::proto::packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::proto::packet_crafter::{self, GroupTransmitter, RatchetPacketCrafterContainer};
use citadel_types::proto::VirtualObjectMetadata;
//use futures_codec::Framed;
use crate::proto::misc;
use crate::proto::misc::clean_shutdown::{CleanShutdownSink, CleanShutdownStream};
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::packet_processor::includes::{Duration, SocketAddr};
use crate::proto::packet_processor::{self, PrimaryProcessorResult};
use crate::proto::session_manager::HdpSessionManager;
use citadel_types::proto::ConnectMode;
use citadel_types::proto::SessionSecuritySettings;
//use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender, channel, TrySendError};
use crate::auth::AuthenticationRequest;
use crate::kernel::RuntimeFuture;
use crate::prelude::{GroupBroadcast, PeerEvent, PeerResponse, PreSharedKey, SecureProtocolPacket};
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::misc::dual_cell::DualCell;
use crate::proto::misc::dual_late_init::DualLateInit;
use crate::proto::misc::udp_internal_interface::{UdpSplittableTypes, UdpStream};
use crate::proto::outbound_sender::{
    channel, unbounded, SendError, UnboundedReceiver, UnboundedSender,
};
use crate::proto::outbound_sender::{
    OutboundPrimaryStreamReceiver, OutboundPrimaryStreamSender, OutboundUdpSender,
};
use crate::proto::packet_processor::raw_primary_packet::{check_proxy, ReceivePortType};
use crate::proto::peer::p2p_conn_handler::P2PInboundHandle;
use crate::proto::peer::peer_layer::{HyperNodePeerLayer, PeerSignal};
use crate::proto::session_queue_handler::{
    QueueWorkerResult, QueueWorkerTicket, SessionQueueWorker, SessionQueueWorkerHandle,
    DRILL_REKEY_WORKER, FIREWALL_KEEP_ALIVE, KEEP_ALIVE_CHECKER, PROVISIONAL_CHECKER,
    RESERVED_CID_IDX,
};
use crate::proto::state_container::{
    FileKey, GroupKey, OutboundFileTransfer, OutboundTransmitterContainer, StateContainer,
    StateContainerInner, VirtualConnectionType, VirtualTargetType,
};
use crate::proto::state_subcontainers::preconnect_state_container::UdpChannelSender;
use crate::proto::state_subcontainers::rekey_container::calculate_update_frequency;
use crate::proto::transfer_stats::TransferStats;
use atomic::Atomic;
use citadel_crypt::prelude::{ConstructorOpts, FixedSizedSource};
use citadel_crypt::streaming_crypt_scrambler::{scramble_encrypt_source, ObjectSource};
use citadel_types::proto::TransferType;
use citadel_user::backend::PersistenceHandler;
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::exports::Connection;
use citadel_wire::nat_identification::NatType;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
//use futures_codec::Framed;
use crate::proto::node_result::{Disconnect, InternalServerError, NodeResult};
use crate::proto::packet_processor::disconnect_packet::SUCCESS_DISCONNECT;
use crate::proto::remote::{NodeRemote, Ticket};
use bytemuck::NoUninit;
use citadel_types::crypto::SecurityLevel;

//use crate::define_struct;

// Defines the primary structure which wraps the inner device
//define_outer_struct_wrapper!(HdpSession, HdpSessionInner);

/// Allows a connection stream to be worked on by a single worker
pub struct CitadelSession {
    #[cfg(not(feature = "multi-threaded"))]
    pub inner: std::rc::Rc<CitadelSessionInner>,
    #[cfg(feature = "multi-threaded")]
    pub inner: std::sync::Arc<CitadelSessionInner>,
}

enum SessionShutdownReason {
    ProperShutdown,
    Error(NetworkError),
}

impl CitadelSession {
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
    pub fn as_weak(&self) -> std::rc::Weak<CitadelSessionInner> {
        std::rc::Rc::downgrade(&self.inner)
    }

    #[cfg(feature = "multi-threaded")]
    pub fn as_weak(&self) -> std::sync::Weak<CitadelSessionInner> {
        std::sync::Arc::downgrade(&self.inner)
    }

    #[cfg(feature = "multi-threaded")]
    pub fn upgrade_weak(this: &std::sync::Weak<CitadelSessionInner>) -> Option<Self> {
        this.upgrade().map(|inner| Self { inner })
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn upgrade_weak(this: &std::rc::Weak<CitadelSessionInner>) -> Option<Self> {
        this.upgrade().map(|inner| Self { inner })
    }
}

impl From<CitadelSessionInner> for CitadelSession {
    fn from(inner: CitadelSessionInner) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
        {
            Self {
                inner: std::rc::Rc::new(inner),
            }
        }

        #[cfg(feature = "multi-threaded")]
        {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }
}

impl Deref for CitadelSession {
    type Target = CitadelSessionInner;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl Clone for CitadelSession {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

//define_struct!(HdpSession, HdpSessionInner);

/// Structure for holding and keep track of packets, as well as basic connection information
#[allow(unused)]
pub struct CitadelSessionInner {
    pub(super) implicated_cid: DualRwLock<Option<u64>>,
    pub(super) kernel_ticket: DualCell<Ticket>,
    pub(super) remote_peer: SocketAddr,
    // Sends results directly to the kernel
    pub(super) kernel_tx: UnboundedSender<NodeResult>,
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
    pub(super) dc_signal_sender: DualRwLock<Option<UnboundedSender<NodeResult>>>,
    pub(super) is_server: bool,
    pub(super) stopper_tx: DualRwLock<citadel_io::tokio::sync::broadcast::Sender<()>>,
    pub(super) queue_handle: DualLateInit<SessionQueueWorkerHandle>,
    pub(super) peer_only_connect_protocol: DualRwLock<Option<ConnectProtocol>>,
    pub(super) primary_stream_quic_conn: DualRwLock<Option<Connection>>,
    pub(super) local_nat_type: NatType,
    pub(super) adjacent_nat_type: DualLateInit<Option<NatType>>,
    pub(super) connect_mode: DualRwLock<Option<ConnectMode>>,
    pub(super) client_config: Arc<rustls::ClientConfig>,
    pub(super) hypernode_peer_layer: HyperNodePeerLayer,
    pub(super) stun_servers: Option<Vec<String>>,
    pub(super) init_time: Instant,
    pub(super) file_transfer_compatible: DualLateInit<bool>,
    pub(super) session_password: PreSharedKey,
    on_drop: UnboundedSender<()>,
}

/// allows each session worker to check the state of the session
#[derive(Copy, Clone, PartialEq, Debug, NoUninit)]
#[repr(u8)]
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

pub(crate) struct SessionInitParams {
    pub on_drop: UnboundedSender<()>,
    pub local_nat_type: NatType,
    pub hdp_remote: NodeRemote,
    pub local_bind_addr: SocketAddr,
    pub local_node_type: NodeType,
    pub kernel_tx: UnboundedSender<NodeResult>,
    pub session_manager: HdpSessionManager,
    pub account_manager: AccountManager,
    pub time_tracker: TimeTracker,
    pub remote_peer: SocketAddr,
    pub init_ticket: Ticket,
    pub client_config: Arc<rustls::ClientConfig>,
    pub hypernode_peer_layer: HyperNodePeerLayer,
    // this is set only when a local client is attempting to start an outbound session
    pub client_only_settings: Option<ClientOnlySessionInitSettings>,
    pub stun_servers: Option<Vec<String>>,
    pub init_time: Instant,
    pub session_password: PreSharedKey,
}

pub(crate) struct ClientOnlySessionInitSettings {
    pub init_mode: HdpSessionInitMode,
    pub peer_only_connect_proto: ConnectProtocol,
    pub cnac: Option<ClientNetworkAccount>,
    pub proposed_credentials: ProposedCredentials,
    pub udp_mode: UdpMode,
    pub keep_alive_timeout_ns: i64,
    pub security_settings: SessionSecuritySettings,
    pub connect_mode: Option<ConnectMode>,
}

impl CitadelSession {
    pub(crate) fn new(
        session_init_params: SessionInitParams,
    ) -> Result<(citadel_io::tokio::sync::broadcast::Sender<()>, Self), NetworkError> {
        let (stopper_tx, _stopper_rx) = citadel_io::tokio::sync::broadcast::channel(10);
        let client_only_settings = &session_init_params.client_only_settings;
        let is_server = client_only_settings.is_none();
        let (cnac, state, implicated_cid) =
            if let Some(client_init_settings) = &session_init_params.client_only_settings {
                match &client_init_settings.init_mode {
                    HdpSessionInitMode::Connect(auth) => {
                        match auth {
                            AuthenticationRequest::Credentialed { .. } => {
                                let cnac = client_init_settings
                                    .cnac
                                    .clone()
                                    .ok_or(NetworkError::InvalidRequest("Client does not exist"))?;
                                let cid = cnac.get_cid();
                                (
                                    Some(cnac),
                                    Arc::new(Atomic::new(SessionState::NeedsConnect)),
                                    Some(cid),
                                )
                            }

                            AuthenticationRequest::Passwordless { .. } => {
                                // register will redirect to preconnect afterwards
                                (
                                    None,
                                    Arc::new(Atomic::new(SessionState::NeedsRegister)),
                                    None,
                                )
                            }
                        }
                    }

                    HdpSessionInitMode::Register(..) => (
                        None,
                        Arc::new(Atomic::new(SessionState::NeedsRegister)),
                        None,
                    ),
                }
            } else {
                (
                    None,
                    Arc::new(Atomic::new(SessionState::SocketJustOpened)),
                    None,
                )
            };

        let timestamp = session_init_params.time_tracker.get_global_time_ns();
        let hypernode_peer_layer = session_init_params.hypernode_peer_layer;
        let connect_mode = client_only_settings.as_ref().and_then(|r| r.connect_mode);
        let local_nat_type = session_init_params.local_nat_type;
        let kernel_tx = session_init_params.kernel_tx;
        let peer_only_connect_protocol = client_only_settings
            .as_ref()
            .map(|r| r.peer_only_connect_proto.clone())
            .into();
        let on_drop = session_init_params.on_drop;
        let local_bind_addr = session_init_params.local_bind_addr;
        let local_node_type = session_init_params.local_node_type;
        let remote_node_type = None;
        let time_tracker = session_init_params.time_tracker;
        let kernel_ticket = session_init_params.init_ticket;
        let remote_peer = session_init_params.remote_peer;
        let session_manager = session_init_params.session_manager;
        let hdp_remote = session_init_params.hdp_remote;
        let session_security_settings = client_only_settings.as_ref().map(|r| r.security_settings);
        let udp_mode = client_only_settings
            .as_ref()
            .map(|r| r.udp_mode)
            .unwrap_or(UdpMode::Disabled);
        let account_manager = session_init_params.account_manager;
        let client_config = session_init_params.client_config;
        let keep_alive_timeout_ns = client_only_settings
            .as_ref()
            .map(|r| r.keep_alive_timeout_ns)
            .unwrap_or(KEEP_ALIVE_TIMEOUT_NS);
        let stun_servers = session_init_params.stun_servers;
        let init_time = session_init_params.init_time;
        let session_password = session_init_params.session_password;

        let mut inner = CitadelSessionInner {
            hypernode_peer_layer,
            connect_mode: DualRwLock::from(connect_mode),
            primary_stream_quic_conn: DualRwLock::from(None),
            local_nat_type,
            adjacent_nat_type: DualLateInit::default(),
            do_static_hr_refresh_atexit: true.into(),
            dc_signal_sender: DualRwLock::from(Some(kernel_tx.clone())),
            peer_only_connect_protocol,
            on_drop,
            local_bind_addr,
            local_node_type,
            remote_node_type,
            implicated_cid: DualRwLock::from(implicated_cid),
            time_tracker,
            kernel_ticket: kernel_ticket.into(),
            remote_peer,
            kernel_tx: kernel_tx.clone(),
            session_manager,
            state_container: StateContainerInner::create(
                kernel_tx,
                hdp_remote,
                keep_alive_timeout_ns,
                state.clone(),
                cnac,
                time_tracker,
                session_security_settings,
                is_server,
                TransferStats::new(timestamp, 0),
                udp_mode,
            ),
            to_primary_stream: DualLateInit::default(),
            state,
            account_manager,
            is_server,
            stopper_tx: stopper_tx.clone().into(),
            queue_handle: DualLateInit::default(),
            client_config,
            stun_servers,
            init_time,
            file_transfer_compatible: DualLateInit::default(),
            session_password,
        };

        if let Some(proposed_credentials) = session_init_params
            .client_only_settings
            .map(|r| r.proposed_credentials)
        {
            inner.store_proposed_credentials(proposed_credentials);
        }

        Ok((stopper_tx, Self::from(inner)))
    }

    /// Once the [CitadelSession] is created, it can then be executed to begin handling a periodic connection handler.
    /// This will automatically stop running once the internal state is set to Disconnected
    /// `tcp_stream`: this goes to the adjacent HyperNode
    /// `p2p_listener`: This is TCP listener bound to the same local_addr as tcp_stream. Required for TCP hole-punching
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    pub async fn execute(
        &self,
        mut primary_stream: GenericNetworkStream,
        peer_addr: SocketAddr,
    ) -> Result<Option<u64>, (NetworkError, Option<u64>)> {
        log::trace!(target: "citadel", "HdpSession is executing ...");
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

            this.to_primary_stream
                .set_once(Some(primary_outbound_tx.clone()));

            let timestamp = this.time_tracker.get_global_time_ns();
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
            let handle_zero_state = Self::handle_zero_state(
                None,
                persistence_handler,
                primary_outbound_tx,
                this_outbound,
                this.state.load(Ordering::SeqCst),
                timestamp,
                cnac_opt,
            );

            let session_future = spawn_handle!(async move {
                citadel_io::tokio::select! {
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
            spawn!(queue_worker_future);

            (session_future, handle_zero_state, implicated_cid)
        };

        if let Err(err) = handle_zero_state.await {
            log::error!(target: "citadel", "Unable to proceed past session zero-state. Stopping session: {:?}", &err);
            return Err((err, implicated_cid.get()));
        }

        let res = session_future
            .await
            .map_err(|err| (NetworkError::Generic(err.to_string()), None))?;

        match res {
            Ok(_) => {
                log::trace!(target: "citadel", "Done EXECUTING sess (Ok(())) | cid: {:?} | is_server: {}", this_close.implicated_cid.get(), this_close.is_server);
                Ok(implicated_cid.get())
            }

            Err(err) => {
                let ticket = this_close.kernel_ticket.get();
                let reason = err.to_string();
                let cid = implicated_cid.get();

                log::trace!(target: "citadel", "Session {} connected to {} is ending! Reason: {}. (strong count: {})", ticket.0, peer_addr, reason.as_str(), this_close.strong_count());

                this_close.send_session_dc_signal(Some(ticket), false, "Inbound stream ending");

                Err((err, cid))
            }
        }
    }

    async fn stopper(
        mut receiver: citadel_io::tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), NetworkError> {
        receiver
            .recv()
            .await
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(())
    }

    /// Executes each session in parallel (or concurrent if using a LocalSet)
    pub async fn session_future_receiver(
        mut p2p_session_rx: UnboundedReceiver<Pin<Box<dyn RuntimeFuture>>>,
    ) -> Result<(), NetworkError> {
        while let Some(session) = p2p_session_rx.recv().await {
            spawn!(session);
        }

        Ok(())
    }

    /// Before going through the usual flow, check to see if we need to initiate either a stage0 REGISTER or CONNECT packet
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    async fn handle_zero_state(
        zero_packet: Option<BytesMut>,
        persistence_handler: PersistenceHandler,
        to_outbound: OutboundPrimaryStreamSender,
        session: CitadelSession,
        state: SessionState,
        timestamp: i64,
        cnac: Option<ClientNetworkAccount>,
    ) -> Result<(), NetworkError> {
        if let Some(zero) = zero_packet {
            to_outbound
                .unbounded_send(zero)
                .map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;
        }

        match state {
            SessionState::NeedsRegister => {
                log::trace!(target: "citadel", "Beginning registration subroutine");
                let session_ref = session;
                let mut state_container = inner_mut_state!(session_ref.state_container);
                let session_security_settings = state_container.session_security_settings.unwrap();
                let proposed_username = state_container
                    .connect_state
                    .proposed_credentials
                    .as_ref()
                    .ok_or(NetworkError::InternalError(
                        "Proposed credentials not loaded",
                    ))?
                    .username();
                let proposed_cid = persistence_handler.get_cid_by_username(proposed_username);
                let passwordless = state_container
                    .register_state
                    .passwordless
                    .ok_or(NetworkError::InternalError("Passwordless state not loaded"))?;
                // we supply 0,0 for cid and new drill vers by default, even though it will be reset by bob
                let alice_constructor = StackedRatchetConstructor::new_alice(
                    ConstructorOpts::new_vec_init(
                        Some(session_security_settings.crypto_params),
                        (session_security_settings.security_level.value() + 1) as usize,
                    ),
                    proposed_cid,
                    0,
                    Some(session_security_settings.security_level),
                )
                .ok_or(NetworkError::InternalError(
                    "Unable to construct Alice ratchet",
                ))?;

                state_container.register_state.last_packet_time = Some(Instant::now());
                log::trace!(target: "citadel", "Running stage0 alice");
                let transfer =
                    alice_constructor
                        .stage0_alice()
                        .ok_or(NetworkError::InternalError(
                            "Unable to construct AliceToBob transfer",
                        ))?;

                let stage0_register_packet =
                    crate::proto::packet_crafter::do_register::craft_stage0(
                        session_security_settings.crypto_params.into(),
                        timestamp,
                        transfer,
                        passwordless,
                        proposed_cid,
                    );
                to_outbound
                    .unbounded_send(stage0_register_packet)
                    .map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;

                state_container.register_state.constructor = Some(alice_constructor);
                log::trace!(target: "citadel", "Successfully sent stage0 register packet outbound");
            }

            SessionState::NeedsConnect => {
                Self::begin_connect(&session, cnac.as_ref().unwrap())?;
            }

            // This implies this node received a new incoming connection. It is up to the other node, Alice, to send a stage 0 packet
            SessionState::SocketJustOpened => {
                log::trace!(target: "citadel", "No actions needed on primary TCP port; beginning outbound listening subroutine ...");
                // If somebody makes a connection to this node, but doesn't send anything, we need a way to remove
                // such a stale connection. By setting the value below, we ensure the possibility that the session
                // timer removes it
                inner_mut_state!(session.state_container)
                    .connect_state
                    .last_packet_time = Some(Instant::now());
            }

            _ => {
                log::error!(target: "citadel", "Invalid initial state. Check program logic");
                std::process::exit(-1);
            }
        }

        Ok(())
    }

    pub(crate) fn begin_connect(
        session: &CitadelSession,
        cnac: &ClientNetworkAccount,
    ) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "Beginning pre-connect subroutine!");
        let session_ref = session;
        let connect_mode = (*inner!(session.connect_mode))
            .ok_or(NetworkError::InternalError("Connect mode not loaded"))?;
        let mut state_container = inner_mut_state!(session_ref.state_container);

        let udp_mode = state_container.udp_mode;
        let timestamp = session_ref.time_tracker.get_global_time_ns();
        let session_security_settings = state_container.session_security_settings.unwrap();
        let peer_only_connect_mode = session_ref.peer_only_connect_protocol.get().unwrap();
        // reset the toolset's ARA
        let static_aux_hr = &cnac.refresh_static_hyper_ratchet();
        // security level inside static hr may not be what the declared session security level for this session is. Session security level can be no higher than the initial static HR level, since the chain requires recursion from the initial value
        let _ = static_aux_hr.verify_level(Some(session_security_settings.security_level)).map_err(|_| NetworkError::InvalidRequest("The specified security setting for the session exceeds the registration security setting"))?;
        let opts = static_aux_hr
            .get_next_constructor_opts()
            .into_iter()
            .take((session_security_settings.security_level.value() + 1) as usize)
            .collect();
        //static_aux_hr.verify_level(Some(security_level)).map_err(|_| NetworkError::Generic(format!("Invalid security level. Maximum security level for this account is {:?}", static_aux_hr.get_default_security_level())))?;
        let alice_constructor = StackedRatchetConstructor::new_alice(
            opts,
            cnac.get_cid(),
            0,
            Some(session_security_settings.security_level),
        )
        .ok_or(NetworkError::InternalError(
            "Unable to construct Alice ratchet",
        ))?;
        let transfer = alice_constructor
            .stage0_alice()
            .ok_or(NetworkError::InternalError(
                "Failed to construct AliceToBobTransfer",
            ))?;
        // encrypts the entire connect process with the highest possible security level
        let max_usable_level = static_aux_hr.get_default_security_level();
        let nat_type = session_ref.local_nat_type.clone();

        if udp_mode == UdpMode::Enabled {
            state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
        }

        // NEXT STEP: check preconnect, and update internal security-level recv side to the security level found in transfer to ensure all future packages are at that security-level
        let syn = packet_crafter::pre_connect::craft_syn(
            static_aux_hr,
            transfer,
            nat_type,
            udp_mode,
            timestamp,
            state_container.keep_alive_timeout_ns,
            max_usable_level,
            session_security_settings,
            peer_only_connect_mode,
            connect_mode,
        );

        state_container.pre_connect_state.last_stage =
            packet_flags::cmd::aux::do_preconnect::SYN_ACK;
        state_container.pre_connect_state.constructor = Some(alice_constructor);
        state_container.connect_state.connect_mode = Some(connect_mode);

        session.send_to_primary_stream(None, syn)?;

        log::trace!(target: "citadel", "Successfully sent SYN pre-connect packet");
        Ok(())
    }

    // tcp_conn_awaiter must be provided in order to know when the begin loading the UDP conn for the user. The TCP connection must first be loaded in order to place the udp conn inside the virtual_conn hashmap
    pub(crate) fn udp_socket_loader(
        this: CitadelSession,
        v_target: VirtualTargetType,
        udp_conn: UdpSplittableTypes,
        addr: TargettedSocketAddr,
        ticket: Ticket,
        tcp_conn_awaiter: Option<citadel_io::tokio::sync::oneshot::Receiver<()>>,
    ) {
        let this_weak = this.as_weak();
        std::mem::drop(this);
        let task = async move {
            let (listener, udp_sender_future, stopper_rx) = {
                let this = CitadelSession::upgrade_weak(&this_weak)
                    .ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let sess = this;

                // we supply the natted ip since it is where we expect to receive packets
                // whether local is server or not, we should expect to receive packets from natted
                let hole_punched_socket = addr.receive_address;
                let hole_punched_addr_ip = hole_punched_socket.ip();

                let local_bind_addr = udp_conn.local_addr().unwrap();
                let needs_manual_ka = udp_conn.needs_manual_ka();

                let (outbound_sender_tx, outbound_sender_rx) = unbounded();
                let udp_sender = OutboundUdpSender::new(
                    outbound_sender_tx,
                    local_bind_addr,
                    hole_punched_socket,
                    needs_manual_ka,
                );
                let (stopper_tx, stopper_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

                let is_server = sess.is_server;
                std::mem::drop(sess);
                if let Some(tcp_conn_awaiter) = tcp_conn_awaiter {
                    log::trace!(target: "citadel", "Awaiting tcp conn to finish before creating UDP subsystem ... is_server={}", is_server);
                    tcp_conn_awaiter
                        .await
                        .map_err(|err| NetworkError::Generic(err.to_string()))?;
                }

                let sess = CitadelSession::upgrade_weak(&this_weak)
                    .ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let accessor = match v_target {
                    VirtualConnectionType::LocalGroupServer { implicated_cid: _ } => {
                        let mut state_container = inner_mut_state!(sess.state_container);
                        state_container.udp_primary_outbound_tx = Some(udp_sender.clone());
                        log::trace!(target: "citadel", "C2S UDP subroutine inserting UDP channel ... (is_server={})", is_server);
                        if let Some(channel) = state_container.insert_udp_channel(
                            C2S_ENCRYPTION_ONLY,
                            v_target,
                            ticket,
                            udp_sender,
                            stopper_tx,
                        ) {
                            log::trace!(target: "citadel", "C2S UDP subroutine created udp channel ... (is_server={})", is_server);
                            if let Some(sender) = state_container
                                .pre_connect_state
                                .udp_channel_oneshot_tx
                                .tx
                                .take()
                            {
                                //TODO: await before sending Channel to c2s or p2p
                                log::trace!(target: "citadel", "C2S UDP subroutine sending channel to local user ... (is_server={})", is_server);
                                sender.send(channel).map_err(|_| {
                                    NetworkError::InternalError("Unable to send UdpChannel through")
                                })?;
                                EndpointCryptoAccessor::C2S(sess.state_container.clone())
                            } else {
                                log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had no UDP sender");
                                return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"));
                            }
                        } else {
                            log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                            return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."));
                        }
                    }

                    VirtualConnectionType::LocalGroupPeer {
                        implicated_cid: _implicated_cid,
                        peer_cid: target_cid,
                    } => {
                        let mut state_container = inner_mut_state!(sess.state_container);
                        if let Some(channel) = state_container.insert_udp_channel(
                            target_cid, v_target, ticket, udp_sender, stopper_tx,
                        ) {
                            if let Some(kem_state) =
                                state_container.peer_kem_states.get_mut(&target_cid)
                            {
                                // Below will fail if UDP mode is off, as desired
                                if let Some(sender) = kem_state.udp_channel_sender.tx.take() {
                                    // below will fail if the user drops the receiver at the kernel-level
                                    sender.send(channel).map_err(|_| {
                                        NetworkError::InternalError(
                                            "Unable to send UdpChannel through",
                                        )
                                    })?;
                                    EndpointCryptoAccessor::P2P(
                                        target_cid,
                                        sess.state_container.clone(),
                                    )
                                } else {
                                    log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had no UDP sender");
                                    return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had no UDP sender"));
                                }
                            } else {
                                log::error!(target: "citadel", "Tried loading the peer kem state, but was absent");
                                return Err(NetworkError::InternalError(
                                    "Tried loading the peer kem state, but was absent",
                                ));
                            }
                        } else {
                            log::error!(target: "citadel", "Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ...");
                            return Err(NetworkError::InternalError("Tried loading UDP channel, but, the state container had an invalid configuration. Make sure TCP is loaded first ..."));
                        }
                    }

                    _ => {
                        return Err(NetworkError::InternalError("Invalid virtual target"));
                    }
                };

                // unlike TCP, we will not use [LengthDelimitedCodec] because there is no guarantee that packets
                // will arrive in order
                let (writer, reader) = udp_conn.split();

                let listener = Self::listen_udp_port(
                    sess,
                    hole_punched_addr_ip,
                    local_bind_addr.port(),
                    reader,
                    accessor.clone(),
                );

                log::trace!(target: "citadel", "Server established UDP Port {}", local_bind_addr);

                //futures.push();
                let udp_sender_future =
                    Self::udp_outbound_sender(outbound_sender_rx, addr, writer, accessor);
                (listener, udp_sender_future, stopper_rx)
            };

            log::trace!(target: "citadel", "[Q-UDP] Initiated UDP subsystem...");

            let stopper = async move {
                stopper_rx
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            };

            citadel_io::tokio::select! {
                res0 = listener => res0,
                res1 = udp_sender_future => res1,
                res2 = stopper => res2
            }
        };

        spawn!(task);
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    pub async fn outbound_stream(
        primary_outbound_rx: OutboundPrimaryStreamReceiver,
        writer: CleanShutdownSink<GenericNetworkStream, LengthDelimitedCodec, Bytes>,
    ) -> Result<(), NetworkError> {
        primary_outbound_rx
            .0
            .map(|r| {
                #[cfg_attr(
                    feature = "localhost-testing",
                    tracing::instrument(level = "trace", target = "citadel", skip_all, fields(packet_length = r.len()))
                )]
                fn process_outbound_packet(r: BytesMut) -> Bytes {
                    r.freeze()
                }

                Ok(process_outbound_packet(r))
            })
            .forward(writer)
            .map_err(|err| NetworkError::Generic(err.to_string()))
            .await
    }

    /// NOTE: We need to have at least one owning/strong reference to the session. Having the inbound stream own a single strong count makes the most sense
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    pub async fn execute_inbound_stream(
        mut reader: CleanShutdownStream<GenericNetworkStream, LengthDelimitedCodec, Bytes>,
        this_main: CitadelSession,
        p2p_handle: Option<P2PInboundHandle>,
    ) -> Result<(), NetworkError> {
        let this_main = &this_main;
        log::trace!(target: "citadel", "HdpSession async inbound-stream subroutine executed");
        let (
            ref remote_peer,
            ref local_primary_port,
            ref implicated_cid,
            ref kernel_tx,
            ref primary_stream,
            peer_cid,
            is_server,
        ) = if let Some(p2p) = p2p_handle {
            (
                p2p.remote_peer,
                p2p.local_bind_port,
                p2p.implicated_cid,
                p2p.kernel_tx,
                p2p.to_primary_stream,
                Some(p2p.peer_cid),
                false,
            )
        } else {
            let borrow = this_main;
            let remote_peer = borrow.remote_peer;
            let local_primary_port = borrow.local_bind_addr.port();
            let implicated_cid = borrow.implicated_cid.clone();
            let kernel_tx = borrow.kernel_tx.clone();
            let primary_stream = borrow.to_primary_stream.clone().unwrap();
            let is_server = borrow.is_server;
            (
                remote_peer,
                local_primary_port,
                implicated_cid,
                kernel_tx,
                primary_stream,
                None,
                is_server,
            )
        };

        fn evaluate_result(
            result: Result<PrimaryProcessorResult, NetworkError>,
            primary_stream: &OutboundPrimaryStreamSender,
            kernel_tx: &UnboundedSender<NodeResult>,
            session: &CitadelSession,
            cid_opt: Option<u64>,
        ) -> std::io::Result<()> {
            match result {
                Ok(PrimaryProcessorResult::ReplyToSender(return_packet)) => {
                    CitadelSession::send_to_primary_stream_closure(
                        primary_stream,
                        kernel_tx,
                        return_packet,
                        None,
                        cid_opt,
                    )
                    .map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Unable to ReplyToSender: {:?}", err.into_string()),
                        )
                    })
                }

                Err(reason) => {
                    log::error!(target: "citadel", "[PrimaryProcessor] session ending: {:?} | Session end state: {:?}", reason, session.state.load(Ordering::Relaxed));
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        reason.into_string(),
                    ))
                }

                Ok(PrimaryProcessorResult::EndSession(reason)) => {
                    log::warn!(target: "citadel", "[PrimaryProcessor] session ending: {}", reason);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, reason))
                }

                Ok(PrimaryProcessorResult::Void) => {
                    // this implies that the packet processor found no reason to return a message
                    Ok(())
                }
            }
        }

        fn handle_session_terminating_error(
            session: &CitadelSession,
            err: std::io::Error,
            is_server: bool,
            peer_cid: Option<u64>,
        ) -> SessionShutdownReason {
            const _WINDOWS_FORCE_SHUTDOWN: i32 = 10054;
            const _RST: i32 = 104;
            const _ECONN_RST: i32 = 54; // for macs

            let error = err.raw_os_error().unwrap_or(-1);
            // error != WINDOWS_FORCE_SHUTDOWN && error != RST && error != ECONN_RST &&
            if error != -1 {
                log::error!(target: "citadel", "primary port reader error {}: {}. is server: {}. P2P: {}", error, err.to_string(), is_server, peer_cid.is_some());
            }

            let err_string = err.to_string();

            if err_string.contains(SUCCESS_DISCONNECT) {
                SessionShutdownReason::ProperShutdown
            } else {
                let implicated_cid = session.implicated_cid.get().unwrap_or_default();
                let v_conn_type = if let Some(peer_cid) = peer_cid {
                    VirtualConnectionType::LocalGroupPeer {
                        implicated_cid,
                        peer_cid,
                    }
                } else {
                    VirtualConnectionType::LocalGroupServer { implicated_cid }
                };

                if let Err(err) = session.send_to_kernel(NodeResult::Disconnect(Disconnect {
                    ticket: session.kernel_ticket.get(),
                    cid_opt: session.implicated_cid.get(),
                    success: false,
                    v_conn_type: Some(v_conn_type),
                    message: err_string.clone(),
                })) {
                    log::error!(target: "citadel", "Error sending disconnect signal to kernel: {err:?}");
                }

                if peer_cid.is_none() {
                    // If this is a c2s connection, close the session
                    session.send_session_dc_signal(
                        Some(session.kernel_ticket.get()),
                        false,
                        err_string.as_str(),
                    );
                }

                SessionShutdownReason::Error(NetworkError::Generic(err_string))
            }
        }

        let reader = async_stream::stream! {
            while let Some(packet) = reader.next().await {
                yield packet
            }
        };

        let res = reader
            .try_for_each_concurrent(None, |packet| async move {
                let implicated_cid = implicated_cid.get();
                let result = packet_processor::raw_primary_packet::process_raw_packet(
                    implicated_cid,
                    this_main,
                    *remote_peer,
                    *local_primary_port,
                    packet,
                )
                .await;
                evaluate_result(result, primary_stream, kernel_tx, this_main, implicated_cid)
            })
            .map_err(|err| handle_session_terminating_error(this_main, err, is_server, peer_cid))
            .await;

        match res {
            Ok(ok) => Ok(ok),
            Err(err) => match err {
                SessionShutdownReason::Error(err) => Err(err),
                SessionShutdownReason::ProperShutdown => Ok(()),
            },
        }
    }

    pub(crate) fn send_to_primary_stream_closure(
        to_primary_stream: &OutboundPrimaryStreamSender,
        kernel_tx: &UnboundedSender<NodeResult>,
        msg: BytesMut,
        ticket: Option<Ticket>,
        cid_opt: Option<u64>,
    ) -> Result<(), NetworkError> {
        if let Err(err) = to_primary_stream.unbounded_send(msg) {
            kernel_tx
                .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                    ticket_opt: ticket,
                    cid_opt,
                    message: err.to_string(),
                }))
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
            Err(NetworkError::InternalError("Primary stream closed"))
        } else {
            Ok(())
        }
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    async fn execute_queue_worker(this_main: CitadelSession) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "HdpSession async timer subroutine executed");

        let queue_worker = {
            //let this_interval = this_main.clone();
            let borrow = this_main;
            let (mut queue_worker, sender) = SessionQueueWorker::new(borrow.stopper_tx.get());
            inner_mut_state!(borrow.state_container)
                .queue_handle
                .set_once(sender.clone());
            borrow.queue_handle.set_once(sender);

            queue_worker.load_state_container(borrow.state_container.clone());
            let time_tracker = borrow.time_tracker;
            let time_tracker_2 = time_tracker;

            let kernel_ticket = borrow.kernel_ticket.get();
            let is_server = borrow.is_server;
            drop(borrow);

            // now, begin loading the subroutines
            //let mut loop_idx = 0;
            queue_worker.insert_reserved_fn(
                Some(QueueWorkerTicket::Oneshot(
                    PROVISIONAL_CHECKER,
                    RESERVED_CID_IDX,
                )),
                LOGIN_EXPIRATION_TIME,
                |state_container| {
                    if state_container.state.load(Ordering::SeqCst) != SessionState::Connected {
                        QueueWorkerResult::EndSession
                    } else {
                        // remove it from being called again
                        QueueWorkerResult::Complete
                    }
                },
            );

            if !is_server {
                queue_worker.insert_reserved_fn(Some(QueueWorkerTicket::Periodic(DRILL_REKEY_WORKER, 0)), Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE), move |state_container| {
                    let ticket = kernel_ticket;

                    if state_container.state.load(Ordering::Relaxed) == SessionState::Connected {
                        let timestamp = time_tracker.get_global_time_ns();

                        let security_level = state_container.session_security_settings.as_ref().map(|r| r.security_level).unwrap();

                        let p2p_sessions = state_container.active_virtual_connections.iter().filter_map(|vconn| {
                            if vconn.1.endpoint_container.as_ref()?.endpoint_crypto.local_is_initiator && vconn.1.is_active.load(Ordering::SeqCst) && vconn.1.last_delivered_message_timestamp.get().map(|r| r.elapsed() > Duration::from_millis(15000)).unwrap_or(true) {
                                Some(vconn.1.connection_type)
                            } else {
                                None
                            }
                        }).collect::<Vec<VirtualTargetType>>();

                        let virtual_target = VirtualTargetType::LocalGroupServer { implicated_cid: C2S_ENCRYPTION_ONLY };
                        if state_container.initiate_drill_update(timestamp, virtual_target, Some(ticket)).is_ok() {
                            // now, call for each p2p session
                            for vconn in p2p_sessions {
                                if let Err(err) = state_container.initiate_drill_update(timestamp, vconn, None) {
                                    log::warn!(target: "citadel", "Unable to initiate drill update for {:?}: {:?}", vconn, err);
                                }
                            }

                            QueueWorkerResult::AdjustPeriodicity(calculate_update_frequency(security_level.value(), &state_container.transfer_stats))
                        } else {
                            log::warn!(target: "citadel", "initiate_drill_update subroutine signalled failure");
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
                            log::error!(target: "citadel", "The keep alive subsystem has timed out. Executing shutdown phase (skipping proper disconnect)");
                            QueueWorkerResult::EndSession
                        } else {
                            QueueWorkerResult::Incomplete
                        }
                    } else {
                        log::error!(target: "citadel", "Keep alive subsystem will not be used for this session as requested");
                        QueueWorkerResult::Complete
                    }
                } else {
                    // keep it running, as we may be in provisional mode
                    QueueWorkerResult::Incomplete
                }
            });

            queue_worker.insert_reserved_fn(
                Some(QueueWorkerTicket::Periodic(FIREWALL_KEEP_ALIVE, 0)),
                FIREWALL_KEEP_ALIVE_UDP,
                move |state_container| {
                    if state_container.state.load(Ordering::SeqCst) == SessionState::Connected {
                        if state_container.udp_mode == UdpMode::Disabled {
                            //log::trace!(target: "citadel", "TCP only mode detected. Removing FIREWALL_KEEP_ALIVE subroutine");
                            return QueueWorkerResult::Complete;
                        }

                        if let Some(tx) = state_container.udp_primary_outbound_tx.as_ref() {
                            if !tx.needs_manual_ka {
                                return QueueWorkerResult::Complete;
                            }

                            let _ = tx.send_keep_alive();
                        }
                    }

                    QueueWorkerResult::Incomplete
                },
            );

            queue_worker
        };

        queue_worker.await
    }

    pub fn revfs_pull(
        &self,
        ticket: Ticket,
        v_conn: VirtualConnectionType,
        virtual_path: PathBuf,
        delete_on_pull: bool,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        self.ensure_connected(&ticket)?;
        let mut state_container = inner_mut_state!(self.state_container);
        let ts = self.time_tracker.get_global_time_ns();

        match v_conn {
            VirtualConnectionType::LocalGroupServer {
                implicated_cid: _implicated_cid,
            } => {
                let crypt_container = &mut state_container
                    .c2s_channel_container
                    .as_mut()
                    .unwrap()
                    .peer_session_crypto;

                let latest_hr = crypt_container.get_hyper_ratchet(None).unwrap();
                let packet = packet_crafter::file::craft_revfs_pull(
                    latest_hr,
                    security_level,
                    ticket,
                    ts,
                    C2S_ENCRYPTION_ONLY,
                    virtual_path,
                    delete_on_pull,
                );
                self.send_to_primary_stream(Some(ticket), packet)
            }
            VirtualConnectionType::LocalGroupPeer {
                implicated_cid: _,
                peer_cid: target_cid,
            } => {
                let endpoint_container =
                    state_container.get_peer_endpoint_container_mut(target_cid)?;
                let latest_hr = endpoint_container
                    .endpoint_crypto
                    .get_hyper_ratchet(None)
                    .unwrap();
                let packet = packet_crafter::file::craft_revfs_pull(
                    latest_hr,
                    security_level,
                    ticket,
                    ts,
                    target_cid,
                    virtual_path,
                    delete_on_pull,
                );
                let primary_stream = endpoint_container
                    .get_direct_p2p_primary_stream()
                    .unwrap_or_else(|| self.to_primary_stream.as_ref().unwrap());
                primary_stream
                    .unbounded_send(packet)
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            }

            ty => Err(NetworkError::msg(format!(
                "REVFS is not yet enabled for virtual connections of type {ty:?}"
            ))),
        }
    }

    pub fn revfs_delete(
        &self,
        ticket: Ticket,
        v_conn: VirtualConnectionType,
        virtual_path: PathBuf,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        self.ensure_connected(&ticket)?;

        let mut state_container = inner_mut_state!(self.state_container);
        let ts = self.time_tracker.get_global_time_ns();

        match v_conn {
            VirtualConnectionType::LocalGroupServer {
                implicated_cid: _implicated_cid,
            } => {
                let crypt_container = &mut state_container
                    .c2s_channel_container
                    .as_mut()
                    .unwrap()
                    .peer_session_crypto;

                let latest_hr = crypt_container.get_hyper_ratchet(None).unwrap();
                let packet = packet_crafter::file::craft_revfs_delete(
                    latest_hr,
                    security_level,
                    ticket,
                    ts,
                    C2S_ENCRYPTION_ONLY,
                    virtual_path,
                );
                self.send_to_primary_stream(Some(ticket), packet)
            }
            VirtualConnectionType::LocalGroupPeer {
                implicated_cid: _,
                peer_cid: target_cid,
            } => {
                let endpoint_container =
                    state_container.get_peer_endpoint_container_mut(target_cid)?;
                let latest_hr = endpoint_container
                    .endpoint_crypto
                    .get_hyper_ratchet(None)
                    .unwrap();
                let packet = packet_crafter::file::craft_revfs_delete(
                    latest_hr,
                    security_level,
                    ticket,
                    ts,
                    target_cid,
                    virtual_path,
                );
                let primary_stream = endpoint_container
                    .get_direct_p2p_primary_stream()
                    .unwrap_or_else(|| self.to_primary_stream.as_ref().unwrap());
                primary_stream
                    .unbounded_send(packet)
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            }

            ty => Err(NetworkError::msg(format!(
                "REVFS is not yet enabled for virtual connections of type {ty:?}"
            ))),
        }
    }

    fn ensure_connected(&self, ticket: &Ticket) -> Result<(), NetworkError> {
        if self.state.load(Ordering::Relaxed) != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send a request (ticket: {ticket}) outbound, but the session is not connected")))
        } else {
            Ok(())
        }
    }

    /// Similar to process_outbound_packet, but optimized to handle files
    /// The `local_encryption_level` refers to the security applied to the file that already exists,
    /// note, the desired applied encryption level. The desired applied encryption level is inside the
    /// `transfer_type` parameter
    // TODO: Reduce cognitive complexity
    #[allow(clippy::too_many_arguments)]
    pub fn process_outbound_file(
        &self,
        ticket: Ticket,
        max_group_size: Option<usize>,
        source: Box<dyn ObjectSource>,
        virtual_target: VirtualTargetType,
        security_level: SecurityLevel,
        transfer_type: TransferType,
        local_encryption_level: Option<SecurityLevel>,
        virtual_object_metadata: Option<VirtualObjectMetadata>,
        post_close_hook: impl for<'a> FnOnce(PathBuf) + Send + 'static,
    ) -> Result<(), NetworkError> {
        let this = self;
        let source_path = source.path().ok_or_else(|| {
            NetworkError::InternalError("The source object does not have a path location")
        })?;

        let file =
            File::open(&source_path).map_err(|err| NetworkError::Generic(err.to_string()))?;

        if let Some(virtual_object_metadata) = &virtual_object_metadata {
            let expected_min_length = virtual_object_metadata.plaintext_length;
            let file_length = file
                .length()
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
            if file_length < expected_min_length as u64 {
                log::warn!(target: "citadel", "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem: Current file length: {file_length}, expected min length: {expected_min_length}");
                return Err(NetworkError::InternalError(
                    "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem",
                ));
            }
        }

        let file_metadata = file
            .metadata()
            .map_err(|err| NetworkError::Generic(err.to_string()))?;

        self.ensure_connected(&ticket)?;

        let file_name = source
            .get_source_name()
            .map_err(|err| NetworkError::msg(err.into_string()))?;

        let time_tracker = this.time_tracker;
        let timestamp = this.time_tracker.get_global_time_ns();
        let (group_sender, group_sender_rx) = channel(5);
        let mut group_sender_rx =
            citadel_io::tokio_stream::wrappers::ReceiverStream::new(group_sender_rx);
        let (stop_tx, stop_rx) = citadel_io::tokio::sync::oneshot::channel();
        // the above are the same for all vtarget types. Now, we need to get the proper drill and pqc

        let mut state_container = inner_mut_state!(this.state_container);

        log::trace!(target: "citadel", "Transmit file name: {}", &file_name);
        // the key cid must be differentiated from the target cid because the target_cid needs to be zero if
        // there is no proxying. the key cid cannot be zero; if client -> server, key uses implicated cid
        let (
            to_primary_stream,
            file_header,
            object_id,
            target_cid,
            key_cid,
            groups_needed,
            metadata,
        ) = match virtual_target {
            VirtualTargetType::LocalGroupServer { implicated_cid } => {
                // if we are sending this just to the HyperLAN server (in the case of file uploads),
                // then, we use this session's pqc, the cnac's latest drill, and 0 for target_cid
                if !*self.file_transfer_compatible {
                    return Err(NetworkError::msg("File transfer is not enabled for this session. Both nodes must use a filesystem backend"));
                }

                let crypt_container = &mut state_container
                    .c2s_channel_container
                    .as_mut()
                    .unwrap()
                    .peer_session_crypto;
                let object_id = virtual_object_metadata
                    .as_ref()
                    .map(|r| r.object_id)
                    .unwrap_or_else(|| crypt_container.get_next_object_id());
                let group_id_start = crypt_container.get_and_increment_group_id();
                let latest_hr = crypt_container.get_hyper_ratchet(None).cloned().unwrap();
                let static_aux_ratchet = crypt_container
                    .toolset
                    .get_static_auxiliary_ratchet()
                    .clone();

                let to_primary_stream = this.to_primary_stream.clone().unwrap();
                let target_cid = 0;
                let (file_size, groups_needed, _max_bytes_per_group) = scramble_encrypt_source(
                    source,
                    max_group_size,
                    object_id,
                    group_sender,
                    stop_rx,
                    security_level,
                    latest_hr.clone(),
                    static_aux_ratchet,
                    HDP_HEADER_BYTE_LEN,
                    target_cid,
                    group_id_start,
                    transfer_type.clone(),
                    packet_crafter::group::craft_wave_payload_packet_into,
                )
                .map_err(|err| NetworkError::Generic(err.to_string()))?;

                let date_created = file_metadata.created().unwrap_or(SystemTime::now());

                let file_metadata = VirtualObjectMetadata {
                    object_id,
                    name: file_name,
                    date_created: chrono::DateTime::from_timestamp(
                        date_created.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                        0,
                    )
                    .expect("Invalid timestamp")
                    .to_rfc2822(),
                    author: implicated_cid.to_string(),
                    plaintext_length: file_size,
                    group_count: groups_needed,
                    cid: implicated_cid,
                    transfer_type,
                };

                // if 1 group, we don't need to reserve any more group IDs. If 2, then we reserve just one. 3, then 2
                let amt_to_reserve = groups_needed.saturating_sub(1);
                crypt_container.rolling_group_id += amt_to_reserve as u64;
                let file_header = packet_crafter::file::craft_file_header_packet(
                    &latest_hr,
                    group_id_start,
                    ticket,
                    security_level,
                    virtual_target,
                    file_metadata.clone(),
                    timestamp,
                    local_encryption_level,
                );
                (
                    to_primary_stream,
                    file_header,
                    object_id,
                    target_cid,
                    implicated_cid,
                    groups_needed,
                    file_metadata,
                )
            }

            VirtualConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: target_cid,
            } => {
                log::trace!(target: "citadel", "Sending HyperLAN peer ({}) <-> HyperLAN Peer ({})", implicated_cid, target_cid);
                // here, we don't use the base session's PQC. Instead, we use the c2s vconn's pqc to ensure the peer can't access the contents
                // of the file
                let crypt_container_c2s = &state_container
                    .c2s_channel_container
                    .as_ref()
                    .unwrap()
                    .peer_session_crypto;
                let static_aux_ratchet = crypt_container_c2s
                    .toolset
                    .get_static_auxiliary_ratchet()
                    .clone();

                let endpoint_container =
                    state_container.get_peer_endpoint_container_mut(target_cid)?;

                if !endpoint_container.file_transfer_compatible {
                    return Err(NetworkError::msg("File transfer is not enabled for this p2p session. Both nodes must use a filesystem backend"));
                }

                let object_id = virtual_object_metadata
                    .as_ref()
                    .map(|r| r.object_id)
                    .unwrap_or_else(|| endpoint_container.endpoint_crypto.get_next_object_id());
                // reserve group ids
                let start_group_id = endpoint_container
                    .endpoint_crypto
                    .get_and_increment_group_id();

                let latest_usable_ratchet = endpoint_container
                    .endpoint_crypto
                    .get_hyper_ratchet(None)
                    .unwrap();

                let preferred_primary_stream = endpoint_container
                    .get_direct_p2p_primary_stream()
                    .cloned()
                    .unwrap_or_else(|| this.to_primary_stream.clone().unwrap());

                let (file_size, groups_needed, _max_bytes_per_group) = scramble_encrypt_source(
                    source,
                    max_group_size,
                    object_id,
                    group_sender,
                    stop_rx,
                    security_level,
                    latest_usable_ratchet.clone(),
                    static_aux_ratchet,
                    HDP_HEADER_BYTE_LEN,
                    target_cid,
                    start_group_id,
                    transfer_type.clone(),
                    packet_crafter::group::craft_wave_payload_packet_into,
                )
                .map_err(|err| NetworkError::Generic(err.to_string()))?;

                let date_created = file_metadata.created().unwrap_or(SystemTime::now());

                let file_metadata = VirtualObjectMetadata {
                    object_id,
                    name: file_name,
                    date_created: chrono::DateTime::from_timestamp(
                        date_created.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                        0,
                    )
                    .expect("Invalid timestamp")
                    .to_rfc2822(),
                    author: implicated_cid.to_string(),
                    plaintext_length: file_size,
                    group_count: groups_needed,
                    cid: implicated_cid,
                    transfer_type,
                };

                let file_header = packet_crafter::file::craft_file_header_packet(
                    latest_usable_ratchet,
                    start_group_id,
                    ticket,
                    security_level,
                    virtual_target,
                    file_metadata.clone(),
                    timestamp,
                    local_encryption_level,
                );

                // if 1 group, we don't need to reserve any more group IDs. If 2, then we reserve just one. 3, then 2
                let amt_to_reserve = groups_needed.saturating_sub(1);
                endpoint_container.endpoint_crypto.rolling_group_id += amt_to_reserve as u64;

                (
                    preferred_primary_stream,
                    file_header,
                    object_id,
                    target_cid,
                    target_cid,
                    groups_needed,
                    file_metadata,
                )
            }

            _ => {
                log::error!(target: "citadel", "HyperWAN functionality not yet implemented");
                return Err(NetworkError::InternalError(
                    "HyperWAN functionality not yet implemented",
                ));
            }
        };

        // now that the async cryptscrambler tasks have been spawned on the threadpool, we need to also
        // spawn tasks that read the [GroupSenders] from there. We also need to store an [OutboundFileMetadataTransmitter]
        // to store the stopper. After spawning them, the rest is under control. Note: for the async task that spawns here
        // should be given a Rc<RefCell<StateContainer>>. Finally, since two vpeers may send to the source we are sending
        // to, the GROUP HEADER ACK needs to return the group start idx. It is expected the adjacent node reserve enough groups
        // on its end to take into account

        // send the FILE_HEADER
        to_primary_stream
            .unbounded_send(file_header)
            .map_err(|_| NetworkError::InternalError("Primary stream disconnected"))?;
        // create the outbound file container
        let kernel_tx = state_container.kernel_tx.clone();
        let (next_gs_alerter, next_gs_alerter_rx) = unbounded();
        let mut next_gs_alerter_rx =
            citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(next_gs_alerter_rx);
        let (start, start_rx) = citadel_io::tokio::sync::oneshot::channel();
        let outbound_file_transfer_container = OutboundFileTransfer {
            stop_tx: Some(stop_tx),
            metadata,
            ticket,
            next_gs_alerter: next_gs_alerter.clone(),
            start: Some(start),
        };
        let file_key = FileKey::new(object_id);
        let _ = state_container
            .outbound_files
            .insert(file_key, outbound_file_transfer_container);
        // spawn the task that takes GroupSenders from the threadpool cryptscrambler
        drop(state_container);

        let this = self.clone();
        let future = async move {
            let this = &this;
            let next_gs_alerter = &next_gs_alerter;
            // this future will resolve when the sender drops in the file_crypt_scrambler
            match start_rx.await {
                Ok(false) => {
                    log::warn!(target: "citadel", "start_rx signalled to NOT begin streaming process. Ending async subroutine");
                    return;
                }
                Err(err) => {
                    log::error!(target: "citadel", "start_rx error occurred: {:?}", err);
                    return;
                }

                _ => {}
            }

            log::trace!(target: "citadel", "Outbound file transfer async subroutine signalled to begin!");

            // TODO: planning/overhaul of file transmission process
            // By now, the file container has been created remotely and locally
            // We have been signalled to begin polling the group sender
            // NOTE: polling the group_sender_rx (eventually) stops polling the
            // async crypt scrambler. Up to 5 groups can be enqueued before stopping
            // Once 5 groups have enqueued, the only way to continue is if the receiving
            // end tells us it finished that group, and, we poll the next() group sender below.
            //

            let mut relative_group_id = 0;
            let implicated_cid = this.implicated_cid.get();
            // while waiting, we likely have a set of GroupSenders to process
            while let Some(sender) = group_sender_rx.next().await {
                match sender {
                    Ok(sender) => {
                        let (group_id, key) = {
                            // construct the OutboundTransmitters
                            let sess = this;
                            if sess.state.load(Ordering::Relaxed) != SessionState::Connected {
                                log::warn!(target: "citadel", "Since transmitting the file, the session ended");
                                return;
                            }

                            let mut state_container = inner_mut_state!(sess.state_container);

                            let proper_latest_hyper_ratchet = match virtual_target {
                                VirtualConnectionType::LocalGroupServer { implicated_cid: _ } => {
                                    state_container
                                        .c2s_channel_container
                                        .as_ref()
                                        .unwrap()
                                        .peer_session_crypto
                                        .get_hyper_ratchet(None)
                                }
                                VirtualConnectionType::LocalGroupPeer {
                                    implicated_cid: _,
                                    peer_cid,
                                } => match state_container.get_peer_session_crypto(peer_cid) {
                                    Some(peer_sess_crypt) => {
                                        peer_sess_crypt.get_hyper_ratchet(None)
                                    }

                                    None => {
                                        log::warn!(target: "citadel", "Since transmitting the file, the peer session ended");
                                        return;
                                    }
                                },

                                _ => {
                                    log::error!(target: "citadel", "HyperWAN Functionality not implemented");
                                    return;
                                }
                            };

                            if proper_latest_hyper_ratchet.is_none() {
                                log::error!(target: "citadel", "Unable to unwrap StackedRatchet (X-05)");
                                return;
                            }

                            let hyper_ratchet = proper_latest_hyper_ratchet.unwrap();

                            let mut transmitter = GroupTransmitter::new_from_group_sender(
                                to_primary_stream.clone(),
                                sender,
                                RatchetPacketCrafterContainer::new(hyper_ratchet.clone(), None),
                                object_id,
                                ticket,
                                security_level,
                                time_tracker,
                            );
                            // group_id is unique per session
                            let group_id = transmitter.group_id;

                            // We manually send the header. The tails get sent automatically
                            log::trace!(target: "citadel", "Sending GROUP HEADER through primary stream for group {}", group_id);
                            if let Err(err) = sess.try_action(Some(ticket), || {
                                transmitter.transmit_group_header(virtual_target)
                            }) {
                                log::error!(target: "citadel", "Unable to send through primary stream: {}", err.to_string());
                                return;
                            }
                            let group_byte_len = transmitter.get_total_plaintext_bytes();

                            let outbound_container = OutboundTransmitterContainer::new(
                                Some(next_gs_alerter.clone()),
                                transmitter,
                                group_byte_len,
                                groups_needed,
                                relative_group_id,
                                ticket,
                            );
                            relative_group_id += 1;
                            // The payload packets won't be sent until a GROUP_HEADER_ACK is received
                            // the key is the target_cid coupled with the group id
                            let key = GroupKey::new(key_cid, group_id, object_id);

                            assert!(state_container
                                .outbound_transmitters
                                .insert(key, outbound_container)
                                .is_none());
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
                                    let transmitter = &transmitter.burst_transmitter.group_transmitter;
                                    if transmitter.has_expired(GROUP_EXPIRE_TIME_MS) {
                                        if state_container.meta_expiry_state.expired() {
                                            log::error!(target: "citadel", "Outbound group {} has expired; dropping entire transfer", group_id);
                                            //std::mem::drop(transmitter);
                                            if let Some(mut outbound_container) = state_container.outbound_files.remove(&file_key) {
                                                if let Some(stop) = outbound_container.stop_tx.take() {
                                                    if stop.send(()).is_err() {
                                                        log::error!(target: "citadel", "Unable to send stop signal");
                                                    }
                                                }
                                            } else {
                                                log::warn!(target: "citadel", "Attempted to remove {:?}, but was already absent from map", &file_key);
                                            }

                                            if kernel_tx2.unbounded_send(NodeResult::InternalServerError(InternalServerError {
                                                ticket_opt: Some(ticket),
                                                cid_opt: implicated_cid,
                                                message: format!("Timeout on ticket {ticket}")
                                            })).is_err() {
                                                log::error!(target: "citadel", "[File] Unable to send kernel error signal. Ending session");
                                                QueueWorkerResult::EndSession
                                            } else {
                                                QueueWorkerResult::Complete
                                            }
                                        } else {
                                            log::trace!(target: "citadel", "Other outbound groups being processed; patiently awaiting group {}", group_id);
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

                        if (next_gs_alerter_rx.next().await).is_none() {
                            log::warn!(target: "citadel", "next_gs_alerter: steam ended");
                            return;
                        }
                    }

                    Err(err) => {
                        let _ = kernel_tx
                            .clone()
                            .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                                ticket_opt: Some(ticket),
                                cid_opt: implicated_cid,
                                message: err.to_string(),
                            }));
                    }
                }
            }

            // we finished pulling. Now, execute the hook if present
            post_close_hook(source_path);
        };

        spawn!(future);

        Ok(())
    }

    // TODO: Make a generic version to allow requests the ability to bypass the session manager
    pub(crate) fn spawn_message_sender_function(
        this: CitadelSession,
        mut rx: citadel_io::tokio::sync::mpsc::Receiver<SessionRequest>,
    ) {
        let task = async move {
            let this = &this;
            let mut stopper_rx = inner!(this.stopper_tx).subscribe();
            let to_kernel_tx = &this.kernel_tx.clone();

            let stopper = async move {
                stopper_rx
                    .recv()
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            };

            let receiver = async move {
                while let Some(request) = rx.recv().await {
                    let mut state_container = inner_mut_state!(this.state_container);

                    match request {
                        // (ticket, message, v_target, security_level)
                        SessionRequest::SendMessage {
                            ticket,
                            packet,
                            target,
                            security_level,
                        } => {
                            if let Err(err) = state_container.process_outbound_message(
                                ticket,
                                packet,
                                target,
                                security_level,
                                false,
                            ) {
                                to_kernel_tx
                                    .unbounded_send(NodeResult::InternalServerError(
                                        InternalServerError {
                                            ticket_opt: Some(ticket),
                                            cid_opt: this.implicated_cid.get(),
                                            message: err.into_string(),
                                        },
                                    ))
                                    .map_err(|err| NetworkError::Generic(err.to_string()))?
                            }
                        }

                        SessionRequest::Group { ticket, broadcast } => {
                            if let Err(err) = state_container
                                .process_outbound_broadcast_command(ticket, &broadcast)
                            {
                                to_kernel_tx
                                    .unbounded_send(NodeResult::InternalServerError(
                                        InternalServerError {
                                            ticket_opt: Some(ticket),
                                            cid_opt: this.implicated_cid.get(),
                                            message: err.into_string(),
                                        },
                                    ))
                                    .map_err(|err| NetworkError::Generic(err.to_string()))?
                            }
                        }
                    }
                }

                Ok(())
            };

            citadel_io::tokio::select! {
                res0 = stopper => res0,
                res1 = receiver => res1
            }
        };

        spawn!(task);
    }

    #[allow(unused_results)]
    pub(crate) async fn dispatch_peer_command(
        &self,
        ticket: Ticket,
        peer_command: PeerSignal,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "Dispatching peer command {:?} ...", peer_command);
        let this = self;
        let state = this.state.load(Ordering::SeqCst);

        if state != SessionState::Connected {
            log::warn!(target: "citadel", "Session is not connected (s={:?}); will still attempt send peer command {:?}", state, peer_command)
        }

        let timestamp = this.time_tracker.get_global_time_ns();

        let mut state_container = inner_mut_state!(this.state_container);

        // TODO: send errors if any commands have Some() responses
        if let Some(to_primary_stream) = this.to_primary_stream.as_ref() {
            let signal_processed = match peer_command {
                PeerSignal::Disconnect {
                    peer_conn_type: v_conn,
                    disconnect_response: resp,
                } => {
                    let target = v_conn.get_original_target_cid();
                    if !state_container
                        .active_virtual_connections
                        .contains_key(&target)
                    {
                        return self
                            .send_to_kernel(NodeResult::PeerEvent(PeerEvent {
                                event: PeerSignal::Disconnect {
                                    peer_conn_type: v_conn,
                                    disconnect_response: Some(PeerResponse::Disconnected(
                                        "Peer session already disconnected".to_string(),
                                    )),
                                },
                                ticket,
                                implicated_cid: self.implicated_cid.get().ok_or_else(|| {
                                    NetworkError::InternalError("Implicated CID not set")
                                })?,
                            }))
                            .map_err(|err| NetworkError::Generic(err.to_string()));
                    }

                    PeerSignal::Disconnect {
                        peer_conn_type: v_conn,
                        disconnect_response: resp,
                    }
                }
                PeerSignal::DisconnectUDP { peer_conn_type } => {
                    // disconnect UDP locally
                    log::trace!(target: "citadel", "Closing UDP subsystem locally ...");
                    state_container.remove_udp_channel(peer_conn_type.get_original_target_cid());
                    PeerSignal::DisconnectUDP { peer_conn_type }
                }

                PeerSignal::PostConnect {
                    peer_conn_type: a,
                    ticket_opt: b,
                    invitee_response,
                    session_security_settings: d,
                    udp_mode: e,
                    session_password,
                } => {
                    let session_password = session_password.unwrap_or_default();
                    if state_container
                        .outgoing_peer_connect_attempts
                        .contains_key(&a.get_original_target_cid())
                    {
                        log::warn!(target: "citadel", "{} is already attempting to connect to {}", a.get_original_implicated_cid(), a.get_original_target_cid())
                    }

                    state_container
                        .store_session_password(a.get_original_target_cid(), session_password);

                    // in case the ticket gets mapped during simultaneous_connect, store locally
                    let _ = state_container
                        .outgoing_peer_connect_attempts
                        .insert(a.get_original_target_cid(), ticket);
                    PeerSignal::PostConnect {
                        peer_conn_type: a,
                        ticket_opt: b,
                        invitee_response,
                        session_security_settings: d,
                        udp_mode: e,
                        session_password: None,
                    }
                }

                n => n,
            };

            let hyper_ratchet = state_container
                .c2s_channel_container
                .as_ref()
                .ok_or_else(|| {
                    NetworkError::msg(format!(
                        "C2S container not loaded; cannot send peer command {signal_processed:?}"
                    ))
                })?
                .peer_session_crypto
                .get_hyper_ratchet(None)
                .unwrap();
            let packet = super::packet_crafter::peer_cmd::craft_peer_signal(
                hyper_ratchet,
                signal_processed,
                ticket,
                timestamp,
                security_level,
            );

            to_primary_stream
                .unbounded_send(packet)
                .map_err(|err| NetworkError::SocketError(err.to_string()))
        } else {
            Err(NetworkError::InternalError("Invalid configuration"))
        }
    }

    async fn listen_udp_port<S: UdpStream>(
        this: CitadelSession,
        _hole_punched_addr_ip: IpAddr,
        local_port: u16,
        mut stream: S,
        peer_session_accessor: EndpointCryptoAccessor,
    ) -> Result<(), NetworkError> {
        while let Some(res) = stream.next().await {
            match res {
                Ok((packet, remote_peer)) => {
                    log::trace!(target: "citadel", "packet received on waveport {} has {} bytes (src: {:?})", local_port, packet.len(), &remote_peer);
                    let packet = HdpPacket::new_recv(packet, remote_peer, local_port);
                    this.process_inbound_packet_udp(packet, &peer_session_accessor)?;
                }

                Err(err) => {
                    log::warn!(target: "citadel", "UDP Stream error: {:#?}", err);
                    break;
                }
            }
        }

        log::trace!(target: "citadel", "Ending waveport listener on {}", local_port);

        Ok(())
    }

    async fn udp_outbound_sender<S: SinkExt<Bytes> + Unpin>(
        receiver: UnboundedReceiver<(u8, BytesMut)>,
        hole_punched_addr: TargettedSocketAddr,
        mut sink: S,
        peer_session_accessor: EndpointCryptoAccessor,
    ) -> Result<(), NetworkError> {
        let mut receiver =
            citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(receiver);
        let target_cid = peer_session_accessor.get_target_cid();

        while let Some((cmd_aux, packet)) = receiver.next().await {
            let send_addr = hole_punched_addr.send_address;
            let packet = peer_session_accessor.borrow_hr(None, |hr, _| {
                packet_crafter::udp::craft_udp_packet(
                    hr,
                    cmd_aux,
                    packet,
                    target_cid,
                    SecurityLevel::Standard,
                )
            })?;
            log::trace!(target: "citadel", "About to send packet w/len {} | Dest: {:?}", packet.len(), &send_addr);
            sink.send(packet.freeze()).await.map_err(|_| {
                NetworkError::InternalError("UDP sink unable to receive outbound requests")
            })?;
        }

        log::trace!(target: "citadel", "Outbound wave sender ending");

        Ok(())
    }

    pub fn process_inbound_packet_udp(
        &self,
        packet: HdpPacket,
        accessor: &EndpointCryptoAccessor,
    ) -> Result<(), NetworkError> {
        if packet.get_length() < HDP_HEADER_BYTE_LEN {
            return Ok(());
        }

        if let Some((header, _)) = packet.parse() {
            // we only process streaming packets
            if header.cmd_aux != packet_flags::cmd::aux::udp::STREAM {
                // discard any keep alives
                return Ok(());
            }

            let hr_version = header.drill_version.get();
            let mut endpoint_cid_info = None;
            match check_proxy(
                self.implicated_cid.get(),
                header.cmd_primary,
                header.cmd_aux,
                header.session_cid.get(),
                header.target_cid.get(),
                self,
                &mut endpoint_cid_info,
                ReceivePortType::UnorderedUnreliable,
                packet,
            ) {
                Some(packet) => {
                    match packet_processor::udp_packet::process_udp_packet(
                        self, packet, hr_version, accessor,
                    ) {
                        Ok(PrimaryProcessorResult::Void) => Ok(()),

                        Ok(PrimaryProcessorResult::EndSession(err)) => {
                            // stop the UDP stream
                            log::warn!(target: "citadel", "UDP session ending: {:?}", err);
                            Err(NetworkError::Generic(err.to_string()))
                        }

                        Err(err) => {
                            // stop the UDP stream
                            log::warn!(target: "citadel", "UDP session ending: {:?}", err);
                            Err(err)
                        }

                        _ => Ok(()),
                    }
                }

                None => Ok(()),
            }
        } else {
            log::error!(target: "citadel", "A packet was unable to be parsed");
            Ok(())
        }
    }

    /// Returns true if the disconnect initiate was a success, false if not. An error returns if something else occurs
    pub fn initiate_disconnect(&self, ticket: Ticket) -> Result<bool, NetworkError> {
        let session = self;
        if session.state.load(Ordering::Relaxed) != SessionState::Connected {
            log::error!(target: "citadel", "Must be connected to HyperLAN in order to start disconnect")
        }

        let accessor = EndpointCryptoAccessor::C2S(session.state_container.clone());
        accessor
            .borrow_hr(None, |hr, state_container| {
                let timestamp = session.time_tracker.get_global_time_ns();
                let security_level = state_container
                    .session_security_settings
                    .as_ref()
                    .map(|r| r.security_level)
                    .unwrap();
                let to_primary_stream = session.to_primary_stream.as_ref().unwrap();
                let to_kernel_tx = &session.kernel_tx;
                let disconnect_stage0_packet = packet_crafter::do_disconnect::craft_stage0(
                    hr,
                    ticket,
                    timestamp,
                    security_level,
                );
                Self::send_to_primary_stream_closure(
                    to_primary_stream,
                    to_kernel_tx,
                    disconnect_stage0_packet,
                    Some(ticket),
                    self.implicated_cid.get(),
                )
            })?
            .map(|_| true)
    }
}

impl CitadelSessionInner {
    /// Stores the proposed credentials into the register state container
    pub(crate) fn store_proposed_credentials(&mut self, proposed_credentials: ProposedCredentials) {
        let mut state_container = inner_mut_state!(self.state_container);
        state_container.register_state.passwordless = Some(proposed_credentials.is_passwordless());
        state_container.connect_state.proposed_credentials = Some(proposed_credentials);
    }

    /// When a successful login occurs, this function gets called. Must return any AsRef<[u8]> type
    pub(super) fn create_welcome_message(&self, cid: u64) -> String {
        format!(
            "Citadel login::success. Welcome to the Post-quantum network. Implicated CID: {cid}"
        )
    }

    pub(super) fn create_register_success_message(&self) -> String {
        "Citadel register::success. Welcome to your new post-quantum network! Login to interact with your new network".to_string()
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
    pub fn send_to_kernel(&self, msg: NodeResult) -> Result<(), SendError<NodeResult>> {
        self.kernel_tx.unbounded_send(msg)
    }

    /// Will send the message to the primary stream, and will alert the kernel if the stream's connector is full
    pub fn send_to_primary_stream(
        &self,
        ticket: Option<Ticket>,
        msg: BytesMut,
    ) -> Result<(), NetworkError> {
        if let Some(tx) = self.to_primary_stream.as_ref() {
            match tx.unbounded_send(msg) {
                Ok(_) => Ok(()),

                Err(err) => {
                    self.send_to_kernel(NodeResult::InternalServerError(InternalServerError {
                        ticket_opt: ticket,
                        cid_opt: self.implicated_cid.get(),
                        message: err.to_string(),
                    }))
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
                    Err(NetworkError::InternalError(
                        "Unable to send through primary stream",
                    ))
                }
            }
        } else {
            Err(NetworkError::InternalError("Primary stream sender absent"))
        }
    }

    /// will try a running a function, and if an error occurs, will send error to Kernel
    pub fn try_action<T, E: ToString>(
        &self,
        ticket: Option<Ticket>,
        fx: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, NetworkError> {
        match (fx)().map_err(|err| NetworkError::Generic(err.to_string())) {
            Err(err) => {
                self.send_to_kernel(NodeResult::InternalServerError(InternalServerError {
                    ticket_opt: ticket,
                    message: err.to_string(),
                    cid_opt: self.implicated_cid.get(),
                }))
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
                Err(err)
            }

            res => res,
        }
    }

    /// Stops the future from running
    pub fn shutdown(&self) {
        self.state
            .store(SessionState::Disconnected, Ordering::SeqCst);
        let _ = inner!(self.stopper_tx).send(());
    }

    pub(crate) fn initiate_deregister(
        &self,
        _virtual_connection_type: VirtualConnectionType,
        ticket: Ticket,
    ) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "Initiating deregister process ...");
        let accessor = EndpointCryptoAccessor::C2S(self.state_container.clone());
        accessor.borrow_hr(None, |hr, state_container| {
            let timestamp = self.time_tracker.get_global_time_ns();
            let security_level = state_container
                .session_security_settings
                .map(|r| r.security_level)
                .unwrap();
            let stage0_packet =
                packet_crafter::do_deregister::craft_stage0(hr, timestamp, security_level);

            state_container.deregister_state.on_init(timestamp, ticket);
            self.send_to_primary_stream(Some(ticket), stage0_packet)
        })?
    }

    pub(crate) fn is_provisional(&self) -> bool {
        let state = self.state.load(Ordering::Relaxed);
        //self.implicated_cid.is_none()
        // SocketJustOpened is only the state for a session created from an incoming connection
        state == SessionState::SocketJustOpened
            || state == SessionState::NeedsConnect
            || state == SessionState::ConnectionProcess
            || state == SessionState::NeedsRegister
    }

    pub(crate) fn send_session_dc_signal<T: Into<String>>(
        &self,
        ticket: Option<Ticket>,
        disconnect_success: bool,
        msg: T,
    ) {
        if self
            .session_manager
            .provisional_session_active(&self.remote_peer)
        {
            // If we are provisional, we don't need to send a disconnect signal
            return;
        }

        if let Some(tx) = self.dc_signal_sender.take() {
            let _ = tx.unbounded_send(NodeResult::Disconnect(Disconnect {
                ticket: ticket.unwrap_or_else(|| self.kernel_ticket.get()),
                cid_opt: self.implicated_cid.get(),
                success: disconnect_success,
                v_conn_type: None,
                message: msg.into(),
            }));
        }
    }

    pub(crate) fn disable_dc_signal(&self) {
        let _ = self.dc_signal_sender.take();
    }
}

impl Drop for CitadelSessionInner {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "*** Dropping HdpSession {:?} ***", self.implicated_cid.get());
        self.send_session_dc_signal(None, false, "Session dropped");

        if self.on_drop.unbounded_send(()).is_err() {
            //log::error!(target: "citadel", "Unable to cleanly alert node that session ended: {:?}", err);
        }

        let _ = inner!(self.stopper_tx).send(());
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub enum SessionRequest {
    SendMessage {
        ticket: Ticket,
        packet: SecureProtocolPacket,
        target: VirtualTargetType,
        security_level: SecurityLevel,
    },
    Group {
        ticket: Ticket,
        broadcast: GroupBroadcast,
    },
}
