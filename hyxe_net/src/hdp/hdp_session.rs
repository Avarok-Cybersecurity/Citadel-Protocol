use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};

//use async_std::prelude::*;
use bytes::{Bytes, BytesMut};
use either::Either;
use futures::{SinkExt, Stream, StreamExt, TryStreamExt, TryFutureExt};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::udp::UdpFramed;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::fcm::fcm_ratchet::{FcmAliceToBobTransfer, FcmRatchetConstructor};
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::hyper_ratchet::constructor::{ConstructorType, HyperRatchetConstructor};
use hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet};
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_crypt::toolset::Toolset;
use hyxe_fs::io::SyncIO;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::time_tracker::TimeTracker;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::external_services::fcm::kem::FcmPostRegister;
use hyxe_user::network_account::ConnectProtocol;
use hyxe_user::proposed_credentials::ProposedCredentials;
use hyxe_user::re_imports::scramble_encrypt_file;

use crate::constants::{CODEC_BUFFER_CAPACITY, DRILL_UPDATE_FREQUENCY_LOW_BASE, FIREWALL_KEEP_ALIVE_UDP, GROUP_EXPIRE_TIME_MS, HDP_HEADER_BYTE_LEN, INITIAL_RECONNECT_LOCKOUT_TIME_NS, KEEP_ALIVE_INTERVAL_MS, KEEP_ALIVE_TIMEOUT_NS, LOGIN_EXPIRATION_TIME};
use crate::error::NetworkError;
use crate::hdp::file_transfer::VirtualFileMetadata;
use crate::hdp::hdp_packet::{HdpPacket, packet_flags};
use crate::hdp::hdp_packet_crafter::{self, GroupTransmitter, RatchetPacketCrafterContainer};
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
//use futures_codec::Framed;
use crate::hdp::hdp_packet_processor::{self, PrimaryProcessorResult};
use crate::hdp::hdp_packet_processor::includes::{Duration, SocketAddr};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::hdp::hdp_server::{ConnectMode, HdpServerRemote, HdpServerResult, SecrecyMode, Ticket};
use crate::hdp::hdp_session_manager::HdpSessionManager;
use crate::hdp::misc;
use crate::hdp::misc::clean_shutdown::{CleanShutdownSink, CleanShutdownStream};
use crate::hdp::misc::dual_rwlock::DualRwLock;
use crate::hdp::misc::net::{GenericNetworkListener, GenericNetworkStream};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
//use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender, channel, TrySendError};
use crate::hdp::outbound_sender::{channel, Receiver, Sender, SendError, unbounded, UnboundedReceiver, UnboundedSender};
use crate::hdp::outbound_sender::{OutboundTcpReceiver, OutboundTcpSender, OutboundUdpSender};
use crate::hdp::peer::p2p_conn_handler::P2PInboundHandle;
use crate::hdp::peer::peer_layer::{PeerResponse, PeerSignal, UdpMode};
use crate::hdp::session_queue_handler::{DRILL_REKEY_WORKER, FIREWALL_KEEP_ALIVE, KEEP_ALIVE_CHECKER, PROVISIONAL_CHECKER, QueueWorkerResult, QueueWorkerTicket, RESERVED_CID_IDX, SessionQueueWorker};
use crate::hdp::state_container::{FileKey, GroupKey, GroupSender, OutboundFileTransfer, OutboundTransmitterContainer, StateContainer, StateContainerInner, VirtualConnectionType, VirtualTargetType};
use crate::hdp::state_subcontainers::drill_update_container::calculate_update_frequency;
use crate::hdp::time::TransferStats;
use hyxe_user::backend::PersistenceHandler;
use crate::hdp::misc::dual_cell::DualCell;
use std::ops::Deref;
use crate::hdp::misc::dual_late_init::DualLateInit;
use crate::inner_arg::ExpectedInnerTargetMut;
use crate::hdp::misc::lock_holder::LockHolder;
use crate::macros::OwnedWriteGuard;
use crate::kernel::RuntimeFuture;
use std::pin::Pin;
use hyxe_crypt::prelude::ConstructorOpts;
use crate::hdp::peer_session_crypto_accessor::PeerSessionCryptoAccessor;
use crate::hdp::hdp_packet_processor::raw_primary_packet::{check_proxy, ReceivePortType};
use crate::hdp::state_subcontainers::preconnect_state_container::UdpChannelSender;
use hyxe_nat::nat_identification::NatType;

//use crate::define_struct;

pub static STATUS: AtomicUsize = AtomicUsize::new(0);

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
    pub(super) cnac: DualRwLock<Option<ClientNetworkAccount>>,
    // Sends results directly to the kernel
    pub(super) kernel_tx: UnboundedSender<HdpServerResult>,
    pub(super) to_primary_stream: DualLateInit<Option<OutboundTcpSender>>,
    pub(super) udp_primary_outbound_tx: DualLateInit<Option<OutboundUdpSender>>,
    pub(super) p2p_session_tx: DualLateInit<Option<UnboundedSender<Pin<Box<dyn RuntimeFuture>>>>>,
    // Setting this will determine what algorithm is used during the DO_CONNECT stage
    pub(super) session_manager: HdpSessionManager,
    pub(super) state: DualCell<SessionState>,
    pub(super) implicated_user_p2p_internal_listener_addr: DualLateInit<Option<SocketAddr>>,
    pub(super) state_container: StateContainer,
    pub(super) account_manager: AccountManager,
    pub(super) time_tracker: TimeTracker,
    pub(super) local_node_type: HyperNodeType,
    pub(super) remote_node_type: Option<HyperNodeType>,
    pub(super) local_bind_addr: SocketAddr,
    // if this is enabled, then UDP won't be used
    pub(super) udp_mode: DualCell<UdpMode>,
    pub(super) do_static_hr_refresh_atexit: DualCell<bool>,
    pub(super) dc_signal_sent_to_kernel: DualCell<bool>,
    pub(super) transfer_stats: TransferStats,
    pub(super) is_server: bool,
    pub(super) needs_close_message: DualCell<bool>,
    pub(super) stopper_rx: DualRwLock<Option<Receiver<()>>>,
    pub(super) queue_worker: SessionQueueWorker,
    pub(super) fcm_keys: Option<FcmKeys>,
    pub(super) security_settings: DualCell<Option<SessionSecuritySettings>>,
    pub(super) updates_in_progress: DualRwLock<HashMap<u64, Arc<AtomicBool>>>,
    pub(super) peer_only_connect_protocol: DualRwLock<Option<ConnectProtocol>>,
    pub(super) local_nat_type: NatType,
    pub(super) adjacent_nat_type: DualLateInit<Option<NatType>>,
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
    Connect(u64),
    Register(SocketAddr),
}

impl HdpSession {
    /// Creates a new session.
    /// 'implicated_cid': Supply None if you expect to register. If Some, will check the account manager
    pub fn new(init_mode: HdpSessionInitMode, local_nat_type: NatType, peer_only_connect_proto: ConnectProtocol, cnac: Option<ClientNetworkAccount>, remote_peer: SocketAddr, proposed_credentials: ProposedCredentials, on_drop: UnboundedSender<()>, hdp_remote: HdpServerRemote, local_bind_addr: SocketAddr, local_node_type: HyperNodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, time_tracker: TimeTracker, kernel_ticket: Ticket, fcm_keys: Option<FcmKeys>, udp_mode: UdpMode, keep_alive_timeout_ns: i64, security_settings: SessionSecuritySettings) -> Result<(Sender<()>, Self), NetworkError> {
        let (cnac, state, implicated_cid) = match &init_mode {
            HdpSessionInitMode::Connect(implicated_cid) => {
                let cnac = cnac.ok_or(NetworkError::InvalidExternalRequest("Client does not exist"))?;
                (Some(cnac), DualCell::new(SessionState::NeedsConnect), Some(*implicated_cid))
            }

            HdpSessionInitMode::Register(..) => {
                (None, DualCell::new(SessionState::NeedsRegister), None)
            }
        };

        let timestamp = time_tracker.get_global_time_ns();
        let (stopper_tx, stopper_rx) = channel(1);
        let updates_in_progress = DualRwLock::from(HashMap::new());
        let udp_mode = DualCell::new(udp_mode);

        let mut inner = HdpSessionInner {
            implicated_user_p2p_internal_listener_addr: DualLateInit::default(),
            local_nat_type,
            adjacent_nat_type: DualLateInit::default(),
            p2p_session_tx: DualLateInit::default(),
            do_static_hr_refresh_atexit: true.into(),
            dc_signal_sent_to_kernel: false.into(),
            peer_only_connect_protocol: Some(peer_only_connect_proto).into(),
            security_settings: Some(security_settings).into(),
            on_drop,
            updates_in_progress,
            udp_mode,
            local_bind_addr,
            udp_primary_outbound_tx: DualLateInit::default(),
            local_node_type,
            remote_node_type: None,
            kernel_tx: kernel_tx.clone(),
            implicated_cid: DualCell::new(implicated_cid),
            time_tracker,
            kernel_ticket: kernel_ticket.into(),
            to_primary_stream: DualLateInit::default(),
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, keep_alive_timeout_ns, state.clone()),
            session_manager,
            remote_peer,
            cnac: cnac.into(),
            state,
            account_manager,
            transfer_stats: TransferStats::new(timestamp, 0),
            is_server: false,
            needs_close_message: DualCell::new(true),
            stopper_rx: Some(stopper_rx).into(),
            queue_worker: SessionQueueWorker::new(stopper_tx.clone()),
            fcm_keys,
        };

        inner.store_proposed_credentials(proposed_credentials, &init_mode);

        Ok((stopper_tx, Self::from(inner)))
    }

    /// During impersonal mode, a new connection may come inbound. Unlike above in Self::new, we do not yet have the implicated cid nor nid.
    /// We must then expect a welcome packet
    ///
    /// When this is called, the connection is implied to be in impersonal mode. As such, the calling closure should have a way of incrementing
    /// the provisional ticket.
    pub fn new_incoming(on_drop: UnboundedSender<()>, local_nat_type: NatType, hdp_remote: HdpServerRemote, local_bind_addr: SocketAddr, local_node_type: HyperNodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, time_tracker: TimeTracker, remote_peer: SocketAddr, provisional_ticket: Ticket) -> (Sender<()>, Self) {
        let timestamp = time_tracker.get_global_time_ns();
        let (stopper_tx, stopper_rx) = channel(1);
        let updates_in_progress = DualRwLock::from(HashMap::new());
        let state = DualCell::new(SessionState::SocketJustOpened);

        let inner = HdpSessionInner {
            implicated_user_p2p_internal_listener_addr: DualLateInit::default(),
            local_nat_type,
            adjacent_nat_type: DualLateInit::default(),
            p2p_session_tx: DualLateInit::default(),
            do_static_hr_refresh_atexit: true.into(),
            dc_signal_sent_to_kernel: false.into(),
            peer_only_connect_protocol: None.into(),
            security_settings: None.into(),
            on_drop,
            updates_in_progress,
            udp_mode: DualCell::new(UdpMode::Disabled),
            local_bind_addr,
            udp_primary_outbound_tx: DualLateInit::default(),
            local_node_type,
            remote_node_type: None,
            implicated_cid: DualCell::new(None),
            time_tracker,
            kernel_ticket: provisional_ticket.into(),
            remote_peer,
            cnac: None.into(),
            kernel_tx: kernel_tx.clone(),
            session_manager: session_manager.clone(),
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, KEEP_ALIVE_TIMEOUT_NS, state.clone()),
            to_primary_stream: DualLateInit::default(),
            state,
            account_manager,
            transfer_stats: TransferStats::new(timestamp, 0),
            is_server: true,
            needs_close_message: DualCell::new(true),
            stopper_rx: Some(stopper_rx).into(),
            queue_worker: SessionQueueWorker::new(stopper_tx.clone()),
            fcm_keys: None,
        };

        (stopper_tx, Self::from(inner))
    }

    /// Once the [HdpSession] is created, it can then be executed to begin handling a periodic connection handler.
    /// This will automatically stop running once the internal state is set to Disconnected
    ///
    /// `tcp_stream`: this goes to the adjacent HyperNode
    /// `p2p_listener`: This is TCP listener bound to the same local_addr as tcp_stream. Required for TCP hole-punching
    pub async fn execute(&self, p2p_listener: Option<GenericNetworkListener>, tcp_stream: GenericNetworkStream, peer_addr: SocketAddr, connect_mode: Option<ConnectMode>) -> Result<Option<u64>, (NetworkError, Option<u64>)> {
        log::info!("HdpSession is executing ...");
        let this = self.clone();
        let this_outbound = self.clone();
        let this_inbound = self.clone();
        let this_queue_worker = self.clone();
        let this_p2p_listener = self.clone();
        let this_close = self.clone();

        let (session_future, handle_zero_state, implicated_cid, to_kernel_tx, needs_close_message) = {
            let (writer, reader) = misc::net::safe_split_stream(tcp_stream);

            let (primary_outbound_tx, primary_outbound_rx) = unbounded();
            let primary_outbound_tx = OutboundTcpSender::from(primary_outbound_tx);
            let primary_outbound_rx = OutboundTcpReceiver::from(primary_outbound_rx);

            let (p2p_session_tx, p2p_session_rx) = unbounded();

            if let Some(ref p2p_listener) = p2p_listener {
                this.implicated_user_p2p_internal_listener_addr.set_once(Some(p2p_listener.local_addr().map_err(|err| (NetworkError::Generic(err.to_string()), None))?))
            }

            let p2p_listener = p2p_listener.map(|r| (r, p2p_session_rx));
            this.p2p_session_tx.set_once(Some(p2p_session_tx));

            this.queue_worker.load_session(this.state_container.clone());
            //let (obfuscator, packet_opt) = HeaderObfuscator::new(this.is_server);
            //let sess_id = this_ref.kernel_ticket;

            this.to_primary_stream.set_once(Some(primary_outbound_tx.clone()));

            let to_kernel_tx_clone = this.kernel_tx.clone();

            let timestamp = this.time_tracker.get_global_time_ns();
            let local_nid = this.account_manager.get_local_nid();
            let cnac_opt = this.cnac.get();
            let implicated_cid = this.implicated_cid.clone();
            let needs_close_message = this.needs_close_message.clone();
            let persistence_handler = this.account_manager.get_persistence_handler().clone();

            let stopper = this.stopper_rx.take().unwrap();

            // Ensure the tx forwards to the writer
            let writer_future = Self::outbound_stream(primary_outbound_rx, writer);
            let reader_future = Self::execute_inbound_stream(reader, this_inbound, None);
            //let timer_future = Self::execute_timer(this.clone());
            let queue_worker_future = Self::execute_queue_worker(this_queue_worker);
            let stopper_future = Self::stopper(stopper);
            let handle_zero_state = Self::handle_zero_state(None, persistence_handler, primary_outbound_tx.clone(), this_outbound, this.state.get(), timestamp, local_nid, cnac_opt, connect_mode);

            let session_future = if let Some((p2p_listener, p2p_session_rx)) = p2p_listener {
                spawn_handle!(async move {
                            tokio::select! {
                                res0 = writer_future => res0,
                                res1 = reader_future => res1,
                                res2 = stopper_future => res2,
                                res3 = crate::hdp::peer::p2p_conn_handler::p2p_conn_handler(p2p_listener, this_p2p_listener) => res3,
                                res4 = Self::session_future_receiver(p2p_session_rx) => res4
                            }
                        })
            } else {
                spawn_handle!(async move {
                            tokio::select! {
                                res0 = writer_future => res0,
                                res1 = reader_future => res1,
                                res2 = stopper_future => res2
                            }
                        })
            };

            //let session_future = futures::future::try_join4(writer_future, reader_future, timer_future, socket_loader_future);


            // this will automatically drop when getting polled, because it tries upgrading a Weak reference to the session
            // as such, if it cannot, it will end the future. We do this to ensure there is no deadlocking.
            // We now spawn this future independently in order to fix a deadlocking bug in multi-threaded mode. By spawning a
            // separate task, we solve the issue of re-entrancing of mutex
            //#[cfg(feature = "multi-threaded")]
            let _ = spawn!(queue_worker_future);
            /*
            if let Some(p2p_listener) = p2p_listener {
                // NOTE: this currently implies that once an error occurs for the session, the p2p listener is down for the remaining of the session
                let _ = spawn!(crate::hdp::peer::p2p_conn_handler::p2p_conn_handler(p2p_listener, this_p2p_listener));
            }*/

            (session_future, handle_zero_state, implicated_cid, to_kernel_tx_clone, needs_close_message)
        };


        if let Err(err) = handle_zero_state.await {
            log::error!("Unable to proceed past session zero-state. Stopping session: {:?}", &err);
            return Err((err, implicated_cid.get()));
        }

        let res = session_future.await.map_err(|err| (NetworkError::Generic(err.to_string()), None))?;

        match res {
            Ok(_) => {
                log::info!("Done EXECUTING sess");
                Ok(implicated_cid.get())
            }

            Err(err) => {
                let ticket = this_close.kernel_ticket.get();
                let reason = err.to_string();
                let needs_close_message = needs_close_message.get();
                let cid = implicated_cid.get();

                log::info!("Session {} connected to {} is ending! Reason: {}. Needs close message? {} (strong count: {})", ticket.0, peer_addr, reason.as_str(), needs_close_message, this_close.strong_count());

                if needs_close_message {
                    if let Some(cid) = cid {
                        let result = HdpServerResult::Disconnect(ticket, cid, false, None, reason);
                        // false indicates a D/C caused by a non-dc subroutine
                        let _ = to_kernel_tx.unbounded_send(result);
                        this.dc_signal_sent_to_kernel.set(true);
                    }
                }

                Err((err, cid))
            }
        }
    }

    async fn stopper(receiver: Receiver<()>) -> Result<(), NetworkError> {
        let _ = tokio_stream::wrappers::ReceiverStream::new(receiver).next().await;
        Err(NetworkError::InternalError("Session stopper-rx triggered"))
    }

    pub async fn session_future_receiver(mut p2p_session_rx: UnboundedReceiver<Pin<Box<dyn RuntimeFuture>>>) -> Result<(), NetworkError> {
        /*let stream = async_stream::stream! {
            while let Some(future) = p2p_session_rx.recv().await {
                yield future;
            }
        };

        stream.for_each_concurrent(None, |future| async move {
            let _ = future.await;
        }).await;*/

        while let Some(future) = p2p_session_rx.recv().await {
            let _ = spawn!(future);
        }

        Ok(())
    }

    /// Before going through the usual loopy business, check to see if we need to initiate either a stage0 REGISTER or CONNECT packet
    async fn handle_zero_state(zero_packet: Option<BytesMut>, persistence_handler: PersistenceHandler, to_outbound: OutboundTcpSender, session: HdpSession, state: SessionState, timestamp: i64, local_nid: u64, cnac: Option<ClientNetworkAccount>, connect_mode: Option<ConnectMode>) -> Result<(), NetworkError> {
        if let Some(zero) = zero_packet {
            to_outbound.unbounded_send(zero).map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;
        }

        match state {
            SessionState::NeedsRegister => {
                log::info!("Beginning registration subroutine!");
                let potential_cids_alice = persistence_handler.client_only_generate_possible_cids().await.map_err(|err| NetworkError::Generic(err.into_string()))?;
                let session_ref = session;
                let session_security_settings = session_ref.security_settings.get().unwrap();

                // we supply 0,0 for cid and new drill vers by default, even though it will be reset by bob
                let alice_constructor = HyperRatchetConstructor::new_alice(ConstructorOpts::new_vec_init(Some(session_security_settings.crypto_params), (session_security_settings.security_level.value() + 1) as usize), 0, 0, Some(session_security_settings.security_level));
                let mut state_container = inner_mut!(session_ref.state_container);
                state_container.register_state.last_packet_time = Some(Instant::now());
                let transfer = alice_constructor.stage0_alice();

                let stage0_register_packet = crate::hdp::hdp_packet_crafter::do_register::craft_stage0(session_security_settings.crypto_params.into(), timestamp, local_nid, transfer, &potential_cids_alice);
                if let Err(err) = to_outbound.unbounded_send(stage0_register_packet).map_err(|_| NetworkError::InternalError("Writer stream corrupted")) {
                    return Err(err);
                }

                state_container.register_state.constructor = Some(alice_constructor);
                log::info!("Successfully sent stage0 register packet outbound");
            }

            SessionState::NeedsConnect => {
                log::info!("Beginning pre-connect subroutine!");
                let session_ref = session;
                let udp_mode = session_ref.udp_mode.get();
                let local_peer_listener_addr = session_ref.implicated_user_p2p_internal_listener_addr.clone().ok_or(NetworkError::InternalError("Local listener port not loaded"))?;
                let timestamp = session_ref.time_tracker.get_global_time_ns();
                let cnac = cnac.as_ref().unwrap();
                let session_security_settings = session_ref.security_settings.get().unwrap();

                let peer_only_connect_mode = session_ref.peer_only_connect_protocol.get().unwrap();
                // reset the toolset's ARA
                let ref static_aux_hr = cnac.refresh_static_hyper_ratchet();
                // security level inside static hr may not be what the declared session security level for this session is. Session security level can be no higher than the initial static HR level, since the chain requires recursion from the initial value
                let _ = static_aux_hr.verify_level(Some(session_security_settings.security_level)).map_err(|err| NetworkError::Generic(err.into_string()))?;
                let opts = static_aux_hr.get_next_constructor_opts().into_iter().take((session_security_settings.security_level.value() + 1) as usize).collect();
                //static_aux_hr.verify_level(Some(security_level)).map_err(|_| NetworkError::Generic(format!("Invalid security level. Maximum security level for this account is {:?}", static_aux_hr.get_default_security_level())))?;
                let alice_constructor = HyperRatchetConstructor::new_alice(opts, cnac.get_cid(), 0, Some(session_security_settings.security_level));
                let transfer = alice_constructor.stage0_alice();
                let max_usable_level = static_aux_hr.get_default_security_level();
                let nat_type = session_ref.local_nat_type.clone();

                let mut state_container = inner_mut!(session_ref.state_container);

                if udp_mode == UdpMode::Enabled {
                    state_container.pre_connect_state.udp_channel_oneshot_tx = UdpChannelSender::default();
                }

                // NEXT STEP: check preconnect, and update internal security-level recv side to the security level found in transfer to ensure all future packages are at that security-level
                let syn = hdp_packet_crafter::pre_connect::craft_syn(static_aux_hr, transfer, nat_type, udp_mode, local_peer_listener_addr, timestamp, state_container.keep_alive_timeout_ns, max_usable_level, session_security_settings, peer_only_connect_mode, connect_mode.unwrap_or_default());

                state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                state_container.pre_connect_state.constructor = Some(alice_constructor);
                state_container.connect_state.connect_mode = Some(connect_mode.unwrap_or_default());

                to_outbound.unbounded_send(syn).map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;

                log::info!("Successfully sent SYN pre-connect packet");
            }

            // This implies this node received a new incoming connection. It is up to the other node, Alice, to send a stage 0 packet
            SessionState::SocketJustOpened => {
                log::info!("No actions needed on primary TCP port; beginning outbound listening subroutine ...");
                // If somebody makes a connection to this node, but doesn't send anything, we need a way to remove
                // such a stale connection. By setting the value below, we ensure the possibility that the session
                // timer removes it
                inner_mut!(session.state_container).connect_state.last_packet_time = Some(Instant::now());
            }

            _ => {
                log::error!("Invalid initial state. Check program logic");
                std::process::exit(-1);
            }
        }

        Ok(())
    }

    // tcp_conn_awaiter must be provided in order to know when the begin loading the UDP conn for the user. The TCP connection must first be loaded
    pub(crate) fn udp_socket_loader(this: HdpSession, v_target: VirtualTargetType, socket: UdpSocket, addr: HolePunchedSocketAddr, ticket: Ticket, tcp_conn_awaiter: tokio::sync::oneshot::Receiver<()>) {
        let this_weak = this.as_weak();
        std::mem::drop(this);
        let task = async move {
            let (listener, udp_sender_future, stopper_rx) = {
                let this = HdpSession::upgrade_weak(&this_weak).ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let sess = this;
                let local_is_server = sess.is_server;

                // we supply the natted ip since it is where we expect to receive packets
                // whether local is server or not, we should expect to receive packets from natted
                let hole_punched_socket = addr.natted;
                let hole_punched_addr_ip = hole_punched_socket.ip();

                let local_bind_addr = socket.local_addr().unwrap();

                let (outbound_sender_tx, outbound_sender_rx) = unbounded();
                let udp_sender = OutboundUdpSender::new(outbound_sender_tx, local_bind_addr, hole_punched_socket);
                let (stopper_tx, stopper_rx) = tokio::sync::oneshot::channel::<()>();

                std::mem::drop(sess);
                tcp_conn_awaiter.await.map_err(|err| NetworkError::Generic(err.to_string()))?;
                let sess = HdpSession::upgrade_weak(&this_weak).ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

                let accessor = match v_target {
                    VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => {
                        sess.udp_primary_outbound_tx.set_once(Some(udp_sender.clone()));
                        let mut state_container = inner_mut!(sess.state_container);

                        if let Some(channel) = state_container.insert_udp_channel(ENDPOINT_ENCRYPTION_OFF, v_target, ticket, udp_sender, stopper_tx) {
                            let cnac = sess.cnac.get().ok_or(NetworkError::InternalError("CNAC not loaded (required for UDP socket_loader stage)"))?;
                            if let Some(sender) = state_container.pre_connect_state.udp_channel_oneshot_tx.tx.take() {
                                sender.send(channel).map_err(|_| NetworkError::InternalError("Unable to send UdpChannel through"))?;
                                PeerSessionCryptoAccessor::C2S(cnac, sess.state_container.clone())
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
                        let mut state_container = inner_mut!(sess.state_container);
                        if let Some(channel) = state_container.insert_udp_channel(target_cid, v_target, ticket, udp_sender, stopper_tx) {
                            if let Some(kem_state) = state_container.peer_kem_states.get_mut(&target_cid) {
                                if let Some(sender) = kem_state.udp_channel_sender.tx.take() {
                                    sender.send(channel).map_err(|_| NetworkError::InternalError("Unable to send UdpChannel through"))?;
                                    PeerSessionCryptoAccessor::P2P(target_cid, sess.state_container.clone())
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
                let codec = super::codec::BytesCodec::new(CODEC_BUFFER_CAPACITY);

                let framed = UdpFramed::new(socket, codec);
                let (writer, reader) = framed.split();

                let listener = Self::listen_wave_port(sess.clone(), hole_punched_addr_ip, local_bind_addr.port(), reader, accessor.clone());

                log::info!("Server established UDP Port {}", local_bind_addr);

                //futures.push();
                let udp_sender_future = Self::udp_outbound_sender(local_is_server, outbound_sender_rx, addr, writer, accessor);
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

    pub async fn outbound_stream(primary_outbound_rx: OutboundTcpReceiver, writer: CleanShutdownSink<GenericNetworkStream, LengthDelimitedCodec, Bytes>) -> Result<(), NetworkError> {
        //use futures::TryFutureExt;
        //let count = AtomicUsize::new(0);
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

        /*
        while let Some(packet) = reader.next().await {
            let packet = packet.map_err(|err| NetworkError::Generic(err.to_string()))?;

            match hdp_packet_processor::raw_primary_packet::process(implicated_cid.get(), this_main, remote_peer.clone(), *local_primary_port, packet, header_obfuscator).await {
                PrimaryProcessorResult::ReplyToSender(return_packet) => {
                    Self::send_to_primary_stream_closure(&primary_stream, &kernel_tx, return_packet, None)?
                }

                PrimaryProcessorResult::EndSession(reason) => {
                    log::warn!("[PrimaryProcessor] session ending: {}", reason);
                    return Err(NetworkError::Generic(reason.to_string()))
                }

                PrimaryProcessorResult::Void => {
                    // this implies that the packet processor found no reason to return a message
                }
            }
        }

        Ok(())*/


        let reader = async_stream::stream! {
            while let Some(value) = reader.next().await {
                yield value;
            }
        };

        /*#[cfg(feature = "single-threaded")]
            const AMT: Option<usize> = Some(1);

        #[cfg(not(feature = "single-threaded"))]
        const AMT: Option<usize> = None;*/

        reader.try_for_each_concurrent(None, move |packet| {
            async move {
                //log::info!("Primary port received packet with {} bytes+header or {} payload bytes ..", packet.len(), packet.len() - HDP_HEADER_BYTE_LEN);
                match hdp_packet_processor::raw_primary_packet::process(implicated_cid.get(), this_main, remote_peer.clone(), *local_primary_port, packet).await {
                    PrimaryProcessorResult::ReplyToSender(return_packet) => {
                        Self::send_to_primary_stream_closure(&primary_stream, &kernel_tx, return_packet, None)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.into_string()))
                    }

                    PrimaryProcessorResult::EndSession(reason) => {
                        log::warn!("[PrimaryProcessor] session ending: {}", reason);
                        Err(std::io::Error::new(std::io::ErrorKind::Other, reason))
                    }

                    PrimaryProcessorResult::Void => {
                        // this implies that the packet processor found no reason to return a message
                        Ok(())
                    }
                }
            }
        }).await.map_err(|err| {
            const _WINDOWS_FORCE_SHUTDOWN: i32 = 10054;
            const _RST: i32 = 104;
            const _ECONN_RST: i32 = 54; // for macs

            let error = err.raw_os_error().unwrap_or(-1);
            // error != WINDOWS_FORCE_SHUTDOWN && error != RST && error != ECONN_RST &&
            if error != -1 {
                log::error!("primary port reader error {}: {}. is server: {}. P2P: {}", error, err.to_string(), this_main.is_server, p2p);
            }

            NetworkError::Generic(err.to_string())
        })
    }

    fn send_to_primary_stream_closure(to_primary_stream: &OutboundTcpSender, kernel_tx: &UnboundedSender<HdpServerResult>, msg: BytesMut, ticket: Option<Ticket>) -> Result<(), NetworkError> {
        if let Err(err) = to_primary_stream.unbounded_send(msg) {
            kernel_tx.unbounded_send(HdpServerResult::InternalServerError(ticket, err.to_string())).map_err(|err| NetworkError::Generic(err.to_string()))?;
            Err(NetworkError::InternalError("Primary stream closed"))
        } else {
            Ok(())
        }
    }

    async fn execute_queue_worker(this_main: HdpSession) -> Result<(), NetworkError> {
        log::info!("HdpSession async timer subroutine executed");
        let weak_borrow = this_main.as_weak();
        let weak_borrow_2 = weak_borrow.clone();

        let queue_worker = {
            //let this_interval = this_main.clone();
            let borrow = this_main;
            let queue_worker = borrow.queue_worker.clone();
            let udp_mode = borrow.udp_mode.clone();
            let time_tracker = borrow.time_tracker.clone();
            let time_tracker_2 = time_tracker.clone();
            let kernel_ticket = borrow.kernel_ticket.clone();
            let is_server = borrow.is_server;
            std::mem::drop(borrow);

            // now, begin loading the subroutines
            //let mut loop_idx = 0;
            queue_worker.insert_reserved(Some(QueueWorkerTicket::Oneshot(PROVISIONAL_CHECKER, RESERVED_CID_IDX)), LOGIN_EXPIRATION_TIME, |state_container| {
                if state_container.state.get() != SessionState::Connected {
                    QueueWorkerResult::EndSession
                } else {
                    // remove it from being called again
                    QueueWorkerResult::Complete
                }
            });

            if !is_server {
                queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(DRILL_REKEY_WORKER, 0)), Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE), move |_| {
                    let weak_borrow = weak_borrow.clone();
                    let time_tracker = time_tracker.clone();
                    let ticket = kernel_ticket.clone();

                    let task = async move {
                        if let Some(sess) = HdpSession::upgrade_weak(&weak_borrow) {
                            if sess.state.get() == SessionState::Connected {
                                let timestamp = time_tracker.get_global_time_ns();

                                let security_level = sess.security_settings.get().map(|r| r.security_level).clone().unwrap();
                                let transfer_stats = sess.transfer_stats.clone();
                                let mut state_container = inner_mut!(sess.state_container);
                                let p2p_sessions = state_container.active_virtual_connections.iter().filter_map(|vconn| {
                                    if vconn.1.endpoint_container.as_ref()?.endpoint_crypto.local_is_initiator && vconn.1.is_active.load(Ordering::SeqCst) && vconn.1.last_delivered_message_timestamp.get().map(|r| r.elapsed() > Duration::from_millis(15000)).unwrap_or(true) {
                                        Some(vconn.1.connection_type)
                                    } else {
                                        None
                                    }
                                }).collect::<Vec<VirtualTargetType>>();

                                let virtual_target = VirtualTargetType::HyperLANPeerToHyperLANServer(ENDPOINT_ENCRYPTION_OFF);
                                if let Ok(_) = sess.initiate_drill_update(timestamp, virtual_target, &mut state_container, Some(ticket.get())) {
                                    // now, call for each p2p session
                                    for vconn in p2p_sessions {
                                        if let Err(err) = sess.initiate_drill_update(timestamp, vconn, &mut state_container, None) {
                                            log::warn!("Unable to initiate drill update for {:?}: {:?}", vconn, err);
                                        }
                                    }

                                    QueueWorkerResult::AdjustPeriodicity(calculate_update_frequency(security_level.value(), &transfer_stats))
                                } else {
                                    log::warn!("initiate_drill_update subroutine signalled failure");
                                    QueueWorkerResult::EndSession
                                }
                            } else {
                                QueueWorkerResult::Incomplete
                            }
                        } else {
                            log::warn!("HdpSession dropped");
                            QueueWorkerResult::EndSession
                        }
                    };

                    let _ = spawn!(task);

                    QueueWorkerResult::Incomplete
                });
            }

            queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(KEEP_ALIVE_CHECKER, 0)), Duration::from_millis(KEEP_ALIVE_INTERVAL_MS), move |state_container| {
                let timestamp = time_tracker_2.get_global_time_ns();
                if state_container.state.get() == SessionState::Connected {
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

            queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(FIREWALL_KEEP_ALIVE, 0)), FIREWALL_KEEP_ALIVE_UDP, move |state_container| {
                let weak_borrow = weak_borrow_2.clone();
                if state_container.state.get() == SessionState::Connected {
                    if udp_mode.clone().get() == UdpMode::Disabled {
                        //log::info!("TCP only mode detected. Removing FIREWALL_KEEP_ALIVE subroutine");
                        return QueueWorkerResult::Complete;
                    }

                    let task = async move {
                        if let Some(sess) = HdpSession::upgrade_weak(&weak_borrow) {
                            let _ = sess.udp_primary_outbound_tx.as_ref().unwrap().send_keep_alive();
                        }
                    };

                    let _ = spawn!(task);
                }

                QueueWorkerResult::Incomplete
            });

            queue_worker
        };

        //std::mem::drop(this_main);
        queue_worker.await
    }

    /// Similar to process_outbound_packet, but optimized to handle files
    pub fn process_outbound_file(&self, ticket: Ticket, max_group_size: Option<usize>, file: PathBuf, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let this = self;
        let cnac = this.cnac.get().ok_or(NetworkError::InvalidExternalRequest("CNAC not loaded"))?;
        if this.state.get() != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send data (ticket: {}, file: {:?}) outbound, but the session is not connected", ticket, file)))
        } else {
            if let Ok(std_file) = std::fs::File::open(&file) {
                let file_name = file.file_name().ok_or(NetworkError::InternalError("Invalid filename"))?.to_str().ok_or(NetworkError::InternalError("Invalid filename"))?;
                let file_name = String::from(file_name);
                let time_tracker = this.time_tracker.clone();
                let timestamp = this.time_tracker.get_global_time_ns();
                let (group_sender, group_sender_rx) = channel(5);
                let mut group_sender_rx = tokio_stream::wrappers::ReceiverStream::new(group_sender_rx);
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                // the above are the same for all vtarget types. Now, we need to get the proper drill and pqc

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
                                author: "".to_string(),
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
                        let mut state_container = inner_mut!(this.state_container);
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
                let mut state_container = inner_mut!(this.state_container);
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

                    let mut relative_group_id = 0;
                    // while waiting, we likely have a set of GroupSenders to process
                    while let Some(sender) = group_sender_rx.next().await {
                        match sender {
                            Ok(sender) => {
                                let (group_id, key) = {
                                    // construct the OutboundTransmitters
                                    let sess = this;
                                    if sess.state.get() != SessionState::Connected {
                                        log::warn!("Since transmitting the file, the session ended");
                                        return;
                                    }

                                    let mut state_container = inner_mut!(sess.state_container);

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

                                    let mut transmitter = GroupTransmitter::new_from_group_sender(to_primary_stream.clone(), GroupSender::from(sender), RatchetPacketCrafterContainer::new(hyper_ratchet.clone(), None), object_id, target_cid, ticket, security_level, time_tracker.clone());
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

                                // When a wave ACK in the previous group comes, if the group is 50% or more done, the group_sender_rx will
                                // received a signal here

                                if let None = next_gs_alerter_rx.next().await {
                                    log::warn!("next_gs_alerter: steam ended");
                                    return;
                                }

                                let kernel_tx2 = kernel_tx.clone();

                                this.queue_worker.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                                    if let Some(transmitter) = state_container.outbound_transmitters.get(&key) {
                                        // as long as a wave ACK has been received, proceed with the timeout check
                                        // The reason why is because this group may be loaded, but the previous one isn't done
                                        if transmitter.has_begun {
                                            let transmitter = inner!(transmitter.reliability_container);
                                            if transmitter.has_expired(GROUP_EXPIRE_TIME_MS) {
                                                if state_container.meta_expiry_state.expired() {
                                                    log::error!("Outbound group {} has expired; dropping entire transfer", group_id);
                                                    std::mem::drop(transmitter);
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

    /// When a raw packet is received by the [HdpServerRequest] listeners, it is passed into here.
    #[allow(unused_results)]
    pub fn process_outbound_message(&self, ticket: Ticket, packet: SecBuffer, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        self.inner.process_outbound_message(ticket, packet, virtual_target, security_level, false, Default::default())
    }

    pub(crate) fn process_outbound_broadcast_command(&self, ticket: Ticket, command: GroupBroadcast) -> Result<(), NetworkError> {
        let this = self;

        if this.state.get() != SessionState::Connected {
            return Err(NetworkError::InternalError("Session not connected"));
        }

        let cnac = this.cnac.get().unwrap();
        let security_level = this.security_settings.get().map(|r| r.security_level).clone().unwrap();
        let to_primary_stream = this.to_primary_stream.as_ref().unwrap();

        cnac.borrow_hyper_ratchet(None, |hyper_ratchet_opt| {
            let hyper_ratchet = hyper_ratchet_opt.ok_or(NetworkError::InternalError("Hyper ratchet missing"))?;
            let timestamp = this.time_tracker.get_global_time_ns();
            let packet = match &command {
                GroupBroadcast::Create(_) |
                GroupBroadcast::End(_) |
                GroupBroadcast::Kick(..) |
                GroupBroadcast::Message(..) |
                GroupBroadcast::Add(..) |
                GroupBroadcast::AcceptMembership(_) |
                GroupBroadcast::LeaveRoom(_) => {
                    hdp_packet_crafter::peer_cmd::craft_group_message_packet(hyper_ratchet, &command, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level)
                }

                n => {
                    return Err(NetworkError::Generic(format!("{:?} is not a valid group broadcast request", &n)));
                }
            };

            to_primary_stream.unbounded_send(packet).map_err(|err| NetworkError::Generic(err.to_string()))
        })
    }

    #[allow(unused_results)]
    pub(crate) async fn dispatch_peer_command(&self, ticket: Ticket, peer_command: PeerSignal, security_level: SecurityLevel) -> Result<(), NetworkError> {
        log::info!("Dispatching peer command ...");
        let this = self;
        let timestamp = this.time_tracker.get_global_time_ns();
        let mut do_save = false;
        if let Some(cnac) = this.cnac.get().as_ref() {
            if let Some(to_primary_stream) = this.to_primary_stream.as_ref() {
                // move into the closure without cloning the drill
                let packet = cnac.visit_mut(|mut inner| {
                    let this_cid = inner.cid;
                    let signal_processed = match peer_command {
                        PeerSignal::DisconnectUDP(v_conn) => {
                            // disconnect UDP locally
                            log::info!("Closing UDP subsystem locally ...");
                            inner_mut!(self.state_container).remove_udp_channel(v_conn.get_target_cid());
                            PeerSignal::DisconnectUDP(v_conn)
                        }
                        // case 1: user just initiated a post-register request that has Fcm enabled
                        PeerSignal::PostRegister(vconn, a, b, c, FcmPostRegister::Enable) => {
                            let target_cid = vconn.get_original_target_cid();
                            log::info!("[FCM] client {} requested FCM post-register with {}", inner.cid, target_cid);
                            let state_container = inner!(this.state_container);
                            if state_container.peer_kem_states.contains_key(&target_cid) || inner.fcm_crypt_container.contains_key(&target_cid) {
                                return Err(NetworkError::InvalidExternalRequest("Cannot register to the specified client because a concurrent registration process is already occurring, or already registered"));
                            }

                            // create constructor
                            // TODO: Extend FCM to include custom params (within reason, ofc)
                            let fcm_constructor = FcmRatchetConstructor::new_alice(inner.cid, 0, ConstructorOpts::default());
                            let fcm_post_register = FcmPostRegister::AliceToBobTransfer(fcm_constructor.stage0_alice().serialize_to_vector().unwrap(), inner.crypt_container.fcm_keys.clone().ok_or(NetworkError::InvalidExternalRequest("Fcm not configured for this client"))?, this_cid);
                            // finally, store the constructor inside the state container
                            if let Some(_) = inner.kem_state_containers.insert(target_cid, ConstructorType::Fcm(fcm_constructor)) {
                                log::error!("Overwrote pre-existing FCM KEM container. Report to developers")
                            }

                            do_save = true;
                            PeerSignal::PostRegister(vconn, a, b, c, fcm_post_register)
                        }

                        // case 2: local just accepted, fcm is enabled. But, signal was not sent via FCM. Instead, was sent via normal network
                        // TODO: This doesn't make sense. Why is it switching on AliceToBobTransfer, and not BobToAliceTransfer??? ANSWER: check the else statement in hyxewave:[..]/peer.rs. It does not switch-out the transfer type. that must instead be done here (delegation of responsibility as desired)
                        PeerSignal::PostRegister(vconn, a, b, Some(PeerResponse::Accept(Some(c))), FcmPostRegister::AliceToBobTransfer(transfer, peer_fcm_keys, _this_cid)) => {
                            let target_cid = vconn.get_original_target_cid();
                            let local_cid = inner.cid;
                            log::info!("[FCM] client {} accepted FCM post-register with {}", local_cid, target_cid);
                            if inner.fcm_crypt_container.contains_key(&target_cid) {
                                return Err(NetworkError::InvalidExternalRequest("Cannot register to the specified client because crypt container already exists"));
                            }

                            let fcm_keys_local = inner.crypt_container.fcm_keys.clone().ok_or(NetworkError::InvalidExternalRequest("Local node does not have FCM keys to share with the endpoint"))?;

                            let bob_constructor = FcmRatchetConstructor::new_bob(ConstructorOpts::default(), FcmAliceToBobTransfer::deserialize_from_vector(&transfer[..]).map_err(|err| NetworkError::Generic(err.to_string()))?).ok_or(NetworkError::InvalidExternalRequest("Invalid FCM ratchet constructor"))?;
                            let fcm_post_register = FcmPostRegister::BobToAliceTransfer(bob_constructor.stage0_bob().ok_or(NetworkError::InvalidExternalRequest("Invalid FCM ratchet constructor"))?, fcm_keys_local.clone(), local_cid);
                            let fcm_ratchet = bob_constructor.finish_with_custom_cid(local_cid).ok_or(NetworkError::InvalidExternalRequest("Invalid FCM Ratchet constructor"))?;
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

                let to_primary_stream = to_primary_stream.clone();
                let cnac = cnac.clone();

                if do_save {
                    cnac.save().await?;
                }

                return to_primary_stream.unbounded_send(packet).map_err(|err| NetworkError::SocketError(err.to_string()));
            }
        }


        Err(NetworkError::InternalError("Invalid session configuration"))
    }

    async fn listen_wave_port<S: Stream<Item=Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin>(this: HdpSession, hole_punched_addr_ip: IpAddr, local_port: u16, mut stream: S, ref peer_session_accessor: PeerSessionCryptoAccessor) -> Result<(), NetworkError> {
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

    // Accepts
    async fn udp_outbound_sender<S: SinkExt<(Bytes, SocketAddr)> + Unpin>(local_is_server: bool, receiver: UnboundedReceiver<(u8, BytesMut)>, hole_punched_addr: HolePunchedSocketAddr, mut sink: S, peer_session_accessor: PeerSessionCryptoAccessor) -> Result<(), NetworkError> {
        let mut receiver = tokio_stream::wrappers::UnboundedReceiverStream::new(receiver);
        let target_cid = peer_session_accessor.get_target_cid();

        while let Some((cmd_aux, packet)) = receiver.next().await {
            // TODO: figure out the logistics of this IP mess for all possible use cases. This works for hyperlan though
            let send_addr = if local_is_server {
                // if the local is server, we send to the natted ports instead of the initial. It is flip-flopped
                hole_punched_addr.natted
            } else {
                hole_punched_addr.initial
            };

            let packet = peer_session_accessor.borrow_hr(None, |hr, _| hdp_packet_crafter::udp::craft_udp_packet(hr, cmd_aux,packet, target_cid, SecurityLevel::LOW))?;

            log::trace!("About to send packet w/len {} | Dest: {:?}", packet.len(), &send_addr);
            // TODO: UDP header obfuscation
            sink.send((packet.freeze(), send_addr)).await.map_err(|_| NetworkError::InternalError("UDP sink unable to receive outbound requests"))?;
        }

        log::info!("Outbound wave sender ending");

        Ok(())
    }

    pub fn process_inbound_packet_wave(&self, packet: HdpPacket, accessor: &PeerSessionCryptoAccessor) -> Result<(), NetworkError> {
        if packet.get_length() < HDP_HEADER_BYTE_LEN {
            return Ok(());
        }

        //log::info!("Wave inbound port (original): {}", packet.get_remote_port());

        if let Some((header, _)) = packet.parse() {
            // we only process streaming packets
            if header.cmd_aux != packet_flags::cmd::aux::udp::STREAM {
                // discard any keep alives
                return Ok(())
            }

            let hr_version = header.drill_version.get();
            let mut endpoint_cid_info = None;
            match check_proxy(self.implicated_cid.get(), header.cmd_primary, header.cmd_aux, header.session_cid.get(),header.target_cid.get(), self, &mut endpoint_cid_info, ReceivePortType::UDP, packet) {
                Some(packet) => {
                    match hdp_packet_processor::udp_packet::process(self, packet, hr_version, accessor) {
                        PrimaryProcessorResult::Void => {
                            Ok(())
                        }

                        PrimaryProcessorResult::EndSession(err) => {
                            // stop the UDP stream
                            log::warn!("UDP session ending: {:?}", err);
                            Err(NetworkError::Generic(err.to_string()))
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
        if session.state.get() != SessionState::Connected {
            log::error!("Must be connected to HyperLAN in order to start disconnect")
        }

        let cnac = session.cnac.get().unwrap();
        let hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();
        let timestamp = session.time_tracker.get_global_time_ns();
        let security_level = session.security_settings.get().map(|r| r.security_level).clone().unwrap();
        let to_primary_stream = session.to_primary_stream.as_ref().unwrap();
        let ref to_kernel_tx = session.kernel_tx;

        let disconnect_stage0_packet = hdp_packet_crafter::do_disconnect::craft_stage0(&hyper_ratchet, ticket, timestamp, security_level);
        Self::send_to_primary_stream_closure(to_primary_stream, to_kernel_tx, disconnect_stage0_packet, Some(ticket))
            .and_then(|_| Ok(true))
    }
}

impl HdpSessionInner {
    /// Stores the proposed credentials into the register state container
    pub(crate) fn store_proposed_credentials(&mut self, proposed_credentials: ProposedCredentials, init_mode: &HdpSessionInitMode) {
        let mut state_container = inner_mut!(self.state_container);

        match init_mode {
            HdpSessionInitMode::Register(..) => {
                state_container.register_state.proposed_credentials = Some(proposed_credentials);
            }

            HdpSessionInitMode::Connect(_) => {
                state_container.connect_state.proposed_credentials = Some(proposed_credentials);
                // we don't need to store the nonce here
            }
        }
    }

    fn enqueue_packet(&self, enqueued_packets: &mut HashMap<u64, VecDeque<(Ticket, SecBuffer, VirtualTargetType, SecurityLevel)>>, target_cid: u64, ticket: Ticket, packet: SecBuffer, target: VirtualTargetType, security_level: SecurityLevel) {
        if !enqueued_packets.contains_key(&target_cid) {
            let _ = enqueued_packets.insert(target_cid, VecDeque::new());
        }

        let queue = enqueued_packets.get_mut(&target_cid).unwrap();
        queue.push_back((ticket, packet, target, security_level));
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
        if let Some(fail_time) = inner!(self.state_container).connect_state.fail_time {
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

    /// Stops the future from running. This will stop once the periodic checker determines the state is disconnected
    pub fn shutdown(&self) {
        self.state.set(SessionState::Disconnected)
    }

    #[allow(unused_results)]
    pub(crate) fn initiate_drill_update(&self, timestamp: i64, virtual_target: VirtualTargetType, state_container: &mut dyn ExpectedInnerTargetMut<StateContainerInner>, ticket: Option<Ticket>) -> Result<(), NetworkError> {
        if !state_container.meta_expiry_state.expired() {
            log::info!("Drill update will be omitted since packets are being sent");
            return Ok(());
        }

        let cnac = self.cnac.get().unwrap();
        let session_security_settings = self.security_settings.get().unwrap();
        let security_level = session_security_settings.security_level;


        match virtual_target {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => {
                let (ratchet, res) = cnac.visit_mut(|mut inner| {
                    let ratchet = inner.crypt_container.get_hyper_ratchet(None).cloned().unwrap();
                    (ratchet, inner.crypt_container.get_next_constructor(false))
                });

                match res {
                    Some(alice_constructor) => {
                        let stage0_packet = hdp_packet_crafter::do_drill_update::craft_stage0(&ratchet, alice_constructor.stage0_alice(), timestamp, ENDPOINT_ENCRYPTION_OFF, security_level);
                        state_container.drill_update_state.alice_hyper_ratchet = Some(alice_constructor);
                        let to_primary_stream = self.to_primary_stream.as_ref().unwrap();
                        let kernel_tx = &self.kernel_tx;
                        HdpSession::send_to_primary_stream_closure(to_primary_stream, kernel_tx, stage0_packet, ticket)
                    }

                    None => {
                        log::info!("Won't perform update b/c concurrent update occurring");
                        Ok(())
                    }
                }
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, peer_cid) => {
                const MISSING: NetworkError = NetworkError::InvalidExternalRequest("Peer not connected");
                let endpoint_container = &mut state_container.active_virtual_connections.get_mut(&peer_cid).ok_or(MISSING)?.endpoint_container.as_mut().ok_or(MISSING)?;
                let crypt = &mut endpoint_container.endpoint_crypto;
                let alice_constructor = crypt.get_next_constructor(false);
                let latest_hyper_ratchet = crypt.get_hyper_ratchet(None).cloned().ok_or(NetworkError::InternalError("Ratchet not loaded"))?;

                match alice_constructor {
                    Some(alice_constructor) => {
                        let to_primary_stream_preferred = endpoint_container.get_direct_p2p_primary_stream().unwrap_or_else(|| self.to_primary_stream.as_ref().unwrap());
                        let stage0_packet = hdp_packet_crafter::do_drill_update::craft_stage0(&latest_hyper_ratchet, alice_constructor.stage0_alice(), timestamp, peer_cid, security_level);

                        to_primary_stream_preferred.unbounded_send(stage0_packet).map_err(|err| NetworkError::Generic(err.to_string()))?;

                        if let Some(_) = state_container.drill_update_state.p2p_updates.insert(peer_cid, alice_constructor) {
                            log::error!("Overwrote pre-existing peer kem. Report to developers");
                        }

                        // to_primary_stream_preferred.unbounded_send(stage0_packet).map_err(|err| NetworkError::Generic(err.to_string()))
                        Ok(())
                    }

                    None => {
                        log::info!("Won't perform update b/c concurrent update occurring");
                        Ok(())
                    }
                }
            }

            _ => {
                Err(NetworkError::InternalError("HyperWAN Not implemented"))
            }
        }
    }

    pub(crate) fn initiate_deregister(&self, _virtual_connection_type: VirtualConnectionType, ticket: Ticket) -> Result<(), NetworkError> {
        log::info!("Initiating deregister process ...");
        let timestamp = self.time_tracker.get_global_time_ns();
        let cnac = self.cnac.get().unwrap();
        let security_level = self.security_settings.get().map(|r| r.security_level).clone().unwrap();
        let ref hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();

        let stage0_packet = hdp_packet_crafter::do_deregister::craft_stage0(hyper_ratchet, timestamp, security_level);
        let mut state_container = inner_mut!(self.state_container);
        state_container.deregister_state.on_init(timestamp, ticket);
        std::mem::drop(state_container);
        self.send_to_primary_stream(Some(ticket), stage0_packet)
    }

    pub(crate) fn is_provisional(&self) -> bool {
        let state = self.state.get();
        //self.implicated_cid.is_none()
        // SocketJustOpened is only the state for a session created from an incoming connection
        state == SessionState::SocketJustOpened || state == SessionState::NeedsConnect || state == SessionState::ConnectionProcess || state == SessionState::NeedsRegister
    }

    fn get_secrecy_mode(&self, target_cid: u64, state_container: &StateContainerInner) -> Option<SecrecyMode> {
        if target_cid != ENDPOINT_ENCRYPTION_OFF {
            Some(state_container.active_virtual_connections.get(&target_cid)?.endpoint_container.as_ref()?.default_security_settings.secrecy_mode)
        } else {
            self.security_settings.get().map(|r| r.secrecy_mode).clone()
        }
    }

    /// Returns true if a packet was sent, false otherwise. This should only be called when a packet is received
    pub(crate) fn poll_next_enqueued(&self, target_cid: u64, state_container: LockHolder<OwnedWriteGuard<StateContainerInner>>) -> Result<bool, NetworkError> {
        log::info!("Polling next for {}", target_cid);
        state_container.access_consume_or_else(|| inner_mut!(self.state_container), |mut state_container| {
            let secrecy_mode = self.get_secrecy_mode(target_cid, &state_container).ok_or(NetworkError::InternalError("Secrecy mode not loaded"))?;
            match secrecy_mode {
                SecrecyMode::BestEffort => {}

                SecrecyMode::Perfect => {
                    // fetch_nand(false
                    let update_in_progress = inner!(self.updates_in_progress).get(&target_cid).map(|r| r.fetch_nand(false, Ordering::SeqCst)).ok_or(NetworkError::InternalError("Update state not loaded in hashmap!"))?;

                    // We have to make sure when this is called, it also sets update_in_progress to true to place a lock. We will also need to reinforce this via a force_mode inside the get_next_constructor fn in the crypt container
                    // it's possible in high-stress loads, a new inbound packet triggers update_in_progress to true right after checking below. The fetch_nand w/false helps us achieve this
                    if update_in_progress {
                        log::info!("Cannot send packet at this time since update_in_progress"); // in this case, update will happen upon reception of TRUNCATE packet
                        return Ok(false);
                    }

                    //let mut enqueued = inner_mut!(self.enqueued_packets);
                    if !state_container.enqueued_packets.contains_key(&target_cid) {
                        let _ = state_container.enqueued_packets.insert(target_cid, VecDeque::new());
                    }

                    if let Some(queue) = state_container.enqueued_packets.get_mut(&target_cid) {
                        log::info!("Queue has: {} items", queue.len());
                        // since we have a mutable lock on the session, no other attempts will happen. We can safely pop the front of the queue and rest assured that it won't be denied a send this time
                        if let Some((ticket, packet, virtual_target, security_level)) = queue.pop_front() {
                            //std::mem::drop(enqueued);
                            return self.process_outbound_message(ticket, packet, virtual_target, security_level, true, state_container.into()).map(|_| true);
                        } else {
                            log::info!("NO packets enqueued for target {}", target_cid);
                        }
                    } else {
                        log::info!("Enqueued packets queue not present");
                    }
                }
            }

            Ok(false)
        })
    }

    fn has_enqueued(&self, enqueued_packets: &HashMap<u64, VecDeque<(Ticket, SecBuffer, VirtualTargetType, SecurityLevel)>>, target_cid: u64) -> bool {
        enqueued_packets.get(&target_cid).map(|r| r.front().is_some()).unwrap_or(false)
    }

    #[allow(unused_results)]
    fn process_outbound_message(&self, ticket: Ticket, packet: SecBuffer, virtual_target: VirtualTargetType, security_level: SecurityLevel, called_from_poll: bool, state_container: LockHolder<OwnedWriteGuard<StateContainerInner>>) -> Result<(), NetworkError> {
        let this = self;
        if this.state.get() != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send data (ticket: {}) outbound, but the session is not connected", ticket)))
        } else {
            state_container.access_consume_or_else(|| inner_mut!(this.state_container), move |mut state_container| {
                // first, make sure that there aren't already packets in the queue (unless we were called from the poll, in which case, we are getting the latest version)
                let secrecy_mode = this.get_secrecy_mode(virtual_target.get_target_cid(), &state_container).ok_or(NetworkError::InternalError("Secrecy mode not loaded"))?;
                let cnac = this.cnac.get().unwrap();
                let time_tracker = this.time_tracker.clone();
                //let timestamp = time_tracker.get_global_time_ns();

                if secrecy_mode == SecrecyMode::Perfect && !called_from_poll {
                    //let mut enqueued = inner_mut!(this.enqueued_packets);
                    if this.has_enqueued(&state_container.enqueued_packets, virtual_target.get_target_cid()) || inner!(this.updates_in_progress).get(&virtual_target.get_target_cid()).map(|r| r.load(Ordering::SeqCst)).ok_or_else(|| NetworkError::InternalError("Update in progress not loaded for client"))? {
                        // If there are packets enqueued, it doesn't matter if an update is in progress or not. Queue this packet
                        //log::info!("[ABX] enqueuing packet for {:?}", virtual_target);
                        this.enqueue_packet(&mut state_container.enqueued_packets, virtual_target.get_target_cid(), ticket, packet, virtual_target, security_level);
                        return Ok(());
                    }
                }

                // object singleton == 0 implies that the data does not belong to a file
                const OBJECT_SINGLETON: u32 = 0;
                // Drop this to ensure that it doesn't block other async closures from accessing the inner device
                // std::mem::drop(this);
                let (mut transmitter, group_id, target_cid) = match virtual_target {
                    VirtualTargetType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                        // if we are sending this just to the HyperLAN server (in the case of file uploads),
                        // then, we use this session's pqc, the cnac's latest drill, and 0 for target_cid
                        let result = cnac.visit_mut(|mut inner| -> Result<Either<(Option<HyperRatchetConstructor>, HyperRatchet, u64, SecBuffer), SecBuffer>, NetworkError> {
                            //let group_id = inner.crypt_container.get_and_increment_group_id();
                            let latest_hyper_ratchet = inner.crypt_container.get_hyper_ratchet(None).cloned().unwrap();
                            latest_hyper_ratchet.verify_level(Some(security_level)).map_err(|_err| NetworkError::Generic(format!("Invalid security level. The maximum security level for this session is {:?}", latest_hyper_ratchet.get_default_security_level())))?;
                            let constructor = inner.crypt_container.get_next_constructor(called_from_poll);

                            match secrecy_mode {
                                SecrecyMode::BestEffort => {
                                    let group_id = inner.crypt_container.get_and_increment_group_id();
                                    Ok(Either::Left((constructor, latest_hyper_ratchet.clone(), group_id, packet)))
                                }

                                SecrecyMode::Perfect => {
                                    if constructor.is_some() {
                                        // we can perform a kex
                                        let group_id = inner.crypt_container.get_and_increment_group_id();
                                        Ok(Either::Left((constructor, latest_hyper_ratchet.clone(), group_id, packet)))
                                    } else {
                                        // kex later
                                        Ok(Either::Right(packet))
                                    }
                                }
                            }
                        })?;

                        match result {
                            Either::Left((alice_constructor, latest_hyper_ratchet, group_id, packet)) => {
                                let to_primary_stream = this.to_primary_stream.clone().unwrap();
                                (GroupTransmitter::new_message(to_primary_stream, OBJECT_SINGLETON, ENDPOINT_ENCRYPTION_OFF, RatchetPacketCrafterContainer::new(latest_hyper_ratchet, alice_constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, implicated_cid)
                            }

                            Either::Right(packet) => {
                                // store inside hashmap
                                //let mut enqueued_packets = inner_mut!(this.enqueued_packets);
                                log::info!("[ATC] Enqueuing c2s packet");
                                this.enqueue_packet(&mut state_container.enqueued_packets, 0, ticket, packet, virtual_target, security_level);
                                return Ok(());
                            }
                        }
                    }

                    VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                        log::info!("Maybe sending HyperLAN peer ({}) <-> HyperLAN Peer ({})", implicated_cid, target_cid);
                        // here, we don't use the base session's PQC. Instead, we use the vconn's pqc and Toolset

                        //let mut state_container = inner_mut!(this.state_container);

                        if let Some(vconn) = state_container.active_virtual_connections.get_mut(&target_cid) {
                            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {

                                //let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                                let to_primary_stream_preferred = endpoint_container.get_direct_p2p_primary_stream().cloned().unwrap_or_else(|| this.to_primary_stream.clone().unwrap());
                                //let to_primary_stream_preferred = this.to_primary_stream.clone().unwrap();
                                let latest_usable_ratchet = endpoint_container.endpoint_crypto.get_hyper_ratchet(None).unwrap().clone();
                                latest_usable_ratchet.verify_level(Some(security_level)).map_err(|_err| NetworkError::Generic(format!("Invalid security level. The maximum security level for this session is {:?}", latest_usable_ratchet.get_default_security_level())))?;
                                let constructor = endpoint_container.endpoint_crypto.get_next_constructor(called_from_poll);

                                match secrecy_mode {
                                    SecrecyMode::BestEffort => {
                                        let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                                        (GroupTransmitter::new_message(to_primary_stream_preferred, OBJECT_SINGLETON, target_cid, RatchetPacketCrafterContainer::new(latest_usable_ratchet, constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, target_cid)
                                    }

                                    SecrecyMode::Perfect => {
                                        // Note: we can't just add/send here. What if there are packets in the queue? We thus must poll before calling the below function
                                        if constructor.is_some() {
                                            let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                                            log::info!("[Perfect] will send group {}", group_id);
                                            (GroupTransmitter::new_message(to_primary_stream_preferred, OBJECT_SINGLETON, target_cid, RatchetPacketCrafterContainer::new(latest_usable_ratchet, constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, target_cid)
                                        } else {
                                            //assert!(!called_from_poll);
                                            // Being called from poll should only happen when a packet needs to be sent, and is ready to be sent. Further, being called from the poll adds a lock ensuring it gets sent
                                            if called_from_poll {
                                                log::error!("Should not happen (CFP). {:?}", endpoint_container.endpoint_crypto.lock_set_by_alice.clone());
                                                std::process::exit(-1); // for dev purposes
                                            }

                                            //std::mem::drop(state_container);
                                            log::info!("[Perfect] will enqueue packet");
                                            //let mut enqueued_packets = inner_mut!(this.enqueued_packets);
                                            this.enqueue_packet(&mut state_container.enqueued_packets, target_cid, ticket, packet, virtual_target, security_level);
                                            return Ok(());
                                        }
                                    }
                                }
                            } else {
                                return Err(NetworkError::InternalError("Endpoint container not found"));
                            }
                        } else {
                            log::error!("Unable to find active vconn for the channel");
                            return Ok(());
                        }
                    }

                    _ => {
                        return Err(NetworkError::InvalidExternalRequest("HyperWAN functionality not yet implemented"));
                    }
                };


                // We manually send the header. The tails get sent automatically
                log::info!("[message] Sending GROUP HEADER through primary stream for group {} as {}", group_id, this.is_server.then(|| "Server").unwrap_or("Client"));
                let group_len = transmitter.get_total_plaintext_bytes();
                this.try_action(Some(ticket), || transmitter.transmit_group_header(virtual_target))?;

                //this.transfer_stats += TransferStats::new(timestamp, group_len as isize);

                let outbound_container = OutboundTransmitterContainer::new(None, transmitter, group_len, 1, 0, ticket);
                // The payload packets won't be sent until a GROUP_HEADER_ACK is received
                // NOTE: Ever since using GroupKeys, we use either the implicated_cid (for client -> server conns) or target_cids (for peer conns)
                let key = GroupKey::new(target_cid, group_id);
                //inner_mut!(this.state_container).outbound_transmitters.insert(key, outbound_container);
                state_container.outbound_transmitters.insert(key, outbound_container);

                std::mem::drop(state_container);

                this.queue_worker.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                    if let Some(transmitter) = state_container.outbound_transmitters.get(&key) {
                        let transmitter = inner!(transmitter.reliability_container);
                        if transmitter.has_expired(GROUP_EXPIRE_TIME_MS) {
                            if state_container.meta_expiry_state.expired() {
                                log::info!("Outbound group {} has expired; dropping from map", group_id);
                                QueueWorkerResult::Complete
                            } else {
                                log::info!("Other outbound groups being processed; patiently awaiting group {}", group_id);
                                QueueWorkerResult::Incomplete
                            }
                        } else {
                            // it hasn't expired yet, and is still transmitting
                            QueueWorkerResult::Incomplete
                        }
                    } else {
                        // it finished
                        QueueWorkerResult::Complete
                    }
                });

                Ok(())
            })
        }
    }
}

impl Drop for HdpSessionInner {
    fn drop(&mut self) {
        log::info!("*** Dropping HdpSession ***");
        if let Err(_) = self.on_drop.unbounded_send(()) {
            //log::error!("Unable to cleanly alert node that session ended: {:?}", err);
        }

        if !self.dc_signal_sent_to_kernel.get() {
            if let Some(cid) = self.implicated_cid.get() {
                if let Err(_) = self.kernel_tx.unbounded_send(HdpServerResult::Disconnect(Ticket(0), cid, false, None, "Session dropped".to_string())) {
                    //
                }
            }
        }
    }
}