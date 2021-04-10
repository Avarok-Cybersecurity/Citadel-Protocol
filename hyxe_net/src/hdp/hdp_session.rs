use std::net::IpAddr;
//use async_std::prelude::*;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt, TryFutureExt, TryStreamExt, Stream};
//use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender, channel, TrySendError};
use crate::hdp::outbound_sender::{unbounded, channel, UnboundedSender, UnboundedReceiver, SendError, Receiver};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::udp::UdpFramed;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::client_account::ClientNetworkAccount;

use crate::constants::{DEFAULT_PQC_ALGORITHM, INITIAL_RECONNECT_LOCKOUT_TIME_NS, LOGIN_EXPIRATION_TIME, DRILL_UPDATE_FREQUENCY_LOW_BASE, KEEP_ALIVE_INTERVAL_MS, FIREWALL_KEEP_ALIVE_UDP, GROUP_EXPIRE_TIME_MS, HDP_HEADER_BYTE_LEN, CODEC_BUFFER_CAPACITY, KEEP_ALIVE_TIMEOUT_NS};
use crate::error::NetworkError;
use crate::hdp::hdp_packet::{HdpPacket, packet_flags, HeaderObfuscator};
use crate::hdp::hdp_packet_crafter::{self, GroupTransmitter, RatchetPacketCrafterContainer};
//use futures_codec::Framed;
use crate::hdp::hdp_packet_processor::{self, GroupProcessorResult, PrimaryProcessorResult};
use crate::hdp::hdp_packet_processor::includes::{SocketAddr, Duration};
use crate::hdp::hdp_server::{HdpServerResult, Ticket, HdpServerRemote, ConnectMode};
use crate::hdp::hdp_session_manager::HdpSessionManager;
use crate::hdp::outbound_sender::{OutboundUdpSender, KEEP_ALIVE, OutboundTcpReceiver, OutboundTcpSender};
use crate::hdp::state_container::{OutboundTransmitterContainer, StateContainerInner, VirtualConnectionType, VirtualTargetType, GroupKey, OutboundFileTransfer, FileKey, StateContainer, GroupSender};
use crate::hdp::time::TransferStats;
use hyxe_user::proposed_credentials::ProposedCredentials;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::time_tracker::TimeTracker;
use crate::hdp::session_queue_handler::{SessionQueueWorker, QueueWorkerTicket, PROVISIONAL_CHECKER, QueueWorkerResult, DRILL_REKEY_WORKER, KEEP_ALIVE_CHECKER, FIREWALL_KEEP_ALIVE, RESERVED_CID_IDX};
use crate::hdp::state_subcontainers::drill_update_container::calculate_update_frequency;
use std::sync::Arc;
use hyxe_user::re_imports::scramble_encrypt_file;
use crate::hdp::file_transfer::VirtualFileMetadata;
use std::path::PathBuf;
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
use atomic::{Atomic, Ordering};
use std::sync::atomic::AtomicBool;
use crate::inner_arg::{InnerParameterMut, ExpectedInnerTargetMut};
use crate::hdp::misc::clean_shutdown::{CleanShutdownStream, CleanShutdownSink};
use crate::hdp::misc;
use crate::hdp::peer::p2p_conn_handler::P2PInboundHandle;
use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, ConstructorType};
use crate::macros::SessionBorrow;
use crate::hdp::peer::peer_layer::{PeerSignal, PeerResponse};
use hyxe_user::fcm::kem::FcmPostRegister;
use hyxe_crypt::fcm::fcm_ratchet::{FcmRatchetConstructor, FcmAliceToBobTransfer};
use hyxe_fs::io::SyncIO;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use hyxe_crypt::toolset::Toolset;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::sec_bytes::SecBuffer;
use crate::hdp::misc::net::{GenericNetworkStream, GenericNetworkListener};
//use crate::define_struct;

pub type WeakHdpSessionBorrow = crate::macros::WeakBorrow<HdpSessionInner>;
// Defines the primary structure which wraps the inner device
define_outer_struct_wrapper!(HdpSession, HdpSessionInner);

/*
/// Allows a connection stream to be worked on by a single worker
pub struct HdpSession {
    pub inner: Rc<RefCell<HdpSessionInner>>
}
*/

//define_struct!(HdpSession, HdpSessionInner);

/// Structure for holding and keep track of packets, as well as basic connection information
#[allow(unused)]
pub struct HdpSessionInner {
    pub(super) implicated_cid: Arc<Atomic<Option<u64>>>,
    // the external IP of the local node with respect to the outside world. May or may not be natted
    pub(super) external_addr: Arc<Atomic<Option<SocketAddr>>>,
    pub(super) kernel_ticket: Ticket,
    pub(super) remote_peer: SocketAddr,
    pub(super) cnac: Option<ClientNetworkAccount>,
    pub(super) wave_socket_loader: Option<tokio::sync::oneshot::Sender<Vec<(UdpSocket, HolePunchedSocketAddr)>>>,
    // Sends results directly to the kernel
    pub(super) kernel_tx: UnboundedSender<HdpServerResult>,
    pub(super) to_primary_stream: Option<OutboundTcpSender>,
    pub(super) to_wave_ports: Option<OutboundUdpSender>,
    // Setting this will determine what algorithm is used during the DO_CONNECT stage
    pub(super) pqc_algorithm: Option<u8>,
    pub(super) session_manager: HdpSessionManager,
    pub(super) state: SessionState,
    pub(super) state_container: StateContainer,
    pub(super) account_manager: AccountManager,
    pub(super) time_tracker: TimeTracker,
    pub(super) local_node_type: HyperNodeType,
    pub(super) remote_node_type: Option<HyperNodeType>,
    pub(super) local_bind_addr: SocketAddr,
    // if this is enabled, then UDP won't be used
    pub(super) tcp_only: bool,
    pub(super) security_level: SecurityLevel,
    pub(super) transfer_stats: TransferStats,
    pub(super) is_server: bool,
    pub(super) needs_close_message: Arc<AtomicBool>,
    pub(super) stopper_rx: Option<Receiver<()>>,
    pub(super) queue_worker: SessionQueueWorker,
    pub(super) fcm_keys: Option<FcmKeys>
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

impl HdpSession {
    /// Creates a new session.
    /// 'implicated_cid': Supply None if you expect to register. If Some, will check the account manager
    pub async fn new(hdp_remote: HdpServerRemote, pqc_algorithm: Option<u8>, local_bind_addr: SocketAddr, local_node_type: HyperNodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, remote_peer: SocketAddr, time_tracker: TimeTracker, implicated_cid: Option<u64>, kernel_ticket: Ticket, security_level: SecurityLevel, fcm_keys: Option<FcmKeys>, tcp_only: bool, keep_alive_timeout_ns: i64) -> Result<Self, NetworkError> {
        let (cnac, state) = if let Some(implicated_cid) = implicated_cid {
            let cnac = account_manager.get_client_by_cid(implicated_cid).await?.ok_or(NetworkError::InvalidExternalRequest("Client does not exist"))?;
            (Some(cnac), SessionState::NeedsConnect)
        } else {
            (None, SessionState::NeedsRegister)
        };

        let timestamp = time_tracker.get_global_time_ns();
        let (stopper_tx, stopper_rx) = channel(1);

        let inner = HdpSessionInner {
            pqc_algorithm,
            tcp_only,
            local_bind_addr,
            to_wave_ports: None,
            wave_socket_loader: None,
            local_node_type,
            remote_node_type: None,
            security_level,
            kernel_tx: kernel_tx.clone(),
            external_addr: Arc::new(Atomic::new(None)),
            implicated_cid: Arc::new(Atomic::new(implicated_cid)),
            time_tracker,
            kernel_ticket,
            to_primary_stream: None,
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, keep_alive_timeout_ns),
            session_manager,
            remote_peer,
            cnac,
            state,
            account_manager,
            transfer_stats: TransferStats::new(timestamp, 0),
            is_server: false,
            needs_close_message: Arc::new(AtomicBool::new(true)),
            stopper_rx: Some(stopper_rx),
            queue_worker: SessionQueueWorker::new(stopper_tx),
            fcm_keys
        };

        Ok(Self::from(inner))
    }

    /// During impersonal mode, a new connection may come inbound. Unlike above in Self::new, we do not yet have the implicated cid nor nid.
    /// We must then expect a welcome packet
    ///
    /// When this is called, the connection is implied to be in impersonal mode. As such, the calling closure should have a way of incrementing
    /// the provisional ticket.
    pub fn new_incoming(hdp_remote: HdpServerRemote, local_bind_addr: SocketAddr, local_node_type: HyperNodeType, kernel_tx: UnboundedSender<HdpServerResult>, session_manager: HdpSessionManager, account_manager: AccountManager, time_tracker: TimeTracker, remote_peer: SocketAddr, provisional_ticket: Ticket) -> Self {
        let timestamp = time_tracker.get_global_time_ns();
        let (stopper_tx, stopper_rx) = channel(1);
        let inner = HdpSessionInner {
            pqc_algorithm: None,
            tcp_only: false,
            local_bind_addr,
            to_wave_ports: None,
            wave_socket_loader: None,
            local_node_type,
            remote_node_type: None,
            security_level: SecurityLevel::LOW,
            implicated_cid: Arc::new(Atomic::new(None)),
            external_addr: Arc::new(Atomic::new(None)),
            time_tracker,
            kernel_ticket: provisional_ticket,
            remote_peer,
            cnac: None,
            kernel_tx: kernel_tx.clone(),
            session_manager: session_manager.clone(),
            state_container: StateContainerInner::new(kernel_tx, hdp_remote, KEEP_ALIVE_TIMEOUT_NS),
            to_primary_stream: None,
            state: SessionState::SocketJustOpened,
            account_manager,
            transfer_stats: TransferStats::new(timestamp, 0),
            is_server: true,
            needs_close_message: Arc::new(AtomicBool::new(true)),
            stopper_rx: Some(stopper_rx),
            queue_worker: SessionQueueWorker::new(stopper_tx),
            fcm_keys: None
        };

        Self::from(inner)
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
        let this_socket_loader = self.clone();
        let this_queue_worker = self.clone();
        let this_p2p_listener = self.clone();
        let this_close = self.clone();

        let (session_future, handle_zero_state, implicated_cid, to_kernel_tx, needs_close_message) = {

            let (writer, reader) = misc::net::safe_split_stream(tcp_stream);

            let (primary_outbound_tx, primary_outbound_rx) = unbounded();
            let primary_outbound_tx = OutboundTcpSender::from(primary_outbound_tx);
            let primary_outbound_rx = OutboundTcpReceiver::from(primary_outbound_rx);

            let mut this_ref = inner_mut!(this);
            this_ref.queue_worker.load_session(&this_close);
            let (obfuscator, packet_opt) = HeaderObfuscator::new(this_ref.is_server);
            //let sess_id = this_ref.kernel_ticket;
            this_ref.to_primary_stream = Some(primary_outbound_tx.clone());

            let to_kernel_tx_clone = this_ref.kernel_tx.clone();

            let timestamp = this_ref.time_tracker.get_global_time_ns();
            let local_nid = this_ref.account_manager.get_local_nid();
            let cnac_opt = this_ref.cnac.clone();
            let implicated_cid = this_ref.implicated_cid.clone();
            let needs_close_message = this_ref.needs_close_message.clone();


            // setup the socket-loader
            let (socket_loader_tx, socket_loader_rx) = tokio::sync::oneshot::channel();
            this_ref.wave_socket_loader = Some(socket_loader_tx);
            let stopper = this_ref.stopper_rx.take().unwrap();

            // Ensure the tx forwards to the writer
            let writer_future = spawn_handle!(Self::outbound_stream(primary_outbound_rx, writer, obfuscator.clone()));
            let reader_future = spawn_handle!(Self::execute_inbound_stream(reader, this_inbound, None, obfuscator));
            //let timer_future = Self::execute_timer(this.clone());
            let queue_worker_future = Self::execute_queue_worker(this_queue_worker);
            let socket_loader_future = spawn_handle!(Self::socket_loader(this_socket_loader, to_kernel_tx_clone.clone(), socket_loader_rx));
            let stopper_future = spawn_handle!(Self::stopper(stopper));
            let handle_zero_state = Self::handle_zero_state(packet_opt, primary_outbound_tx.clone(), this_outbound, this_ref.state, timestamp, local_nid, cnac_opt, connect_mode);
            std::mem::drop(this_ref);

            let session_future= spawn_handle!(async move {
                            tokio::select! {
                                res0 = writer_future => res0,
                                res1 = reader_future => res1,
                                res2 = stopper_future => res2,

                                res5 = socket_loader_future => res5
                            }
                        });

            //let session_future = futures::future::try_join4(writer_future, reader_future, timer_future, socket_loader_future);


            // this will automatically drop when getting polled, because it tries upgrading a Weak reference to the session
            // as such, if it cannot, it will end the future. We do this to ensure there is no deadlocking.
            // We now spawn this future independently in order to fix a deadlocking bug in multi-threaded mode. By spawning a
            // separate task, we solve the issue of re-entrancing of mutex
            //#[cfg(feature = "multi-threaded")]
            let _ = spawn!(queue_worker_future);
            if let Some(p2p_listener) = p2p_listener {
                // NOTE: this currently implies that once an error occurs for the session, the p2p listener is down for the remaining of the session
                let _ = spawn!(crate::hdp::peer::p2p_conn_handler::p2p_conn_handler(p2p_listener, this_p2p_listener));
            }

            (session_future, handle_zero_state, implicated_cid, to_kernel_tx_clone, needs_close_message)
        };


        if let Err(err) = handle_zero_state.await {
            log::error!("Unable to proceed past session zero-state. Stopping session");
            return Err((err, implicated_cid.load(Ordering::SeqCst)));
        }


        let res = session_future.await.map_err(|err| (NetworkError::Generic(err.to_string()), None))?
            .map_err(|err| (NetworkError::Generic(err.to_string()), None))?;

        match res {
            Ok(_) => {
                log::info!("Done EXECUTING sess");
                Ok(implicated_cid.load(Ordering::SeqCst))
            }

            Err(err) => {
                let ticket = inner!(this_close).kernel_ticket;
                let reason = err.to_string();
                let needs_close_message = needs_close_message.load(Ordering::Relaxed);
                let cid = implicated_cid.load(Ordering::Relaxed);

                log::info!("Session {} connected to {} is ending! Reason: {}. Needs close message? {} (strong count: {})", ticket.0, peer_addr, reason.as_str(), needs_close_message, this_close.strong_count());

                if needs_close_message {
                    if let Some(cid) = cid {
                        let result = HdpServerResult::Disconnect(ticket, cid, false, None, reason);
                        // false indicates a D/C caused by a non-dc subroutine
                        let _ = to_kernel_tx.unbounded_send(result);
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

    /// Before going through the usual loopy business, check to see if we need to initiate either a stage0 REGISTER or CONNECT packet
    async fn handle_zero_state(zero_packet: Option<BytesMut>, to_outbound: OutboundTcpSender, session: HdpSession, state: SessionState, timestamp: i64, local_nid: u64, cnac: Option<ClientNetworkAccount>, connect_mode: Option<ConnectMode>) -> Result<(), NetworkError> {
        if let Some(zero) = zero_packet {
            to_outbound.unbounded_send(zero).map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;
        }

        match state {
            SessionState::NeedsRegister => {
                log::info!("Beginning registration subroutine!");
                let session_ref = inner!(session);
                let security_level = session_ref.security_level;
                let potential_cids_alice = session_ref.account_manager.get_local_nac().client_only_generate_possible_cids().ok_or(NetworkError::InvalidExternalRequest("Local node is not a filesystem type, and cannot act as a client"))?;
                // we supply 0,0 for cid and new drill vers by default, even though it will be reset by bob
                let alice_constructor = HyperRatchetConstructor::new_alice(Some(session_ref.pqc_algorithm.unwrap_or(DEFAULT_PQC_ALGORITHM)), 0, 0, Some(security_level));
                let mut state_container = inner_mut!(session_ref.state_container);
                state_container.register_state.last_packet_time = Some(Instant::now());
                let transfer = alice_constructor.stage0_alice();

                let stage0_register_packet = crate::hdp::hdp_packet_crafter::do_register::craft_stage0(DEFAULT_PQC_ALGORITHM, timestamp, local_nid, transfer, &potential_cids_alice);
                if let Err(err) = to_outbound.unbounded_send(stage0_register_packet).map_err(|_| NetworkError::InternalError("Writer stream corrupted")) {
                    return Err(err);
                }

                state_container.register_state.constructor = Some(alice_constructor);
                log::info!("Successfully sent stage0 register packet outbound");
            }

            SessionState::NeedsConnect => {
                log::info!("Beginning pre-connect subroutine!");
                let session_ref = inner!(session);
                let security_level = session_ref.security_level;
                let tcp_only = session_ref.tcp_only;
                let timestamp = session_ref.time_tracker.get_global_time_ns();
                let cnac = cnac.as_ref().unwrap();
                // reset the toolset's ARA
                let ref static_aux_hr = cnac.refresh_static_hyper_ratchet();
                //static_aux_hr.verify_level(Some(security_level)).map_err(|_| NetworkError::Generic(format!("Invalid security level. Maximum security level for this account is {:?}", static_aux_hr.get_default_security_level())))?;
                let alice_constructor = HyperRatchetConstructor::new_alice(Some(session_ref.pqc_algorithm.unwrap_or(DEFAULT_PQC_ALGORITHM)), cnac.get_cid(), 0, Some(security_level));
                let transfer = alice_constructor.stage0_alice();
                let max_usable_level = static_aux_hr.get_default_security_level();

                let mut state_container = inner_mut!(session_ref.state_container);
                // NEXT STEP: check preconnect, and update internal security-level recv side to the security level found in transfer to ensure all future packages are at that security-level
                let syn = hdp_packet_crafter::pre_connect::craft_syn(static_aux_hr, transfer, tcp_only, timestamp, state_container.keep_alive_timeout_ns, max_usable_level);

                state_container.pre_connect_state.last_stage = packet_flags::cmd::aux::do_preconnect::SYN_ACK;
                state_container.pre_connect_state.constructor = Some(alice_constructor);
                state_container.connect_state.connect_mode = connect_mode;

                to_outbound.unbounded_send(syn).map_err(|_| NetworkError::InternalError("Writer stream corrupted"))?;

                log::info!("Successfully sent SYN pre-connect packet");
            }

            // This implies this node received a new incoming connection. It is up to the other node, Alice, to send a stage 0 packet
            SessionState::SocketJustOpened => {
                log::info!("No actions needed on primary TCP port; beginning outbound listening subroutine ...");
                // If somebody makes a connection to this node, but doesn't send anything, we need a way to remove
                // such a stale connection. By setting the value below, we ensure the possibility that the session
                // timer removes it
                inner_mut!(inner_mut!(session).state_container).connect_state.last_packet_time = Some(Instant::now());
            }

            _ => {
                log::error!("Invalid initial state. Check program logic");
                std::process::exit(-1);
            }
        }

        Ok(())
    }

    async fn socket_loader(this: HdpSession, to_kernel: UnboundedSender<HdpServerResult>, receiver: tokio::sync::oneshot::Receiver<Vec<(UdpSocket, HolePunchedSocketAddr)>>) -> Result<(), NetworkError> {
        let this_weak = this.as_weak();
        std::mem::drop(this);
        let (unordered_futures, udp_sender_future) = {
            let sockets = receiver.await.map_err(|err| NetworkError::Generic(err.to_string()))?;

            let this = HdpSession::upgrade_weak(&this_weak).ok_or(NetworkError::InternalError("HdpSession no longer exists"))?;

            let mut sess = inner_mut!(this);
            let local_is_server = sess.is_server;

            //log::info!("[Oneshot channel] received sockets. Now loading ...");
            let mut sinks = Vec::with_capacity(sockets.len());
            let (outbound_sender_tx, outbound_sender_rx) = unbounded();
            let udp_sender = OutboundUdpSender::new(outbound_sender_tx, sockets.len());

            sess.to_wave_ports = Some(udp_sender.clone());
            inner_mut!(sess.state_container).udp_sender = Some(udp_sender);
            std::mem::drop(sess);

            let unordered_futures = futures::stream::FuturesUnordered::new();
            // we supply the natted ip since it is where we expect to receive packets
            // whether local is server or not, we should expect to receive packets from natted
            let hole_punched_addr_ip = sockets[0].1.natted.ip();
            let mut hole_punched_addrs = Vec::with_capacity(sockets.len());

            for (socket, hole_punched_addr) in sockets {
                let local_bind_addr = socket.local_addr().unwrap();

                // unlike TCP, we will not use [LengthDelimitedCodec] because there is no guarantee that packets
                // will arrive in order
                let codec = super::codec::BytesCodec::new(CODEC_BUFFER_CAPACITY);

                let framed = UdpFramed::new(socket, codec);
                let (writer, reader) = framed.split();

                unordered_futures.push(Self::listen_wave_port(this.clone(), to_kernel.clone(), hole_punched_addr_ip, local_bind_addr.port(), reader));
                sinks.push(writer);
                hole_punched_addrs.push(hole_punched_addr);
                log::info!("Server established UDP Port {}", local_bind_addr);
            }

            //futures.push();
            let udp_sender_future = Self::wave_outbound_sender(local_is_server, outbound_sender_rx, hole_punched_addrs, to_kernel, sinks);
            (unordered_futures, udp_sender_future)
        };

        log::info!("[Q-UDP] Initiated UDP subsystem...");
        futures::future::try_join(unordered_futures.try_collect::<()>(), udp_sender_future).await
            .map(|_| ()).map_err(|err| {
            log::error!("UDP subsystem ending. Reason: {}", err.to_string());
            err
        })
    }

    pub async fn outbound_stream(primary_outbound_rx: OutboundTcpReceiver, mut writer: CleanShutdownSink<GenericNetworkStream, LengthDelimitedCodec, Bytes>, header_obfuscator: HeaderObfuscator) -> Result<(), NetworkError> {
        writer.send_all(&mut primary_outbound_rx.0.map(|packet| {
            Ok(header_obfuscator.prepare_outbound(packet))
        })).map_err(|err| NetworkError::Generic(err.to_string())).await
    }

    /// NOTE: We need to have at least one owning/strong reference to the session. Having the inbound stream own a single strong count makes the most sense
    pub async fn execute_inbound_stream(mut reader: CleanShutdownStream<GenericNetworkStream, LengthDelimitedCodec, Bytes>, ref this_main: HdpSession, p2p_handle: Option<P2PInboundHandle>, ref header_obfuscator: HeaderObfuscator) -> Result<(), NetworkError> {
        log::info!("HdpSession async inbound-stream subroutine executed");
        let (ref remote_peer, ref local_primary_port, ref implicated_cid, ref kernel_tx, ref primary_stream) = if let Some(p2p) = p2p_handle {
            (p2p.remote_peer, p2p.local_bind_port, p2p.implicated_cid, p2p.kernel_tx, p2p.to_primary_stream)
        } else {
            let borrow = inner!(this_main);
            let remote_peer = borrow.remote_peer.clone();
            let local_primary_port = borrow.local_bind_addr.port();
            let implicated_cid = borrow.implicated_cid.clone();
            let kernel_tx = borrow.kernel_tx.clone();
            let primary_stream = borrow.to_primary_stream.clone().unwrap();
            (remote_peer, local_primary_port, implicated_cid, kernel_tx, primary_stream)
        };

        let reader = async_stream::stream! {
            while let Some(value) = reader.next().await {
                yield value;
            }
        };

            let res = reader.try_for_each_concurrent(None, move |packet| {
                async move {
                    //log::info!("Primary port received packet with {} bytes+header or {} payload bytes ..", packet.len(), packet.len() - HDP_HEADER_BYTE_LEN);
                    match hdp_packet_processor::raw_primary_packet::process(implicated_cid.load(Ordering::Relaxed), this_main, remote_peer.clone(), *local_primary_port, packet, header_obfuscator).await {
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
                    log::error!("primary port reader error {}: {}", error, err.to_string());
                }

                NetworkError::Generic(err.to_string())
            });

        res
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
        let queue_worker = {
            //let this_interval = this_main.clone();
            let borrow = inner!(this_main);
            let queue_worker = borrow.queue_worker.clone();
            let is_server = borrow.is_server;
            std::mem::drop(borrow);

            // now, begin loading the subroutines
            //let mut loop_idx = 0;
            queue_worker.insert_reserved(Some(QueueWorkerTicket::Oneshot(PROVISIONAL_CHECKER, RESERVED_CID_IDX)), LOGIN_EXPIRATION_TIME, |sess: &mut InnerParameterMut<SessionBorrow, HdpSessionInner>| {
                if sess.state != SessionState::Connected {
                    QueueWorkerResult::EndSession
                } else {
                    // remove it from being called again
                    QueueWorkerResult::Complete
                }
            });

            if !is_server {
                queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(DRILL_REKEY_WORKER, 0)), Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE), |sess| {
                    if sess.state == SessionState::Connected {
                        let timestamp = sess.time_tracker.get_global_time_ns();
                        let ticket = sess.kernel_ticket;
                        let security_level = sess.security_level;
                        let transfer_stats = sess.transfer_stats.clone();
                        let mut state_container = inner_mut!(sess.state_container);
                        let p2p_sessions = state_container.active_virtual_connections.iter().filter_map(|vconn| {
                            if vconn.1.endpoint_container.as_ref()?.endpoint_crypto.local_is_initiator {
                                Some(vconn.1.connection_type)
                            } else {
                                None
                            }
                        }).collect::<Vec<VirtualTargetType>>();

                        let virtual_target = VirtualTargetType::HyperLANPeerToHyperLANServer(ENDPOINT_ENCRYPTION_OFF);
                        if let Ok(_) = sess.initiate_drill_update(timestamp, virtual_target, &mut wrap_inner_mut!(state_container), Some(ticket)) {
                            // now, call for each p2p session
                            for vconn in p2p_sessions {
                                if let Err(err) = sess.initiate_drill_update(timestamp, vconn, &mut wrap_inner_mut!(state_container), None) {
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
                });
            }

            queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(KEEP_ALIVE_CHECKER, 0)), Duration::from_millis(KEEP_ALIVE_INTERVAL_MS), move |sess| {
                let timestamp = sess.time_tracker.get_global_time_ns();
                if sess.state == SessionState::Connected {
                    let state_container = inner!(sess.state_container);
                    if state_container.keep_alive_timeout_ns != 0 {
                        if state_container.keep_alive_subsystem_timed_out(timestamp) {
                            log::warn!("The keep alive subsystem has timed out. Executing shutdown phase (skipping proper disconnect)");
                            QueueWorkerResult::EndSession
                        } else {
                            QueueWorkerResult::Incomplete
                        }
                    } else {
                        log::warn!("Keep alive subsystem will not be used for this session as requested");
                        QueueWorkerResult::Complete
                    }
                } else {
                    // keep it running, as we may be in provisional mode
                    QueueWorkerResult::Incomplete
                }
            });

            queue_worker.insert_reserved(Some(QueueWorkerTicket::Periodic(FIREWALL_KEEP_ALIVE, 0)), FIREWALL_KEEP_ALIVE_UDP, |sess| {
                if sess.state == SessionState::Connected {
                    if sess.tcp_only {
                        //log::info!("TCP only mode detected. Removing FIREWALL_KEEP_ALIVE subroutine");
                        return QueueWorkerResult::Complete;
                    }

                    if !sess.to_wave_ports.as_ref().unwrap().send_keep_alive_through_all() {
                        return QueueWorkerResult::EndSession;
                    }
                }

                QueueWorkerResult::Incomplete
            });

            queue_worker
        };

        std::mem::drop(this_main);
        queue_worker.await
    }

    /// Similar to process_outbound_packet, but optimized to handle files
    pub fn process_outbound_file(&self, ticket: Ticket, max_group_size: Option<usize>, file: PathBuf, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let this = inner!(self);
        let cnac = this.cnac.clone().ok_or(NetworkError::InvalidExternalRequest("CNAC not loaded"))?;
        if this.state != SessionState::Connected {
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
                            return Err(NetworkError::InternalError("Virtual connection not found for channel"))
                        }
                    }

                    _ => {
                        log::error!("HyperWAN functionality not yet implemented");
                        return Err(NetworkError::InternalError("HyperWAN functionality not yet implemented"))
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
                std::mem::drop(this);
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
                                    let mut sess = inner_mut!(this);
                                    if sess.state != SessionState::Connected {
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
                                    sess.transfer_stats += TransferStats::new(timestamp, group_byte_len as isize);
                                    std::mem::drop(sess);
                                    (group_id, key)
                                };

                                // When a wave ACK in the previous group comes, if the group is 50% or more done, the group_sender_rx will
                                // received a signal here

                                if let None = next_gs_alerter_rx.next().await {
                                    log::warn!("next_gs_alerter: steam ended");
                                    return;
                                }

                                let this = inner!(this);

                                this.queue_worker.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |sess| {
                                    let mut state_container = inner_mut!(sess.state_container);
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

                                                    // send to kernel
                                                    let _ = sess.send_to_kernel(HdpServerResult::InternalServerError(Some(ticket), format!("Timeout on ticket {}", ticket)));

                                                    QueueWorkerResult::Complete
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
    /// This will return None if the connection is not engaged. An incomplete state will not
    /// be valid either.
    ///
    /// This will send the group header too
    #[allow(unused_results)]
    pub fn process_outbound_message(&self, ticket: Ticket, packet: SecBuffer, virtual_target: VirtualTargetType, security_level: SecurityLevel) -> Result<(), NetworkError> {
        let mut this = inner_mut!(self);
        let algorithm = this.pqc_algorithm;
        if this.state != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send data (ticket: {}) outbound, but the session is not connected", ticket)))
        } else {
            let cnac = this.cnac.clone().unwrap();
            let time_tracker = this.time_tracker.clone();
            let timestamp = time_tracker.get_global_time_ns();
            // object singleton == 0 implies that the data does not belong to a file
            const OBJECT_SINGLETON: u32 = 0;
            // Drop this to ensure that it doesn't block other async closures from accessing the inner device
            // std::mem::drop(this);
            let (mut transmitter, group_id, target_cid) = match virtual_target {
                VirtualTargetType::HyperLANPeerToHyperLANServer(implicated_cid) => {
                    // if we are sending this just to the HyperLAN server (in the case of file uploads),
                    // then, we use this session's pqc, the cnac's latest drill, and 0 for target_cid
                    let (alice_constructor, latest_hyper_ratchet, group_id) = cnac.visit_mut(|mut inner| -> Result<_, NetworkError> {
                        let group_id = inner.crypt_container.get_and_increment_group_id();
                        let latest_hyper_ratchet = inner.crypt_container.get_hyper_ratchet(None).cloned().unwrap();
                        latest_hyper_ratchet.verify_level(Some(security_level)).map_err(|_err| NetworkError::Generic(format!("Invalid security level. The maximum security level for this session is {:?}", latest_hyper_ratchet.get_default_security_level())))?;
                        let constructor = inner.crypt_container.get_next_constructor(algorithm);

                        Ok((constructor, latest_hyper_ratchet.clone(), group_id))
                    })?;

                    let to_primary_stream = this.to_primary_stream.clone().unwrap();

                    (GroupTransmitter::new_message(to_primary_stream, OBJECT_SINGLETON, ENDPOINT_ENCRYPTION_OFF, RatchetPacketCrafterContainer::new(latest_hyper_ratchet, alice_constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, implicated_cid)
                }

                VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    log::info!("Sending HyperLAN peer ({}) <-> HyperLAN Peer ({})", implicated_cid, target_cid);

                    // here, we don't use the base session's PQC. Instead, we use the vconn's pqc and Toolset
                    let mut state_container = inner_mut!(this.state_container);
                    if let Some(vconn) = state_container.active_virtual_connections.get_mut(&target_cid) {
                        if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                            let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                            let to_primary_stream_preferred = endpoint_container.get_direct_p2p_primary_stream().cloned().unwrap_or_else(|| this.to_primary_stream.clone().unwrap());
                            let latest_usable_ratchet = endpoint_container.endpoint_crypto.get_hyper_ratchet(None).unwrap().clone();
                            latest_usable_ratchet.verify_level(Some(security_level)).map_err(|_err| NetworkError::Generic(format!("Invalid security level. The maximum security level for this session is {:?}", latest_usable_ratchet.get_default_security_level())))?;
                            let alice_constructor = endpoint_container.endpoint_crypto.get_next_constructor(algorithm);

                            (GroupTransmitter::new_message(to_primary_stream_preferred, OBJECT_SINGLETON, target_cid, RatchetPacketCrafterContainer::new(latest_usable_ratchet, alice_constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, target_cid)
                        } else {
                            log::error!("Endpoint container not found");
                            return Ok(());
                        }
                    } else {
                        log::error!("Unable to find active vconn for the channel");
                        return Ok(());
                    }
                }

                _ => {
                    return Err(NetworkError::InvalidExternalRequest("HyperWAN functionality not yet implemented"))
                }
            };


            // We manually send the header. The tails get sent automatically
            log::info!("[message] Sending GROUP HEADER through primary stream for group {}", group_id);
            let group_len = transmitter.get_total_plaintext_bytes();
            this.try_action(Some(ticket), || transmitter.transmit_group_header(virtual_target))?;

            this.transfer_stats += TransferStats::new(timestamp, group_len as isize);

            let outbound_container = OutboundTransmitterContainer::new(None, transmitter, group_len, 1, 0, ticket);
            // The payload packets won't be sent until a GROUP_HEADER_ACK is received
            // NOTE: Ever since using GroupKeys, we use either the implicated_cid (for client -> server conns) or target_cids (for peer conns)
            let key = GroupKey::new(target_cid, group_id);
            inner_mut!(this.state_container).outbound_transmitters.insert(key, outbound_container);

            this.queue_worker.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |sess| {
                let state_container = inner!(sess.state_container);
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
        }
    }

    pub(crate) fn process_outbound_broadcast_command(&self, ticket: Ticket, command: GroupBroadcast) -> Result<(), NetworkError> {
        let this = inner!(self);
        if this.state != SessionState::Connected {
            return Err(NetworkError::InternalError("Session not connected"));
        }

        let cnac = this.cnac.as_ref().unwrap();
        let security_level = this.security_level;
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
    pub(crate) fn dispatch_peer_command(&self, ticket: Ticket, peer_command: PeerSignal, security_level: SecurityLevel) -> Result<(), NetworkError> {
        log::info!("Dispatching peer command ...");
        let this = inner!(self);
        let timestamp = this.time_tracker.get_global_time_ns();
        let mut do_save = false;
        if let Some(cnac) = this.cnac.as_ref() {
            if let Some(to_primary_stream) = this.to_primary_stream.as_ref() {
                // move into the closure without cloning the drill
                return cnac.visit_mut(|mut inner| {
                    let this_cid = inner.cid;
                    let signal_processed = match peer_command {
                        // case 1: user just initiated a post-register request that has Fcm enabled
                        PeerSignal::PostRegister(vconn, a, b, c, FcmPostRegister::Enable) => {
                            let target_cid = vconn.get_original_target_cid();
                            log::info!("[FCM] client {} requested FCM post-register with {}", inner.cid, target_cid);
                            let state_container = inner!(this.state_container);
                            if state_container.peer_kem_states.contains_key(&target_cid) || inner.fcm_crypt_container.contains_key(&target_cid) {
                                return Err(NetworkError::InvalidExternalRequest("Cannot register to the specified client because a concurrent registration process is already occurring, or already registered"));
                            }

                            // create constructor
                            let fcm_constructor = FcmRatchetConstructor::new_alice(inner.cid, 0);
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

                            let bob_constructor = FcmRatchetConstructor::new_bob(FcmAliceToBobTransfer::deserialize_from_vector(&transfer[..]).map_err(|err| NetworkError::Generic(err.to_string()))?).ok_or(NetworkError::InvalidExternalRequest("Invalid FCM ratchet constructor"))?;
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

                    if do_save {
                        cnac.spawn_save_task_on_threadpool();
                    }

                    let hyper_ratchet = inner.crypt_container.get_hyper_ratchet(None).unwrap();
                    let packet = super::hdp_packet_crafter::peer_cmd::craft_peer_signal(hyper_ratchet, signal_processed, ticket, timestamp, security_level);
                    to_primary_stream.unbounded_send(packet).map_err(|err| NetworkError::SocketError(err.to_string()))
                })
            }
        }


        Err(NetworkError::InternalError("Invalid session configuration"))
    }

    async fn listen_wave_port<S: Stream<Item=Result<(BytesMut, SocketAddr), std::io::Error>> + Unpin>(this: HdpSession, to_kernel: UnboundedSender<HdpServerResult>, hole_punched_addr_ip: IpAddr, local_port: u16, mut stream: S) -> Result<(), NetworkError> {
        while let Some(res) = stream.next().await {
            match res {
                Ok((packet, remote_peer)) => {
                    log::info!("packet received on waveport {} has {} bytes (src: {:?})", local_port, packet.len(), &remote_peer);
                    if remote_peer.ip() != hole_punched_addr_ip {
                        log::error!("The packet received is not part of the firewall session. Dropping");
                    } else {
                        if packet != KEEP_ALIVE {
                            let packet = HdpPacket::new_recv(packet, remote_peer, local_port);
                            if let Err(err) = this.process_inbound_packet_wave(packet) {
                                to_kernel.unbounded_send(HdpServerResult::InternalServerError(None, err.to_string())).unwrap();
                                log::error!("The session manager returned a critical error. Aborting UDP subsystem");
                                return Err(err);
                            }
                        }
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

    async fn wave_outbound_sender<S: SinkExt<(Bytes, SocketAddr)> + Unpin>(local_is_server: bool, receiver: UnboundedReceiver<(usize, BytesMut)>, hole_punched_addrs: Vec<HolePunchedSocketAddr>, to_kernel_tx: UnboundedSender<HdpServerResult>, mut sinks: Vec<S>) -> Result<(), NetworkError> {
        let mut receiver = tokio_stream::wrappers::UnboundedReceiverStream::new(receiver);
        while let Some((idx, packet)) = receiver.next().await {
            if let Some(sink) = sinks.get_mut(idx) {

                // TODO: figure out the logistics of this IP mess for all possible use cases. This works for hyperlan though
                let send_addr = if local_is_server {
                    // if the local is server, we send to the natted ports instead of the initial. It is flip-flopped
                    hole_punched_addrs[idx].natted
                } else {
                    hole_punched_addrs[idx].initial
                };

                log::trace!("About to send packet w/len {} through UDP sink idx: {} | Dest: {:?}", packet.len(), idx, &send_addr);
                // TODO: UDP header obfuscation
                if let Err(_err) = sink.send((packet.freeze(), send_addr)).await {
                    to_kernel_tx.unbounded_send(HdpServerResult::InternalServerError(None, format!("Sink Error on idx {}", idx))).unwrap();
                }
            } else {
                log::error!("Invalid idx: {}", idx);
            }
        }

        log::info!("Outbound wave sender ending");

        Ok(())
    }

    /// In general, the packets that come through here are one of two general types: Either the modulated transmission of
    /// the encryption file, or, post-registration modulated data
    pub fn process_inbound_packet_wave(&self, packet: HdpPacket) -> Result<(), NetworkError> {
        if packet.get_length() < HDP_HEADER_BYTE_LEN {
            return Ok(());
        }

        let mut this = inner_mut!(self);

        //log::info!("Wave inbound port (original): {}", packet.get_remote_port());

        if let Some((header, payload)) = packet.parse() {
            // even in the case of proxy, we can quickly see if it's even worth proxying

            // now, check to see if we need to proxy the wave packet. With the same logic as with primary packets, we check
            // to see if the target_cid is not zero
            let target_cid = header.target_cid.get();
            let mut proxy_cid_info = None;
            let this_implicated_cid = this.implicated_cid.load(Ordering::SeqCst);
            if target_cid != 0 {
                // after the UDP hole-punching process, it is possible that packets arrive here
                // that are small ACK's. Ignore them, but check implicated_cid below since, if they arrive,
                // this will get triggered before a session starts
                if let Some(this_implicated_cid) = this_implicated_cid {
                    if this_implicated_cid != target_cid {
                        // we need to proxy the wave packet
                        log::info!("Proxying WAVE packet from {} to {}", this_implicated_cid, target_cid);
                        // check for the existence of the vconn
                        let state_container = inner!(this.state_container);
                        if let Some(peer_vconn) = state_container.active_virtual_connections.get(&target_cid) {
                            let senders = peer_vconn.sender.as_ref().unwrap();
                            if let Some(peer_udp_sender) = senders.0.as_ref() {
                                // in this case, we can complete the movement all the way through w/ UDP
                                if !peer_udp_sender.unbounded_send(packet.into_packet()) {
                                    log::error!("[UDP] Unable to proxy WAVE packet from {} to {} (TrySendError)", this_implicated_cid, target_cid);
                                    return Ok(());
                                }
                            } else {
                                // in this case, while we can route from A -> S w/ UDP, going from S -> B will require TCP
                                if let Err(_) = senders.1.unbounded_send(packet.into_packet()) {
                                    log::error!("[TCP] Unable to proxy WAVE packet from {} to {} (TrySendError)", this_implicated_cid, target_cid);
                                    return Ok(());
                                }
                            }
                            // now that the packet was forwarded, we automatically switch into the outer branch and return Ok(());
                        } else {
                            log::error!("Unable to proxy wave packet; Virtual connection to {} not active", target_cid);
                        }

                        return Ok(());
                    } else {
                        // since implicated_cid == target_cid, the packet has reached its destination
                        proxy_cid_info = Some((header.session_cid.get(), target_cid))
                    }
                }
                // else, the wave packet has reached its destination, and as such, the normal processing logic can execute below
            }

            // since we are here, it means the wave packet reached its destination
            let v_src_port = payload[0] as u16;
            let v_recv_port = payload[1] as u16;
            let payload = &payload[2..];

            log::info!("WAVE Packet with cmd {} being processed by session {}", header.cmd_primary, this.get_id());
            match header.cmd_primary {
                packet_flags::cmd::primary::GROUP_PACKET => {
                    match hdp_packet_processor::wave_group_packet::process(&mut wrap_inner_mut!(this), v_src_port, v_recv_port, &header, payload, proxy_cid_info) {
                        GroupProcessorResult::SendToKernel(_ticket, concatenated_packet) => {
                            //this.send_to_kernel(HdpServerResult::MessageDelivery(ticket, this_implicated_cid.unwrap(), concatenated_packet))?;
                            let mut state_container = inner_mut!(this.state_container);
                            if !state_container.forward_data_to_channel(0, header.group.get(), concatenated_packet) {
                                log::error!("Unable to send data to c2s channel");
                            }

                            Ok(())
                        }

                        GroupProcessorResult::ReplyToSender(return_packet) => {
                            this.send_to_primary_stream(None, return_packet)?;
                            Ok(())
                        }

                        GroupProcessorResult::Void => {
                            // no-op
                            Ok(())
                        }

                        GroupProcessorResult::Error(err) => {
                            this.send_to_kernel(HdpServerResult::InternalServerError(Some(header.context_info.get().into()), err))?;
                            Ok(())
                        }
                        GroupProcessorResult::ShutdownSession(err) => {
                            this.send_to_kernel(HdpServerResult::InternalServerError(Some(header.context_info.get().into()), err))?;
                            Err(NetworkError::InternalError("Session signalled to shutdown. Reason sent to kernel"))
                        }
                    }
                }

                _ => {
                    log::trace!("A non-group packet was received on a waveform port");
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
        let session = inner!(self);
        if session.state != SessionState::Connected {
            log::error!("Must be connected to HyperLAN in order to start disconnect")
        }

        let cnac = session.cnac.as_ref().unwrap();
        let hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();
        let timestamp = session.time_tracker.get_global_time_ns();
        let security_level = session.security_level;
        let to_primary_stream = session.to_primary_stream.as_ref().unwrap();
        let ref to_kernel_tx = session.kernel_tx;

        let disconnect_stage0_packet = hdp_packet_crafter::do_disconnect::craft_stage0(&hyper_ratchet, ticket, timestamp, security_level);
        Self::send_to_primary_stream_closure(to_primary_stream, to_kernel_tx, disconnect_stage0_packet, Some(ticket))
            .and_then(|_| Ok(true))
    }

    /// Stores the proposed credentials into the register state container
    pub fn store_proposed_credentials(&self, proposed_credentials: ProposedCredentials, stage_for: u8) {
        let this = inner_mut!(self);
        let mut state_container = inner_mut!(this.state_container);
        match stage_for {
            packet_flags::cmd::primary::DO_REGISTER => {
                state_container.register_state.proposed_credentials = Some(proposed_credentials);
            }

            packet_flags::cmd::primary::DO_CONNECT => {
                state_container.connect_state.proposed_credentials = Some(proposed_credentials);
                // we don't need to store the nonce here
            }

            _ => {
                panic!("Invalid proposed stage for credential insertion")
            }
        }
    }
}

impl HdpSessionInner {
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
    pub fn shutdown(&mut self) {
        self.state = SessionState::Disconnected
    }

    fn get_id(&self) -> u64 {
        match self.implicated_cid.load(Ordering::SeqCst) {
            Some(implicated_cid) => {
                implicated_cid
            }

            None => {
                self.kernel_ticket.0
            }
        }
    }

    #[allow(unused_results)]
    pub(crate) fn initiate_drill_update<K: ExpectedInnerTargetMut<StateContainerInner>>(&self, timestamp: i64, virtual_target: VirtualTargetType, state_container: &mut InnerParameterMut<K, StateContainerInner>, ticket: Option<Ticket>) -> Result<(), NetworkError> {
        let cnac = self.cnac.as_ref().unwrap();
        let security_level = self.security_level;

        match virtual_target {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => {
                let res = cnac.visit_mut(|mut inner| {
                    if inner.crypt_container.update_in_progress {
                        None
                    } else {
                        let latest_hyper_ratchet = inner.crypt_container.get_hyper_ratchet(None).cloned()?;
                        latest_hyper_ratchet.verify_level(Some(security_level)).ok()?;
                        let alice_constructor = latest_hyper_ratchet.next_alice_constructor(self.pqc_algorithm.clone());
                        inner.crypt_container.update_in_progress = true;
                        Some((latest_hyper_ratchet, alice_constructor))
                    }
                });

                match res {
                    Some((hyper_ratchet, alice_constructor)) => {
                        let stage0_packet = hdp_packet_crafter::do_drill_update::craft_stage0(&hyper_ratchet, alice_constructor.stage0_alice(), timestamp, ENDPOINT_ENCRYPTION_OFF, security_level);
                        state_container.drill_update_state.alice_hyper_ratchet = Some(alice_constructor);
                        let to_primary_stream = self.to_primary_stream.as_ref().unwrap();
                        let kernel_tx = &self.kernel_tx;
                        HdpSession::send_to_primary_stream_closure(to_primary_stream, kernel_tx, stage0_packet, ticket)
                    }

                    None => {
                        log::info!("Won't perform update b/c concurrent update occuring");
                        Ok(())
                    }
                }
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, peer_cid) => {
                const MISSING: NetworkError = NetworkError::InvalidExternalRequest("Peer not connected");
                let endpoint_container = &mut state_container.active_virtual_connections.get_mut(&peer_cid).ok_or(MISSING)?.endpoint_container.as_mut().ok_or(MISSING)?;
                let crypt = &mut endpoint_container.endpoint_crypto;
                let alice_constructor = if crypt.update_in_progress {
                    None
                } else {
                    let latest_hr = crypt.get_hyper_ratchet(None).cloned().unwrap();
                    latest_hr.verify_level(Some(security_level)).map_err(|err| NetworkError::Generic(err.to_string()))?;
                    let alice_constructor = latest_hr.next_alice_constructor(None);
                    crypt.update_in_progress = true;
                    Some((alice_constructor, latest_hr))
                };

                match alice_constructor {
                    Some((alice_constructor, latest_hyper_ratchet)) => {
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

    pub(crate) fn initiate_deregister(&self, _virtual_connection_type: VirtualConnectionType, ticket: Ticket) -> bool {
        log::info!("Initiating deregister process ...");
        let timestamp = self.time_tracker.get_global_time_ns();
        let cnac = self.cnac.as_ref().unwrap();
        let security_level = self.security_level;
        let ref hyper_ratchet = cnac.get_hyper_ratchet(None).unwrap();

        let stage0_packet = hdp_packet_crafter::do_deregister::craft_stage0(hyper_ratchet, timestamp, security_level);
        let mut state_container = inner_mut!(self.state_container);
        state_container.deregister_state.on_init(timestamp, ticket);
        std::mem::drop(state_container);
        self.send_to_primary_stream(Some(ticket), stage0_packet).is_ok()
    }

    pub(crate) fn is_provisional(&self) -> bool {
        //self.implicated_cid.is_none()
        // SocketJustOpened is only the state for a session created from an incoming connection
        self.state == SessionState::SocketJustOpened || self.state == SessionState::NeedsConnect || self.state == SessionState::ConnectionProcess || self.state == SessionState::NeedsRegister
    }
}

impl Drop for HdpSessionInner {
    fn drop(&mut self) {
        log::info!("*** Dropping HdpSession ***");
    }
}