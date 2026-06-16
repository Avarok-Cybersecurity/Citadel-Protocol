//! # Citadel Protocol State Management
//!
//! This module implements the state management system for the Citadel Protocol.
//! It handles connection states, virtual connections, group messaging, file transfers,
//! and maintains the overall protocol state machine.
//!
//! ## State Management
//!
//! The state container manages several types of states:
//!
//! - **Connection States**: Pre-connect, connect, register, and deregister states
//! - **Virtual Connections**: Peer-to-peer and client-server connections
//! - **Group Management**: Group channels and broadcast messaging
//! - **File Transfers**: Both inbound and outbound file transfers
//!
//! ## Features
//!
//! - **Virtual Connections**: Manages peer-to-peer and client-server connections
//! - **State Machine**: Handles protocol state transitions
//! - **Group Messaging**: Supports secure group communication
//! - **File Transfer**: Manages secure file transfers with progress tracking
//! - **UDP Support**: Optional UDP connectivity for performance
//!
//! ## Implementation Details
//!
//! The state container is split into several components:
//!
//! 1. **State Container**: Main state management interface
//! 2. **Virtual Connections**: Connection management
//! 3. **Group Management**: Group messaging and channels
//! 4. **File Transfer**: File transfer state tracking
//!
//! ## Security
//!
//! - All state transitions are cryptographically verified
//! - Connection states are protected against replay attacks
//! - Group keys are securely managed
//! - File transfers are encrypted end-to-end

use self::includes::*;

// Re-exported at the module root so external paths like
// `crate::proto::state_container::VirtualConnectionType` keep resolving.
pub use citadel_types::proto::{VirtualConnectionType, VirtualTargetType, C2S_IDENTITY_CID};

/// Shared imports for `state_container` and its submodules. Mirrors the
/// `packet_processor::includes` convention: each child file begins with
/// `use super::includes::*;`.
pub(crate) mod includes {
    pub(crate) use dashmap::DashMap;
    pub(crate) use std::collections::HashMap;
    pub(crate) use std::fmt::{Debug, Formatter};
    pub(crate) use std::ops::RangeInclusive;
    pub(crate) use std::sync::Arc;

    pub(crate) use crate::proto::disconnect_tracker::DisconnectToken;
    pub(crate) use crate::proto::packet_processor::primary_group_packet::get_resp_target_cid_from_header;

    pub(crate) use crate::proto::outbound_sender::{unbounded, UnboundedSender};
    pub(crate) use zerocopy::Ref;

    pub(crate) use citadel_crypt::scramble::crypt_splitter::{
        GroupReceiver, GroupReceiverConfig, GroupReceiverStatus,
    };
    pub(crate) use citadel_user::client_account::ClientNetworkAccount;
    pub(crate) use netbeam::time_tracker::TimeTracker;

    pub(crate) use crate::constants::{
        GROUP_TIMEOUT_MS, INDIVIDUAL_WAVE_TIMEOUT_MS, KEEP_ALIVE_INTERVAL_MS,
        MAX_OUTGOING_UNPROCESSED_REQUESTS,
    };
    pub(crate) use crate::error::NetworkError;
    pub(crate) use crate::functional::IfEqConditional;
    pub(crate) use crate::prelude::{InternalServerError, ReKeyResult, ReKeyReturnType};
    pub(crate) use crate::proto::misc::dual_cell::DualCell;
    pub(crate) use crate::proto::misc::dual_late_init::DualLateInit;
    pub(crate) use crate::proto::misc::dual_rwlock::DualRwLock;
    pub(crate) use crate::proto::misc::platform_ops::PlatformOps;
    pub(crate) use crate::proto::node_result::{NodeResult, ObjectTransferHandle};
    pub(crate) use crate::proto::outbound_sender::{
        OutboundPrimaryStreamSender, OutboundUdpSender,
    };
    pub(crate) use crate::proto::packet::packet_flags;
    pub(crate) use crate::proto::packet::HdpHeader;
    pub(crate) use crate::proto::packet_crafter::ObjectTransmitter;
    pub(crate) use crate::proto::packet_processor::includes::{CitadelSession, Instant};
    pub(crate) use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
    pub(crate) use crate::proto::packet_processor::PrimaryProcessorResult;
    pub(crate) use crate::proto::peer::channel::{PeerChannel, UdpChannel};
    pub(crate) use crate::proto::peer::group_channel::{GroupBroadcastPayload, GroupChannel};
    pub(crate) use crate::proto::peer::p2p_conn_handler::DirectP2PRemote;
    pub(crate) use crate::proto::remote::{NodeRemote, Ticket};
    pub(crate) use crate::proto::session::{SessionRequest, SessionState, UserMessage};
    pub(crate) use crate::proto::session_queue_handler::SessionQueueWorkerHandle;
    pub(crate) use crate::proto::state_subcontainers::connect_state_container::ConnectState;
    pub(crate) use crate::proto::state_subcontainers::deregister_state_container::DeRegisterState;
    pub(crate) use crate::proto::state_subcontainers::meta_expiry_container::MetaExpiryState;
    pub(crate) use crate::proto::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
    pub(crate) use crate::proto::state_subcontainers::preconnect_state_container::PreConnectState;
    pub(crate) use crate::proto::state_subcontainers::register_state_container::RegisterState;
    pub(crate) use crate::proto::transfer_stats::TransferStats;
    pub(crate) use crate::proto::{packet_crafter, send_with_error_logging};
    pub(crate) use crate::{ProtocolMessenger, ProtocolRatchetManager};
    pub(crate) use bytes::Bytes;
    pub(crate) use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
    pub(crate) use citadel_crypt::messaging::MessengerLayerOrderedMessage;
    pub(crate) use citadel_crypt::ordered_channel::OrderedChannel;
    pub(crate) use citadel_crypt::ratchets::ratchet_manager::RatchetMessage;
    pub(crate) use citadel_crypt::ratchets::Ratchet;
    pub(crate) use citadel_io::tokio::sync::mpsc::unbounded_channel;
    pub(crate) use citadel_io::tokio_stream::wrappers::UnboundedReceiverStream;
    pub(crate) use citadel_io::{tokio, Mutex};
    pub(crate) use citadel_types::crypto::SecurityLevel;
    pub(crate) use citadel_types::crypto::{PreSharedKey, SecBuffer};
    pub(crate) use citadel_types::prelude::ObjectId;
    pub(crate) use citadel_types::proto::{
        MessageGroupKey, ObjectTransferOrientation, ObjectTransferStatus, SessionSecuritySettings,
        TransferType, UdpMode, VirtualObjectMetadata,
    };
    pub(crate) use citadel_user::backend::utils::*;
    pub(crate) use citadel_user::backend::PersistenceHandler;
    pub(crate) use citadel_wire::nat_identification::NatType;
    pub(crate) use std::sync::atomic::{AtomicBool, Ordering};

    pub(crate) use super::super::state_container::{
        VirtualConnectionType, VirtualTargetType, C2S_IDENTITY_CID,
    };

    // Local types defined in `mod.rs`, re-exported so child modules reach
    // them via `use super::includes::*;`.
    pub(crate) use super::{
        EndpointChannelContainer, FileKey, GroupKey, GroupReceiverContainer, InboundFileTransfer,
        P2PDisconnectSignal, ReKeyIndex, StateContainer, StateContainerInner,
        UnorderedChannelContainer, VirtualConnection,
    };
}

impl<R: Ratchet> Debug for StateContainer<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateContainer")
    }
}

define_outer_struct_wrapper!(StateContainer, StateContainerInner, <R: Ratchet>, <R>);

mod channels;
mod inbound_transfer;
mod monitoring;
mod outbound_transfer;
mod rekey_and_groups;
mod transfer_error;
mod virtual_connections;

/// For keeping track of the stages
pub struct StateContainerInner<R: Ratchet> {
    pub(super) pre_connect_state: PreConnectState<R>,
    pub(super) node_remote: NodeRemote<R>,
    /// No hashmap here, since register is only for a single target
    pub(super) register_state: RegisterState<R>,
    /// No hashmap here, since connect is only for a single target
    pub(super) connect_state: ConnectState,
    pub(super) deregister_state: DeRegisterState,
    pub(super) meta_expiry_state: MetaExpiryState,
    pub(super) network_stats: NetworkStats,
    // Concurrent maps (per-entry shard locks): the inbound object/file path touches these per wave
    // packet (`on_group_payload_received`). `DashMap` lets that hot path run under a *read* lock on the
    // StateContainer, so concurrent vconns' file transfers don't serialize on the coarse write lock (the
    // inbound twin of the `outbound_transmitters` convoy fix — see bench/RESULTS.md "C8 gate").
    pub(super) inbound_files: DashMap<FileKey, InboundFileTransfer>,
    pub(super) outbound_files: HashMap<FileKey, OutboundFileTransfer>,
    pub(super) file_transfer_handles: DashMap<FileKey, UnboundedSender<ObjectTransferStatus>>,
    pub(super) inbound_groups: DashMap<GroupKey, GroupReceiverContainer>,
    // Concurrent map (per-entry shard locks): the sender registers a transmitter on send and removes
    // it on the GROUP_HEADER_ACK — both per message. A `DashMap` lets those happen under a *read* lock
    // on the StateContainer, so concurrent vconns' sends don't serialize on the coarse write lock.
    pub(super) outbound_transmitters: DashMap<GroupKey, OutboundTransmitterContainer<R>>,
    pub(super) peer_kem_states: HashMap<u64, PeerKemStateContainer<R>>,
    // u64 is peer id, ticket is the local original ticket (ticket may
    // transform if a simultaneous connect)
    pub(super) outgoing_peer_connect_attempts: HashMap<u64, OutgoingPeerConnectionAttempt>,
    pub(super) udp_primary_outbound_tx: Option<OutboundUdpSender>,
    pub(super) kernel_tx: UnboundedSender<NodeResult<R>>,
    pub(super) active_virtual_connections: HashMap<u64, VirtualConnection<R>>,
    /// Ratchets extracted from P2P vconns before removal, allowing in-flight
    /// packets to be decrypted after the stream dies. Cleared when a new
    /// connection for the same peer is created or at session shutdown.
    pub(super) stale_p2p_ratchets: HashMap<u64, R>,
    pub(crate) keep_alive_timeout_ns: i64,
    pub(crate) state: DualCell<SessionState>,
    // whenever a c2s or p2p channel is loaded, this is fired to signal any UDP loaders that it is safe to store the UDP conn in the corresponding v_conn
    pub(super) tcp_loaded_status: Option<citadel_io::tokio::sync::oneshot::Sender<()>>,
    // TODO: Ensure cleanup
    pub(super) hole_puncher_pipes:
        HashMap<u64, citadel_io::tokio::sync::mpsc::UnboundedSender<Bytes>>,
    pub(super) pending_hole_punch_packets: HashMap<u64, Vec<Bytes>>,
    /// Channels for delivering WebRTC signaling payloads to in-progress
    /// P2P hole-punch tasks. Keyed by peer CID.
    pub(super) webrtc_signaling_channels: HashMap<
        u64,
        citadel_io::tokio::sync::mpsc::UnboundedSender<
            crate::proto::peer::peer_crypt::WebRtcSignalingPayload,
        >,
    >,
    pub(super) cnac: Option<ClientNetworkAccount<R, R>>,
    pub(super) time_tracker: TimeTracker,
    pub(super) session_security_settings: Option<SessionSecuritySettings>,
    pub(super) queue_handle: DualLateInit<SessionQueueWorkerHandle<R>>,
    pub(super) group_channels: HashMap<MessageGroupKey, UnboundedSender<GroupBroadcastPayload>>,
    /// Per-group zero-trust TreeKEM CGKA state (the ratchet tree + epoch keys). The relay holds none
    /// of this; only group members hold an entry. Keyed identically to [`Self::group_channels`].
    pub(super) group_cgka: HashMap<MessageGroupKey, crate::proto::peer::group_cgka::GroupCgkaState>,
    pub(super) transfer_stats: TransferStats,
    pub(super) udp_mode: UdpMode,
    triggered_rekeys: Arc<Mutex<HashMap<ReKeyIndex, Ticket>>>,
    session_passwords: HashMap<u64, PreSharedKey>,
    is_server: bool,
}

/// This helps consolidate unique keys between vconns sending data to this node
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct GroupKey {
    target_cid: u64,
    group_id: u64,
    object_id: ObjectId,
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct ReKeyIndex {
    target_cid: u64,
    ticket: Ticket,
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct FileKey {
    // wave payload get the object id inscribed
    pub object_id: ObjectId,
}

#[derive(Copy, Clone, Debug)]
pub struct OutgoingPeerConnectionAttempt {
    pub ticket: Ticket,
    pub session_security_settings: SessionSecuritySettings,
}

/// when the GROUP_HEADER comes inbound with virtual file metadata, this should be created alongside
/// an async task fired-up on the threadpool
#[allow(dead_code)]
pub(crate) struct InboundFileTransfer {
    pub object_id: ObjectId,
    pub total_groups: usize,
    pub groups_rendered: usize,
    pub last_group_window_len: usize,
    pub last_group_finish_time: i64,
    pub ticket: Ticket,
    pub virtual_target: VirtualTargetType,
    pub metadata: VirtualObjectMetadata,
    pub stream_to_hd: UnboundedSender<Vec<u8>>,
    pub reception_complete_tx: citadel_io::tokio::sync::oneshot::Sender<HdpHeader>,
    pub local_encryption_level: Option<SecurityLevel>,
}

#[allow(dead_code)]
pub(crate) struct OutboundFileTransfer {
    pub metadata: VirtualObjectMetadata,
    pub ticket: Ticket,
    // for alerting the group sender to begin sending the next group
    pub next_gs_alerter: UnboundedSender<()>,
    // for alerting the async task to begin creating GroupSenders
    pub start: Option<citadel_io::tokio::sync::oneshot::Sender<bool>>,
    // This sends a shutdown signal to the async cryptscambler
    pub stop_tx: Option<citadel_io::tokio::sync::oneshot::Sender<()>>,
}

impl GroupKey {
    pub fn new(target_cid: u64, group_id: u64, object_id: ObjectId) -> Self {
        Self {
            target_cid,
            group_id,
            object_id,
        }
    }
}

impl FileKey {
    pub fn new(object_id: ObjectId) -> Self {
        Self { object_id }
    }
}

/// Signal for P2P disconnect, used for bidirectional disconnect propagation.
/// Includes ticket so disconnect initiator knows when operation completed.
#[derive(Debug, Clone)]
pub struct P2PDisconnectSignal {
    pub peer_cid: u64,
    pub reason: P2PDisconnectReason,
    /// Preserved for disconnect initiator to know when operation completed.
    /// Some when ExplicitDisconnect, None for automatic disconnects.
    pub ticket: Option<Ticket>,
    /// Token identifying the specific P2P connection instance.
    /// Used to reject stale disconnect signals from previous connections.
    pub disconnect_token: Option<DisconnectToken>,
}

/// Reason for P2P disconnect
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // StreamEnded and ExplicitDisconnect will be used for granular disconnect handling
pub enum P2PDisconnectReason {
    /// I/O stream died (network failure)
    StreamEnded,
    /// User called disconnect explicitly
    ExplicitDisconnect,
    /// C2S session is ending (hard disconnect)
    SessionShutdown,
}

/// For keeping track of connections
pub struct VirtualConnection<R: Ratchet> {
    /// For determining the type of connection
    pub connection_type: VirtualConnectionType,
    pub last_delivered_message_timestamp: DualRwLock<Option<Instant>>,
    pub is_active: Arc<AtomicBool>,
    // this is Some for server, None for endpoints
    pub sender: Option<(Option<OutboundUdpSender>, OutboundPrimaryStreamSender)>,
    // this is None for server, Some for endpoints
    pub endpoint_container: Option<EndpointChannelContainer<R>>,
    /// The NAT type of the adjacent peer (if known)
    pub adjacent_nat_type: Option<NatType>,
    /// Unique ID for this P2P connection instance (exchanged during KEX).
    /// Used to build `DisconnectToken` for stale-signal rejection.
    /// `Ticket(0)` for C2S connections.
    pub p2p_connection_id: Ticket,
}

impl<R: Ratchet> VirtualConnection<R> {
    /// If No version is supplied, uses the latest committed version
    pub fn get_endpoint_ratchet(&self, version: Option<u32>) -> Option<R> {
        let endpoint_container = self.endpoint_container.as_ref()?;
        endpoint_container.ratchet_manager.get_ratchet(version)
    }
}

pub struct EndpointChannelContainer<R: Ratchet> {
    pub(crate) direct_p2p_remote: Option<DirectP2PRemote>,
    pub(crate) ratchet_manager: ProtocolRatchetManager<R>,
    pub(crate) channel_signal: Option<NodeResult<R>>,
    to_ordered_local_channel:
        OrderedChannel<RatchetMessage<MessengerLayerOrderedMessage<UserMessage>>>,
    // for UDP
    pub(crate) to_unordered_local_channel: Option<UnorderedChannelContainer>,
    pub(crate) file_transfer_compatible: bool,
    /// Oneshot sender for P2P disconnect notification - uses `.take()` for exactly-once semantics.
    /// Sends P2PDisconnectSignal which includes the ticket for disconnect initiator.
    pub(crate) p2p_disconnect_notifier:
        Option<citadel_io::tokio::sync::oneshot::Sender<P2PDisconnectSignal>>,
}

pub(crate) struct UnorderedChannelContainer {
    to_channel: UnboundedSender<SecBuffer>,
    stopper_tx: citadel_io::tokio::sync::oneshot::Sender<()>,
}

impl<R: Ratchet> EndpointChannelContainer<R> {
    pub fn get_direct_p2p_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        Some(&self.direct_p2p_remote.as_ref()?.p2p_primary_stream)
    }

    /// Takes the P2P disconnect notifier using Option::take() for exactly-once semantics.
    /// If None, the notifier was already taken (disconnect signal already sent).
    pub fn take_p2p_disconnect_notifier(
        &mut self,
    ) -> Option<citadel_io::tokio::sync::oneshot::Sender<P2PDisconnectSignal>> {
        self.p2p_disconnect_notifier.take()
    }
}

impl<R: Ratchet> Drop for VirtualConnection<R> {
    fn drop(&mut self) {
        self.is_active.store(false, Ordering::SeqCst);
        if let Some(endpoint_container) = self.endpoint_container.as_mut() {
            let _ = endpoint_container.ratchet_manager.shutdown();
            // Trigger P2P disconnect notification if not already triggered (exactly-once via .take())
            if let Some(notifier) = endpoint_container.take_p2p_disconnect_notifier() {
                let peer_cid = self.connection_type.get_target_cid();
                let session_cid = self.connection_type.get_session_cid();
                log::trace!(target: "citadel", "VirtualConnection drop: sending P2P disconnect notification (SessionShutdown) for peer {peer_cid}");
                let disconnect_token = Some(DisconnectToken {
                    cid: session_cid,
                    connection_id: self.p2p_connection_id,
                });
                let signal = P2PDisconnectSignal {
                    peer_cid,
                    reason: P2PDisconnectReason::SessionShutdown,
                    ticket: None, // No ticket for automatic disconnects (Drop)
                    disconnect_token,
                };
                let _ = notifier.send(signal);
            } else {
                log::trace!(target: "citadel", "VirtualConnection drop: P2P disconnect notifier already taken");
            }
        }
    }
}

// VirtualConnectionType and VirtualTargetType are re-exported from citadel_types::proto

#[derive(Default)]
pub(super) struct NetworkStats {
    pub(super) last_keep_alive: Option<i64>,
    pub(super) ping_ns: Option<i64>,
    pub(super) jitter_ns: Option<i64>,
    pub(super) rtt_ns: Option<i64>,
}

pub(crate) struct OutboundTransmitterContainer<R: Ratchet> {
    pub(crate) burst_transmitter: ObjectTransmitter<R>,
    // in the case of file transfers, it is desirable to wake-up the async task
    // that enqueues the next group
    object_notifier: Option<UnboundedSender<()>>,
    waves_in_current_window: usize,
    group_plaintext_length: usize,
    transmission_start_time: Instant,
    parent_object_total_groups: usize,
    relative_group_id: u32,
    #[allow(dead_code)]
    ticket: Ticket,
    pub has_begun: bool,
}

impl<R: Ratchet> OutboundTransmitterContainer<R> {
    pub fn new(
        object_notifier: Option<UnboundedSender<()>>,
        burst_transmitter: ObjectTransmitter<R>,
        group_plaintext_length: usize,
        parent_object_total_groups: usize,
        relative_group_id: u32,
        ticket: Ticket,
    ) -> Self {
        let transmission_start_time = Instant::now();
        let has_begun = false;

        Self {
            has_begun,
            relative_group_id,
            ticket,
            parent_object_total_groups,
            transmission_start_time,
            group_plaintext_length,
            object_notifier,
            burst_transmitter,
            waves_in_current_window: 0,
        }
    }
}

#[allow(dead_code)]
pub(crate) struct GroupReceiverContainer {
    pub(crate) receiver: GroupReceiver,
    pub(crate) has_begun: bool,
    virtual_target: VirtualTargetType,
    ticket: Ticket,
    // Waves in this window are accepted
    current_window: RangeInclusive<u32>,
    security_level: SecurityLevel,
    // When the system needs to send WAVE_DO_RETRANSMISSION, this gets cut in half.
    // When the system needs to send a WAVE_ACK, this gets incremented by 1
    next_window_size: usize,
    last_window_size: usize,
    max_window_size: usize,
    window_drift: isize,
    waves_in_window_finished: usize,
    pub object_id: ObjectId,
}

impl GroupReceiverContainer {
    pub fn new(
        object_id: ObjectId,
        receiver: GroupReceiver,
        virtual_target: VirtualTargetType,
        security_level: SecurityLevel,
        ticket: Ticket,
    ) -> Self {
        Self {
            has_begun: false,
            object_id,
            security_level,
            virtual_target,
            receiver,
            ticket,
            current_window: 0..=0,
            waves_in_window_finished: 0,
            last_window_size: 0,
            window_drift: 0,
            next_window_size: 1,
            max_window_size: 0,
        }
    }
}

impl<R: Ratchet> StateContainerInner<R> {
    /// Creates a new container
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        kernel_tx: UnboundedSender<NodeResult<R>>,
        hdp_server_remote: NodeRemote<R>,
        keep_alive_timeout_ns: i64,
        state: DualCell<SessionState>,
        cnac: Option<ClientNetworkAccount<R, R>>,
        time_tracker: TimeTracker,
        session_security_settings: Option<SessionSecuritySettings>,
        is_server: bool,
        transfer_stats: TransferStats,
        udp_mode: UdpMode,
    ) -> StateContainer<R> {
        let inner = Self {
            outgoing_peer_connect_attempts: Default::default(),
            file_transfer_handles: DashMap::new(),
            group_channels: Default::default(),
            group_cgka: Default::default(),
            udp_mode,
            transfer_stats,
            queue_handle: Default::default(),
            is_server,
            session_security_settings,
            time_tracker,
            cnac,
            hole_puncher_pipes: HashMap::new(),
            pending_hole_punch_packets: HashMap::new(),
            webrtc_signaling_channels: HashMap::new(),
            tcp_loaded_status: None,
            state,
            keep_alive_timeout_ns,
            node_remote: hdp_server_remote,
            meta_expiry_state: Default::default(),
            pre_connect_state: Default::default(),
            udp_primary_outbound_tx: None,
            deregister_state: Default::default(),
            active_virtual_connections: Default::default(),
            stale_p2p_ratchets: Default::default(),
            network_stats: Default::default(),
            kernel_tx,
            register_state: packet_flags::cmd::aux::do_register::STAGE0.into(),
            connect_state: packet_flags::cmd::aux::do_connect::STAGE0.into(),
            inbound_groups: DashMap::new(),
            outbound_transmitters: DashMap::new(),
            peer_kem_states: HashMap::new(),
            inbound_files: DashMap::new(),
            outbound_files: HashMap::new(),
            session_passwords: HashMap::new(),
            triggered_rekeys: Arc::new(Mutex::new(HashMap::new())),
        };
        inner.into()
    }

    // Note: c2s connection passwords are also stored as "session_password" in the [`CitadelSession`]
    pub fn store_session_password(&mut self, peer_cid: u64, session_password: PreSharedKey) {
        self.session_passwords.insert(peer_cid, session_password);
    }

    pub fn get_session_password(&self, peer_cid: u64) -> Option<&PreSharedKey> {
        self.session_passwords.get(&peer_cid)
    }

    // TODO: use this in period cleanup tasks
    #[allow(dead_code)]
    pub fn remove_session_password(&mut self, peer_cid: u64) {
        self.session_passwords.remove(&peer_cid);
    }
}
