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

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::RangeInclusive;
use std::sync::Arc;

use crate::proto::packet_processor::primary_group_packet::get_resp_target_cid_from_header;
use serde::{Deserialize, Serialize};

use crate::proto::outbound_sender::{unbounded, UnboundedSender};
use zerocopy::Ref;

use citadel_crypt::scramble::crypt_splitter::{
    GroupReceiver, GroupReceiverConfig, GroupReceiverStatus,
};
use citadel_user::client_account::ClientNetworkAccount;
use netbeam::time_tracker::TimeTracker;

use crate::constants::{
    GROUP_TIMEOUT_MS, INDIVIDUAL_WAVE_TIMEOUT_MS, KEEP_ALIVE_INTERVAL_MS,
    MAX_OUTGOING_UNPROCESSED_REQUESTS,
};
use crate::error::NetworkError;
use crate::functional::IfEqConditional;
use crate::prelude::{InternalServerError, PreSharedKey, ReKeyResult, ReKeyReturnType};
use crate::proto::misc::dual_cell::DualCell;
use crate::proto::misc::dual_late_init::DualLateInit;
use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::ordered_channel::OrderedChannel;
use crate::proto::node_result::{NodeResult, ObjectTransferHandle};
use crate::proto::outbound_sender::{OutboundPrimaryStreamSender, OutboundUdpSender};
use crate::proto::packet::packet_flags;
use crate::proto::packet::HdpHeader;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_crafter::ObjectTransmitter;
use crate::proto::packet_processor::includes::{CitadelSession, Instant};
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::channel::{PeerChannel, UdpChannel};
use crate::proto::peer::group_channel::{GroupBroadcastPayload, GroupChannel};
use crate::proto::peer::p2p_conn_handler::DirectP2PRemote;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::{SessionRequest, SessionState, UserMessage};
use crate::proto::session_queue_handler::SessionQueueWorkerHandle;
use crate::proto::state_subcontainers::connect_state_container::ConnectState;
use crate::proto::state_subcontainers::deregister_state_container::DeRegisterState;
use crate::proto::state_subcontainers::meta_expiry_container::MetaExpiryState;
use crate::proto::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use crate::proto::state_subcontainers::preconnect_state_container::PreConnectState;
use crate::proto::state_subcontainers::register_state_container::RegisterState;
use crate::proto::transfer_stats::TransferStats;
use crate::proto::{packet_crafter, send_with_error_logging};
use crate::{ProtocolMessenger, ProtocolRatchetManager};
use bytes::Bytes;
use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::ratchets::ratchet_manager::RatchetMessage;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio_stream::wrappers::UnboundedReceiverStream;
use citadel_io::{tokio, Mutex};
use citadel_types::crypto::SecBuffer;
use citadel_types::crypto::SecurityLevel;
use citadel_types::prelude::ObjectId;
use citadel_types::proto::{
    MessageGroupKey, ObjectTransferOrientation, ObjectTransferStatus, SessionSecuritySettings,
    TransferType, UdpMode, VirtualObjectMetadata,
};
use citadel_user::backend::utils::*;
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use std::sync::atomic::{AtomicBool, Ordering};

impl<R: Ratchet> Debug for StateContainer<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateContainer")
    }
}

define_outer_struct_wrapper!(StateContainer, StateContainerInner, <R: Ratchet>, <R>);

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
    pub(super) inbound_files: HashMap<FileKey, InboundFileTransfer>,
    pub(super) outbound_files: HashMap<FileKey, OutboundFileTransfer>,
    pub(super) file_transfer_handles: HashMap<FileKey, UnboundedSender<ObjectTransferStatus>>,
    pub(super) inbound_groups: HashMap<GroupKey, GroupReceiverContainer>,
    pub(super) outbound_transmitters: HashMap<GroupKey, OutboundTransmitterContainer<R>>,
    pub(super) peer_kem_states: HashMap<u64, PeerKemStateContainer<R>>,
    // u64 is peer id, ticket is the local original ticket (ticket may
    // transform if a simultaneous connect)
    pub(super) outgoing_peer_connect_attempts: HashMap<u64, OutgoingPeerConnectionAttempt>,
    pub(super) udp_primary_outbound_tx: Option<OutboundUdpSender>,
    pub(super) kernel_tx: UnboundedSender<NodeResult<R>>,
    pub(super) active_virtual_connections: HashMap<u64, VirtualConnection<R>>,
    pub(crate) keep_alive_timeout_ns: i64,
    pub(crate) state: DualCell<SessionState>,
    // whenever a c2s or p2p channel is loaded, this is fired to signal any UDP loaders that it is safe to store the UDP conn in the corresponding v_conn
    pub(super) tcp_loaded_status: Option<citadel_io::tokio::sync::oneshot::Sender<()>>,
    // TODO: Ensure cleanup
    pub(super) hole_puncher_pipes:
        HashMap<u64, citadel_io::tokio::sync::mpsc::UnboundedSender<Bytes>>,
    pub(super) cnac: Option<ClientNetworkAccount<R, R>>,
    pub(super) time_tracker: TimeTracker,
    pub(super) session_security_settings: Option<SessionSecuritySettings>,
    pub(super) queue_handle: DualLateInit<SessionQueueWorkerHandle<R>>,
    pub(super) group_channels: HashMap<MessageGroupKey, UnboundedSender<GroupBroadcastPayload>>,
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
    to_ordered_local_channel: OrderedChannel<RatchetMessage<UserMessage>>,
    // for UDP
    pub(crate) to_unordered_local_channel: Option<UnorderedChannelContainer>,
    pub(crate) file_transfer_compatible: bool,
}

pub(crate) struct UnorderedChannelContainer {
    to_channel: UnboundedSender<SecBuffer>,
    stopper_tx: citadel_io::tokio::sync::oneshot::Sender<()>,
}

impl<R: Ratchet> EndpointChannelContainer<R> {
    pub fn get_direct_p2p_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        Some(&self.direct_p2p_remote.as_ref()?.p2p_primary_stream)
    }
}

impl<R: Ratchet> Drop for VirtualConnection<R> {
    fn drop(&mut self) {
        self.is_active.store(false, Ordering::SeqCst);
        if let Some(endpoint_container) = self.endpoint_container.as_mut() {
            let _ = endpoint_container.ratchet_manager.shutdown();
        }
    }
}

/// For determining the nature of a [VirtualConnection]
#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash, Serialize, Deserialize)]
pub enum VirtualConnectionType {
    LocalGroupPeer {
        session_cid: u64,
        peer_cid: u64,
    },
    ExternalGroupPeer {
        session_cid: u64,
        interserver_cid: u64,
        peer_cid: u64,
    },
    LocalGroupServer {
        session_cid: u64,
    },
    ExternalGroupServer {
        session_cid: u64,
        interserver_cid: u64,
    },
}

/// For readability
pub type VirtualTargetType = VirtualConnectionType;
impl VirtualConnectionType {
    pub fn serialize(&self) -> Vec<u8> {
        Self::serialize_to_vector(self).unwrap()
    }

    pub fn deserialize_from<'a, T: AsRef<[u8]> + 'a>(this: T) -> Option<Self> {
        Self::deserialize_from_vector(this.as_ref()).ok()
    }

    /// Gets the target cid, agnostic to type
    pub fn get_target_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid: _cid } => {
                // by rule of the network, the target CID is zero if a C2S connection
                C2S_IDENTITY_CID
            }

            VirtualConnectionType::LocalGroupPeer {
                session_cid: _session_cid,
                peer_cid: target_cid,
            } => *target_cid,

            VirtualConnectionType::ExternalGroupPeer {
                session_cid: _session_cid,
                interserver_cid: _icid,
                peer_cid: target_cid,
            } => *target_cid,

            VirtualConnectionType::ExternalGroupServer {
                session_cid: _session_cid,
                interserver_cid: icid,
            } => *icid,
        }
    }

    /// Gets the target cid, agnostic to type
    pub fn get_session_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid: cid } => *cid,

            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _target_cid,
            } => *session_cid,

            VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: _icid,
                peer_cid: _target_cid,
            } => *session_cid,

            VirtualConnectionType::ExternalGroupServer {
                session_cid,
                interserver_cid: _icid,
            } => *session_cid,
        }
    }

    pub fn is_local_group(&self) -> bool {
        matches!(
            self,
            VirtualConnectionType::LocalGroupPeer { .. }
                | VirtualConnectionType::LocalGroupServer { .. }
        )
    }

    pub fn is_external_group(&self) -> bool {
        !self.is_local_group()
    }

    pub fn try_as_peer_connection(&self) -> Option<PeerConnectionType> {
        match self {
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid,
            } => Some(PeerConnectionType::LocalGroupPeer {
                session_cid: *session_cid,
                peer_cid: *peer_cid,
            }),

            VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: icid,
                peer_cid,
            } => Some(PeerConnectionType::ExternalGroupPeer {
                session_cid: *session_cid,
                interserver_cid: *icid,
                peer_cid: *peer_cid,
            }),

            _ => None,
        }
    }

    pub fn set_target_cid(&mut self, target_cid: u64) {
        match self {
            VirtualConnectionType::LocalGroupPeer {
                session_cid: _,
                peer_cid,
            }
            | VirtualConnectionType::ExternalGroupPeer {
                session_cid: _,
                interserver_cid: _,
                peer_cid,
            } => *peer_cid = target_cid,

            _ => {}
        }
    }

    pub fn set_session_cid(&mut self, cid: u64) {
        match self {
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _,
            }
            | VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: _,
                peer_cid: _,
            } => *session_cid = cid,

            _ => {}
        }
    }
}

impl Display for VirtualConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualConnectionType::LocalGroupServer { session_cid: cid } => {
                write!(f, "Local Group Peer to Local Group Server ({cid})")
            }

            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: target_cid,
            } => {
                write!(
                    f,
                    "Local Group Peer to Local Group Peer ({session_cid} -> {target_cid})"
                )
            }

            VirtualConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => {
                write!(
                    f,
                    "Local Group Peer to External Group Peer ({session_cid} -> {icid} -> {target_cid})"
                )
            }

            VirtualConnectionType::ExternalGroupServer {
                session_cid,
                interserver_cid: icid,
            } => {
                write!(
                    f,
                    "Local Group Peer to External Group Server ({session_cid} -> {icid})"
                )
            }
        }
    }
}

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
            file_transfer_handles: HashMap::new(),
            group_channels: Default::default(),
            udp_mode,
            transfer_stats,
            queue_handle: Default::default(),
            is_server,
            session_security_settings,
            time_tracker,
            cnac,
            hole_puncher_pipes: HashMap::new(),
            tcp_loaded_status: None,
            state,
            keep_alive_timeout_ns,
            node_remote: hdp_server_remote,
            meta_expiry_state: Default::default(),
            pre_connect_state: Default::default(),
            udp_primary_outbound_tx: None,
            deregister_state: Default::default(),
            active_virtual_connections: Default::default(),
            network_stats: Default::default(),
            kernel_tx,
            register_state: packet_flags::cmd::aux::do_register::STAGE0.into(),
            connect_state: packet_flags::cmd::aux::do_connect::STAGE0.into(),
            inbound_groups: HashMap::new(),
            outbound_transmitters: HashMap::new(),
            peer_kem_states: HashMap::new(),
            inbound_files: HashMap::new(),
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

    /// Attempts to find the direct p2p stream. If not found, will use the default
    /// to_server stream. Note: the underlying crypto is still the same
    pub fn get_preferred_stream(&self, peer_cid: u64) -> &OutboundPrimaryStreamSender {
        fn get_inner<R: Ratchet>(
            this: &StateContainerInner<R>,
            peer_cid: u64,
        ) -> Option<&OutboundPrimaryStreamSender> {
            Some(
                &this
                    .active_virtual_connections
                    .get(&peer_cid)?
                    .endpoint_container
                    .as_ref()?
                    .direct_p2p_remote
                    .as_ref()?
                    .p2p_primary_stream,
            )
        }

        // On fallback
        get_inner(self, peer_cid).unwrap_or_else(|| {
            get_inner(self, C2S_IDENTITY_CID)
                .expect("The C2S virtual connection should always exist")
        })
    }

    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_ordered_channel(
        &mut self,
        target_cid: u64,
        group_id: u64,
        data: RatchetMessage<UserMessage>,
    ) -> Result<(), NetworkError> {
        let endpoint_container = self.get_endpoint_container_mut(target_cid)?;
        endpoint_container
            .to_ordered_local_channel
            .on_packet_received(group_id, data)
    }

    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_unordered_channel(&self, target_cid: u64, data: SecBuffer) -> bool {
        if let Some(vconn) = self.active_virtual_connections.get(&target_cid) {
            if let Some(channel) = vconn.endpoint_container.as_ref() {
                if let Some(unordered_channel) = channel.to_unordered_local_channel.as_ref() {
                    return unordered_channel.to_channel.unbounded_send(data).is_ok();
                }
            }
        }

        log::warn!(target: "citadel", "Attempted to forward data to unordered channel, but, one or more containers were not present");

        false
    }

    // Requirements: A TCP/reliable ordered conn channel must already be setup in order for the connection to continue
    pub fn insert_udp_channel(
        &mut self,
        target_cid: u64,
        v_conn: VirtualConnectionType,
        ticket: Ticket,
        to_udp_stream: OutboundUdpSender,
        stopper_tx: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> Option<UdpChannel<R>> {
        if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
            if let Some((sender, _)) = p2p_container.sender.as_mut() {
                *sender = Some(to_udp_stream.clone());
                if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                    let (to_channel, rx) = unbounded();
                    let udp_channel = UdpChannel::new(
                        to_udp_stream,
                        rx,
                        target_cid,
                        v_conn,
                        ticket,
                        p2p_container.is_active.clone(),
                        self.node_remote.clone(),
                    );
                    p2p_endpoint_container.to_unordered_local_channel =
                        Some(UnorderedChannelContainer {
                            to_channel,
                            stopper_tx,
                        });
                    // data can now be forwarded
                    Some(udp_channel)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn remove_udp_channel(&mut self, target_cid: u64) {
        if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
            if let Some((sender, _)) = p2p_container.sender.as_mut() {
                if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                    if let Some(channel) = p2p_endpoint_container.to_unordered_local_channel.take()
                    {
                        let _ = channel.stopper_tx.send(());
                    }
                    *sender = None;
                }
            }
        }
    }

    /// The inner P2P handles will get dropped, causing the connections to end
    pub fn end_connections(&mut self) {
        self.active_virtual_connections.clear();
    }

    /// In order for the upgrade to work, the peer_addr must be reflective of the peer_addr present when
    /// receiving the packet. As such, the direct p2p-stream MUST have sent the packet
    pub(crate) fn insert_direct_p2p_connection(
        &mut self,
        provisional: DirectP2PRemote,
        peer_cid: u64,
    ) -> Result<(), NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) {
            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                log::trace!(target: "citadel", "UPGRADING {} conn type", provisional.from_listener.if_eq(true, "listener").if_false("client"));
                // By setting the below value, all outbound packets will use
                // this direct conn over the proxied TURN-like connection
                vconn.sender = Some((None, provisional.p2p_primary_stream.clone())); // setting this will allow the UDP stream to be upgraded too

                if endpoint_container
                    .direct_p2p_remote
                    .replace(provisional)
                    .is_some()
                {
                    log::warn!(target: "citadel", "Dropped previous p2p remote during upgrade process");
                }

                return Ok(());
            }
        }

        Err(NetworkError::InternalError("Unable to upgrade"))
    }

    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn create_virtual_connection(
        &mut self,
        default_security_settings: SessionSecuritySettings,
        channel_ticket: Ticket,
        target_cid: u64,
        virtual_connection_type: VirtualConnectionType,
        endpoint_crypto: PeerSessionCrypto<R>,
        sess: &CitadelSession<R>,
        file_transfer_compatible: bool,
    ) -> PeerChannel<R> {
        let (tx_ratchet_manager_to_outbound, mut rx_from_ratchet_manager_to_outbound) =
            unbounded::<RatchetMessage<UserMessage>>();
        let (tx_to_outbound, rx_for_outbound) =
            crate::proto::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);
        let (rekey_tx, mut rekey_rx) = tokio::sync::mpsc::unbounded_channel::<R>();
        // Take messages from the ratchet manager , forward it to the dedicated outbound sender
        let task_outbound = async move {
            while let Some(ratchet_layer_message) = rx_from_ratchet_manager_to_outbound.recv().await
            {
                if let Err(err) = tx_to_outbound
                    .send(SessionRequest::SendMessage(ratchet_layer_message))
                    .await
                {
                    citadel_logging::error!(target: "citadel", "Failed to send secure protocol packet for {virtual_connection_type}: {err:?}");
                    break;
                }
            }

            citadel_logging::warn!(target: "citadel", "Outbound ratchet task for {virtual_connection_type} ended");
        };

        let kernel_tx = self.kernel_tx.clone();
        let session_cid = virtual_connection_type.get_session_cid();
        let triggered_rekeys = self.triggered_rekeys.clone();
        // On each rekey finished, take the received ratchet, R, and send it through the kernel_tx
        let task_rekey_finished_listener = async move {
            while let Some(rekey_finished) = rekey_rx.recv().await {
                let mut lock = triggered_rekeys.lock();
                if let Some(entry) = lock.iter().find(|r| r.0.target_cid == target_cid) {
                    let ticket = *entry.1;
                    let to_remove = *entry.0;
                    lock.remove(&to_remove);
                    let result = NodeResult::ReKeyResult(ReKeyResult {
                        ticket,
                        status: ReKeyReturnType::Success {
                            version: rekey_finished.version(),
                        },
                        session_cid,
                    });
                    if let Err(err) = kernel_tx.unbounded_send(result) {
                        citadel_logging::error!(target: "citadel", "Failed to send rekey result for {virtual_connection_type}: {err:?}");
                        break;
                    }
                }
            }
        };

        let password_cid_index = match virtual_connection_type {
            VirtualConnectionType::LocalGroupPeer { .. } => target_cid, // TODO make sure this is right
            VirtualConnectionType::LocalGroupServer { .. } => C2S_IDENTITY_CID,
            _ => {
                panic!("HyperWAN functionality not yet enabled");
            }
        };

        let psks = self
            .get_session_password(password_cid_index)
            .cloned()
            .expect("The PSK was not found!");

        let (tx_to_ratchet_manager_inbound, rx_for_ratchet_manager) = unbounded();

        let ratchet_manager = ProtocolRatchetManager::new(
            Box::new(tx_ratchet_manager_to_outbound),
            Box::new(UnboundedReceiverStream::new(rx_for_ratchet_manager)),
            endpoint_crypto,
            psks.as_ref(),
        );

        let is_active = Arc::new(AtomicBool::new(true));

        let protocol_messenger = ProtocolMessenger::new(
            ratchet_manager.clone(),
            default_security_settings.secrecy_mode,
            Some(rekey_tx),
            is_active.clone(),
        );

        // This will automatically take inbound messages, order them, and forward them to the ratchet manager for processing
        // where the ratchet manager will automatically forward the processed messages to the protocol_messenger above
        let to_channel = OrderedChannel::new(tx_to_ratchet_manager_inbound);

        // We don't need an inbound task since:
        // [*] Inbound messages get passed like usual to the ordered channel (1)
        // [*] The ordered channel passes the message to the ratchet manager (2)
        // [*] the ratchet manager passes to the protocol messenger (3)
        // [*] the protocol messenger gets polled for messages (4)

        let is_server = sess.is_server;

        let combined_task = async move {
            tokio::select! {
                _ = task_rekey_finished_listener => {}
                _ = task_outbound => {}
            };

            citadel_logging::warn!(target: "citadel", "Combined task for {virtual_connection_type} ended (is_server: {is_server})");
        };

        spawn!(combined_task);

        let peer_channel = PeerChannel::new(
            self.node_remote.clone(),
            target_cid,
            virtual_connection_type,
            channel_ticket,
            default_security_settings.security_level,
            is_active.clone(),
            protocol_messenger,
        );

        CitadelSession::spawn_message_sender_function(
            sess.clone(),
            virtual_connection_type,
            rx_for_outbound,
        );

        let endpoint_container = Some(EndpointChannelContainer {
            direct_p2p_remote: None,
            ratchet_manager,
            channel_signal: None,
            to_ordered_local_channel: to_channel,
            to_unordered_local_channel: None,
            file_transfer_compatible,
        });

        let vconn = VirtualConnection {
            last_delivered_message_timestamp: DualRwLock::from(None),
            connection_type: virtual_connection_type,
            is_active,
            sender: None,
            endpoint_container,
        };

        self.active_virtual_connections.insert(target_cid, vconn);

        peer_channel
    }

    /// This should be ran at the beginning of a session to provide ordered delivery to clients
    #[allow(unused_results)]
    pub fn init_new_c2s_virtual_connection(
        &mut self,
        cnac: &ClientNetworkAccount<R, R>,
        channel_ticket: Ticket,
        session_cid: u64,
        session: &CitadelSession<R>,
    ) -> PeerChannel<R> {
        let security_settings = self
            .session_security_settings
            .expect("Should be set at beginning of session or on first SYN packet");
        // Reuse the latest one. During SYN/SYN_ACK process, toolsets should be reset inside the endpoint_crypto
        let endpoint_crypto = cnac.get_session_crypto().clone();

        let channel = self.create_virtual_connection(
            security_settings,
            channel_ticket,
            C2S_IDENTITY_CID,
            VirtualConnectionType::LocalGroupServer { session_cid },
            endpoint_crypto,
            session,
            true,
        );

        let p2p_remote = DirectP2PRemote {
            stopper: None,
            p2p_primary_stream: session
                .to_primary_stream
                .clone()
                .expect("Should be set at beginning of session or on first SYN packet"),
            from_listener: false,
        };

        self.insert_direct_p2p_connection(p2p_remote, C2S_IDENTITY_CID)
            .expect("C2S insertion should not fail");

        if let Some(udp_alerter) = self.tcp_loaded_status.take() {
            let _ = udp_alerter.send(());
        }

        channel
    }

    pub fn setup_tcp_alert_if_udp_c2s(&mut self) -> citadel_io::tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        self.tcp_loaded_status = Some(tx);
        rx
    }

    /// Note: the `endpoint_crypto` container needs to be Some in order for transfer to occur between peers w/o encryption/decryption at the center point
    /// GROUP packets and PEER_CMD::CHANNEL packets bypass the central node's encryption/decryption phase
    pub fn insert_new_virtual_connection_as_server(
        &mut self,
        target_cid: u64,
        connection_type: VirtualConnectionType,
        target_udp_sender: Option<OutboundUdpSender>,
        target_tcp_sender: OutboundPrimaryStreamSender,
    ) {
        let val = VirtualConnection {
            last_delivered_message_timestamp: DualRwLock::from(None),
            endpoint_container: None,
            sender: Some((target_udp_sender, target_tcp_sender)),
            connection_type,
            is_active: Arc::new(AtomicBool::new(true)),
        };
        if self
            .active_virtual_connections
            .insert(target_cid, val)
            .is_some()
        {
            log::warn!(target: "citadel", "Inserted a virtual connection. but overwrote one in the process. Report to developers");
        }

        log::trace!(target: "citadel", "Vconn {} -> {} established", connection_type.get_session_cid(), target_cid);
    }

    pub fn get_virtual_connection_crypto(&self, peer_cid: u64) -> Option<&PeerSessionCrypto<R>> {
        Some(
            self.active_virtual_connections
                .get(&peer_cid)?
                .endpoint_container
                .as_ref()?
                .ratchet_manager
                .session_crypto_state(),
        )
    }

    pub fn get_virtual_connection_mut(
        &mut self,
        target_cid: u64,
    ) -> Result<&mut VirtualConnection<R>, NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&target_cid) {
            Ok(vconn)
        } else {
            Err(NetworkError::msg(format!(
                "Unable to find virtual connection to peer {target_cid}"
            )))
        }
    }

    pub fn get_virtual_connection(
        &self,
        target_cid: u64,
    ) -> Result<&VirtualConnection<R>, NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get(&target_cid) {
            Ok(vconn)
        } else {
            Err(NetworkError::msg(format!(
                "Unable to find virtual connection to peer {target_cid}"
            )))
        }
    }

    pub fn get_endpoint_container_mut(
        &mut self,
        target_cid: u64,
    ) -> Result<&mut EndpointChannelContainer<R>, NetworkError> {
        let v_conn = self.get_virtual_connection_mut(target_cid)?;
        if let Some(endpoint_container) = v_conn.endpoint_container.as_mut() {
            Ok(endpoint_container)
        } else {
            Err(NetworkError::msg(format!(
                "Unable to access endpoint container to peer {target_cid}"
            )))
        }
    }

    pub fn get_endpoint_container(
        &self,
        target_cid: u64,
    ) -> Result<&EndpointChannelContainer<R>, NetworkError> {
        let v_conn = self.get_virtual_connection(target_cid)?;
        if let Some(endpoint_container) = v_conn.endpoint_container.as_ref() {
            Ok(endpoint_container)
        } else {
            Err(NetworkError::msg(format!(
                "Unable to access endpoint container to peer {target_cid}"
            )))
        }
    }

    /// When a keep alive is received, this function gets called. Prior to getting called,
    /// validity must be ensured!
    #[allow(unused_results)]
    pub fn on_keep_alive_received(
        &mut self,
        inbound_packet_timestamp_ns: i64,
        mut current_timestamp_ns: i64,
    ) -> bool {
        if self.keep_alive_timeout_ns == 0 {
            return true;
        }

        let mut ping_ns = current_timestamp_ns - inbound_packet_timestamp_ns;
        if ping_ns < 0 {
            // For localhost testing, this sometimes occurs. The clocks might be out of sync a bit.
            current_timestamp_ns -= ping_ns;
            // Negate it, for now. Usually, this wont happen on networks
            ping_ns = -ping_ns;
        }
        // The jitter is the differential of pings. Ping current - ping present
        let jitter_ns = ping_ns - self.network_stats.ping_ns.unwrap_or(0);
        self.network_stats.jitter_ns.replace(jitter_ns);
        self.network_stats.ping_ns.replace(ping_ns);

        //log::trace!(target: "citadel", "KEEP ALIVE subsystem statistics: Ping: {}ms | RTT: {}ms | Jitter: {}ms", (ping_ns as f64/1_000_000f64) as f64, (self.network_stats.rtt_ns.clone().unwrap_or(0) as f64/1_000_000f64) as f64, (jitter_ns as f64/1000000f64) as f64);
        if let Some(last_ka) = self.network_stats.last_keep_alive.take() {
            if ping_ns > self.keep_alive_timeout_ns {
                // possible timeout. There COULD be packets being spammed, preventing KAs from getting through. Thus, check the meta expiry container
                !self.meta_expiry_state.expired()
            } else {
                self.network_stats
                    .last_keep_alive
                    .replace(current_timestamp_ns);
                // We subtract two keep alive intervals, since it pauses that long on each end. We multiply by 1 million to convert ms to ns
                const PROCESS_TIME_NS: i64 = 2 * KEEP_ALIVE_INTERVAL_MS as i64 * 1_000_000;
                self.network_stats
                    .rtt_ns
                    .replace(current_timestamp_ns - last_ka - PROCESS_TIME_NS);
                true
            }
        } else {
            // This is the first KA in the series
            self.network_stats
                .last_keep_alive
                .replace(current_timestamp_ns);
            true
        }
    }

    /// Like the other functions in this file, ensure that verification is called before running this
    /// Returns the initial wave window
    #[allow(unused_results)]
    pub fn on_group_header_received(
        &mut self,
        header: &Ref<&[u8], HdpHeader>,
        group_receiver_config: GroupReceiverConfig,
        virtual_target: VirtualTargetType,
    ) -> Option<RangeInclusive<u32>> {
        log::trace!(target: "citadel", "GRC config: {:?}", group_receiver_config);
        let object_id = group_receiver_config.object_id;
        let group_id = header.group.get();
        let ticket = header.context_info.get();
        // below, the target_cid in the key is where the packet came from. If it is a client, or a hyperlan conn, the implicated cid stays the same
        let inbound_group_key = GroupKey::new(header.session_cid.get(), group_id, object_id);
        if let std::collections::hash_map::Entry::Vacant(e) =
            self.inbound_groups.entry(inbound_group_key)
        {
            let receiver = GroupReceiver::new(
                group_receiver_config,
                INDIVIDUAL_WAVE_TIMEOUT_MS,
                GROUP_TIMEOUT_MS,
            );
            let security_level = SecurityLevel::for_value(header.security_level as usize)?;
            let mut receiver_container = GroupReceiverContainer::new(
                object_id,
                receiver,
                virtual_target,
                security_level,
                ticket.into(),
            );
            // check to see if we need to copy the last wave window
            let last_window_size = if object_id != ObjectId::zero() {
                // copy previous window
                let file_key = FileKey::new(object_id);
                if let Some(inbound_file_transfer) = self.inbound_files.get(&file_key) {
                    inbound_file_transfer.last_group_window_len
                } else {
                    log::error!(target: "citadel", "The GROUP HEADER implied the existence of a file transfer, but the key {:?} does not map to anything", &file_key);
                    return None;
                }
            } else {
                0
            };

            let wave_window = if last_window_size != 0 {
                // the last_window_size may not have an oversized length. take the min
                receiver_container.last_window_size = last_window_size;
                let waves_in_group = receiver_container.receiver.get_wave_count();
                // take waves_in_group - 1 because it needs to take into account the max inclusive boundary
                let max_idx =
                    std::cmp::min(last_window_size, waves_in_group.saturating_sub(1)) as u32;
                let min_idx = 0; // this is a new group; start at zero
                receiver_container.current_window = min_idx..=max_idx;
                min_idx..=max_idx
            } else {
                // if it was zero, not part of a file. Use the one proposed by the receiver container, by default
                receiver_container.current_window.clone()
            };

            e.insert(receiver_container);
            Some(wave_window)
        } else {
            log::error!(target: "citadel", "Duplicate group HEADER detected ({})", group_id);
            None
        }
    }

    /// This creates an entry in the inbound_files hashmap
    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn on_file_header_received(
        &mut self,
        header: &Ref<&[u8], HdpHeader>,
        virtual_target: VirtualTargetType,
        metadata_orig: VirtualObjectMetadata,
        pers: &PersistenceHandler<R, R>,
        state_container: StateContainer<R>,
        ratchet: R,
        _target_cid: u64,
        v_target_flipped: VirtualTargetType,
        preferred_primary_stream: OutboundPrimaryStreamSender,
        local_encryption_level: Option<SecurityLevel>,
    ) -> bool {
        let target_cid = v_target_flipped.get_target_cid();
        let session_cid = v_target_flipped.get_session_cid();
        let object_id = metadata_orig.object_id;

        let key = FileKey::new(object_id);
        let ticket = header.context_info.get().into();
        let is_revfs_pull = local_encryption_level.is_some();

        log::trace!(target: "citadel", "File header {session_cid}: {key:?} | revfs_pull: {is_revfs_pull}");

        if let std::collections::hash_map::Entry::Vacant(e) = self.inbound_files.entry(key) {
            let (stream_to_hd, stream_to_hd_rx) = unbounded::<Vec<u8>>();

            let security_level_rebound: SecurityLevel = header.security_level.into();
            let timestamp = self.time_tracker.get_global_time_ns();
            let pers = pers.clone();
            let metadata = metadata_orig.clone();
            let tt = self.time_tracker;
            let (reception_complete_tx, success_receiving_rx) =
                citadel_io::tokio::sync::oneshot::channel();
            let entry = InboundFileTransfer {
                last_group_finish_time: tt.get_global_time_ns(),
                last_group_window_len: 0,
                object_id,
                total_groups: metadata_orig.group_count,
                ticket,
                groups_rendered: 0,
                virtual_target,
                metadata: metadata.clone(),
                reception_complete_tx,
                stream_to_hd,
                local_encryption_level,
            };

            let (start_recv_tx, start_recv_rx) = if !is_revfs_pull {
                let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };

            e.insert(entry);
            let (handle, tx_status) = ObjectTransferHandler::new(
                target_cid,
                session_cid,
                metadata.clone(),
                ObjectTransferOrientation::Receiver { is_revfs_pull },
                start_recv_tx,
            );
            self.file_transfer_handles
                .insert(key, UnboundedSender(tx_status.clone()));
            // finally, alert the kernel (receiver)
            if let Err(err) = self
                .kernel_tx
                .unbounded_send(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                    ticket,
                    handle,
                    session_cid,
                }))
            {
                log::error!(target: "citadel", "Failed to send the ObjectTransferHandle to the kernel: {err:?}");
            }

            let is_server = self.is_server;

            let task = async move {
                log::info!(target: "citadel", "File transfer initiated, awaiting acceptance ... | revfs_pull: {is_revfs_pull}");
                let res = if let Some(start_rx) = start_recv_rx {
                    start_rx.await
                } else {
                    Ok(true)
                };

                log::info!(target: "citadel", "File transfer initiated! | revfs_pull: {is_revfs_pull}");

                let accepted = res.as_ref().map(|r| *r).unwrap_or(false);
                // first, send a rebound signal immediately to the sender
                // to ensure the sender knows if the user accepted or not
                let file_header_ack = packet_crafter::file::craft_file_header_ack_packet(
                    &ratchet,
                    accepted,
                    object_id,
                    target_cid,
                    ticket,
                    security_level_rebound,
                    v_target_flipped,
                    timestamp,
                    metadata_orig.transfer_type.clone(),
                );

                if let Err(err) = preferred_primary_stream.unbounded_send(file_header_ack) {
                    log::error!(target: "citadel", "Unable to send file_header_ack rebound signal; aborting: {:?}", err);
                    return;
                }

                match res {
                    Ok(accepted) => {
                        if accepted {
                            // local user accepts the file transfer. Alert the adjacent end
                            // and get ready to begin streaming
                            match pers
                                .stream_object_to_backend(
                                    stream_to_hd_rx,
                                    &metadata,
                                    tx_status.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    // TODO: Consider adding a function that waits for the actual file size to be equal to the metadata plaintext length
                                    // in order to not allow the kernel logic to prematurely read the file contents while still syncing.
                                    log::info!(target: "citadel", "Successfully synced file to backend | revfs_pull: {is_revfs_pull} | is_server: {is_server}");
                                    let status = match success_receiving_rx.await {
                                        Ok(header) => {
                                            // write the header
                                            let wave_ack = packet_crafter::group::craft_wave_ack(
                                                &ratchet,
                                                object_id,
                                                get_resp_target_cid_from_header(&header),
                                                header.group.get(),
                                                header.wave_id.get(),
                                                tt.get_global_time_ns(),
                                                None,
                                                header.security_level.into(),
                                            );

                                            send_with_error_logging(
                                                &preferred_primary_stream,
                                                wave_ack,
                                            );

                                            ObjectTransferStatus::ReceptionComplete
                                        }

                                        Err(_) => ObjectTransferStatus::Fail(
                                            "An unknown error occurred while receiving file"
                                                .to_string(),
                                        ),
                                    };

                                    if let Err(err) = tx_status.send(status) {
                                        log::error!(target: "citadel", "Unable to send object transfer status to handle: {err:?}");
                                    }
                                }
                                Err(err) => {
                                    log::error!(target: "citadel", "Unable to sync file to backend: {:?}", err);
                                }
                            }
                        } else {
                            if let Err(err) = tx_status.send(ObjectTransferStatus::Fail(
                                "User did not accept file transfer".to_string(),
                            )) {
                                log::error!(target: "citadel", "Unable to send object transfer status to handle: {err:?}");
                            }
                            // user did not accept. cleanup local
                            log::warn!(target: "citadel", "User did not accept file transfer");
                            let mut state_container = inner_mut_state!(state_container);
                            let _ = state_container.inbound_files.remove(&key);
                            let _ = state_container.file_transfer_handles.remove(&key);
                        }
                    }

                    Err(err) => {
                        log::error!(target: "citadel", "Start_recv_rx failed: {:?}", err);
                        let err_packet = packet_crafter::file::craft_file_header_ack_packet(
                            &ratchet,
                            false,
                            object_id,
                            target_cid,
                            ticket,
                            security_level_rebound,
                            virtual_target,
                            timestamp,
                            metadata_orig.transfer_type.clone(),
                        );
                        let _ = preferred_primary_stream.unbounded_send(err_packet);
                    }
                }
            };

            spawn!(task);
            true
        } else {
            log::error!(target: "citadel", "Duplicate file HEADER detected");
            false
        }
    }

    pub fn on_file_header_ack_received(
        &mut self,
        success: bool,
        session_cid: u64,
        ticket: Ticket,
        object_id: ObjectId,
        v_target: VirtualTargetType,
        _transfer_type: TransferType,
    ) -> Option<()> {
        let (key, receiver_cid) = match v_target {
            VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _target_cid,
            } => {
                let receiver_cid = session_cid;
                // since the order hasn't flipped yet, get the implicated cid
                (FileKey::new(object_id), receiver_cid)
            }

            VirtualConnectionType::LocalGroupServer { session_cid } => {
                (FileKey::new(object_id), session_cid)
            }

            _ => {
                log::error!(target: "citadel", "HyperWAN functionality not yet enabled");
                return None;
            }
        };

        if success {
            // remove the outbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.get_mut(&key) {
                let metadata = file_transfer.metadata.clone();
                // start the async task pulling from the async cryptscrambler
                file_transfer.start.take()?.send(true).ok()?;
                let (handle, tx) = ObjectTransferHandler::new(
                    session_cid,
                    receiver_cid,
                    metadata,
                    ObjectTransferOrientation::Sender,
                    None,
                );
                tx.send(ObjectTransferStatus::TransferBeginning).ok()?;
                let _ = self
                    .file_transfer_handles
                    .insert(key, crate::proto::outbound_sender::UnboundedSender(tx));
                // alert the kernel that file transfer has begun
                self.kernel_tx
                    .unbounded_send(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                        ticket,
                        handle,
                        session_cid,
                    }))
                    .ok()?;
            } else {
                log::error!(target: "citadel", "Attempted to obtain OutboundFileTransfer for {:?}, but it didn't exist", key);
            }
        } else {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.remove(&key) {
                // stop the async cryptscrambler
                file_transfer.stop_tx?.send(()).ok()?;
                // stop the async task pulling from the async cryptscrambler
                file_transfer.start?.send(false).ok()?;
                let _ = self
                    .kernel_tx
                    .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                        message: "The adjacent node did not accept the file transfer request"
                            .into(),
                        ticket_opt: Some(ticket),
                        cid_opt: Some(session_cid),
                    }));
            } else {
                log::error!(target: "citadel", "Attempted to remove OutboundFileTransfer for {:?}, but it didn't exist", key);
            }
        }

        Some(())
    }

    /// This tells us that we should burst-send the packets now. Returns false if the UDP sockets disconnected
    /// `to_primary_stream`: If None, will use the Burst Transmitter
    /// `proposed_window`: In TCP only mode, this won't matter since reliability is handled by the TCP layer. As such, in TCP only mode
    /// the tcp sender dispatches ALL packets
    /// NOTE! object ID is in wave_id for header ACKS
    /// NOTE: If object id != 0, then this header ack belongs to a file transfer and must thus be transmitted via TCP
    #[allow(unused_results)]
    #[allow(clippy::too_many_arguments)]
    pub fn on_group_header_ack_received(
        &mut self,
        peer_cid: u64,
        group_id: u64,
        object_id: ObjectId,
        next_window: Option<RangeInclusive<u32>>,
        fast_msg: bool,
    ) -> bool {
        let key = GroupKey::new(peer_cid, group_id, object_id);

        if fast_msg {
            let _ = self.outbound_transmitters.remove(&key);
            // we don't proceed past here b/c there's no need to send more data
            return true;
        }

        let outbound_container = self.outbound_transmitters.get_mut(&key).unwrap();
        outbound_container.waves_in_current_window = next_window.unwrap_or(0..=0).count();
        // file-transfer, or TCP only mode since next_window is none. Use TCP
        outbound_container
            .burst_transmitter
            .transmit_tcp_file_transfer()
    }

    pub fn notify_object_transfer_handle_failure<T: Into<String>>(
        &mut self,
        header: &HdpHeader,
        error_message: T,
        object_id: ObjectId,
    ) -> Result<(), NetworkError> {
        let target_cid = header.session_cid.get();
        self.notify_object_transfer_handle_failure_with(target_cid, object_id, error_message)
    }

    pub fn notify_object_transfer_handle_failure_with<T: Into<String>>(
        &mut self,
        _target_cid: u64,
        object_id: ObjectId,
        error_message: T,
    ) -> Result<(), NetworkError> {
        // let group_key = GroupKey::new(target_cid, group_id, object_id);
        let file_key = FileKey::new(object_id);
        let file_transfer_handle =
            self.file_transfer_handles
                .get_mut(&file_key)
                .ok_or_else(|| {
                    NetworkError::msg(format!(
                        "file_transfer_handle does not contain key for {file_key:?}"
                    ))
                })?;

        file_transfer_handle
            .unbounded_send(ObjectTransferStatus::Fail(error_message.into()))
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub fn on_group_payload_received(
        &mut self,
        header: &HdpHeader,
        payload: Bytes,
        hr: &R,
    ) -> Result<PrimaryProcessorResult, (NetworkError, Ticket, ObjectId)> {
        let target_cid = header.session_cid.get();
        let group_id = header.group.get();
        let object_id = header.context_info.get().into();
        let group_key = GroupKey::new(target_cid, group_id, object_id);
        let grc = self.inbound_groups.get_mut(&group_key).ok_or_else(|| {
            (
                NetworkError::msg(format!(
                    "inbound_groups does not contain key for {group_key:?}"
                )),
                Ticket(0),
                0.into(),
            )
        })?;

        let ticket = grc.ticket;
        let file_key = FileKey::new(grc.object_id);
        let file_container = self.inbound_files.get_mut(&file_key).ok_or_else(|| {
            (
                NetworkError::msg(format!(
                    "inbound_files does not contain key for {file_key:?}"
                )),
                ticket,
                object_id,
            )
        })?;
        let file_transfer_handle =
            self.file_transfer_handles
                .get_mut(&file_key)
                .ok_or_else(|| {
                    (
                        NetworkError::msg(format!(
                            "file_transfer_handle does not contain key for {file_key:?}"
                        )),
                        ticket,
                        object_id,
                    )
                })?;

        let src = *payload.first().ok_or((
            NetworkError::InvalidRequest("Bad payload packet [0]"),
            ticket,
            object_id,
        ))?;
        let dest = *payload.get(1).ok_or((
            NetworkError::InvalidRequest("Bad payload packet [1]"),
            ticket,
            object_id,
        ))?;
        let ts = self.time_tracker.get_global_time_ns();

        let true_sequence = citadel_crypt::packet_vector::generate_packet_coordinates_inv(
            header.wave_id.get(),
            src as u16,
            dest as u16,
            hr.get_scramble_pqc_and_entropy_bank().1,
        )
        .ok_or((
            NetworkError::InvalidRequest("Unable to obtain true_sequence"),
            ticket,
            object_id,
        ))?;

        let mut send_wave_ack = false;
        let mut complete = false;

        match grc.receiver.on_packet_received(
            group_id,
            true_sequence,
            header.wave_id.get(),
            hr,
            &payload[2..],
        ) {
            GroupReceiverStatus::GROUP_COMPLETE(_last_wid) => {
                let receiver = self.inbound_groups.remove(&group_key).unwrap().receiver;
                let mut chunk = receiver.finalize();
                let bytes_in_group = chunk.len();
                log::trace!(target: "citadel", "GROUP {} COMPLETE. Total groups: {} | Plaintext len: {} | Received plaintext len: {}", group_id, file_container.total_groups, file_container.metadata.plaintext_length, chunk.len());

                if let Some(local_encryption_level) = file_container.local_encryption_level {
                    log::trace!(target: "citadel", "Detected REVFS. Locally decrypting object {object_id} with level {local_encryption_level:?} | Ratchet used: {} w/version {}", hr.get_cid(), hr.version());
                    // which static hr do we need? Since we are receiving this chunk, always our local account's
                    let static_aux_hr = self.cnac.as_ref().unwrap().get_static_auxiliary_ratchet();

                    chunk = static_aux_hr
                        .local_decrypt(chunk, local_encryption_level)
                        .map_err(|err| (NetworkError::msg(err.into_string()), ticket, object_id))?;
                }

                file_container
                    .stream_to_hd
                    .unbounded_send(chunk)
                    .map_err(|err| (NetworkError::Generic(err.to_string()), ticket, object_id))?;

                send_wave_ack = true;

                if group_id as usize >= file_container.total_groups.saturating_sub(1) {
                    complete = true;
                    let file_container = self.inbound_files.remove(&file_key).unwrap();
                    // status of reception complete now located where the streaming to HD completes
                    // we need only take the sender and send a signal to prove that we finished correctly here
                    // TODO: it seems to be sending the file before the backend streamer even gets a chance to finish
                    // TODO: Do not send the reception complete tx until after the backend streamer has finished
                    file_container
                        .reception_complete_tx
                        .send(header.clone())
                        .map_err(|_| {
                            (
                                NetworkError::msg("reception_complete_tx err"),
                                ticket,
                                object_id,
                            )
                        })?;
                } else {
                    let now = self.time_tracker.get_global_time_ns();
                    let elapsed_nanos =
                        now.saturating_sub(file_container.last_group_finish_time) as f64;
                    let bytes_per_ns = bytes_in_group as f64 / elapsed_nanos; // unit: bytes/ns
                                                                              // convert bytes per period into MB/s
                    let mb_per_sec = bytes_per_ns * 1_000_000_000f64; // unit: bytes/sec
                    let mb_per_sec = mb_per_sec / 1_000_000f64; // unit: MB/sec
                                                                // Only use 2 decimals
                    let mb_per_sec = (mb_per_sec * 100.0).round() / 100.0;
                    log::trace!(target: "citadel", "Sending reception tick for group {} of {} | {} MB/s", group_id, file_container.total_groups, mb_per_sec);

                    file_container.last_group_finish_time = now;
                    let status = ObjectTransferStatus::ReceptionTick(
                        group_id as usize,
                        file_container.total_groups,
                        mb_per_sec as f32,
                    );
                    // sending the wave ack will complete the group on the initiator side
                    file_transfer_handle.unbounded_send(status).map_err(|err| {
                        (NetworkError::Generic(err.to_string()), ticket, object_id)
                    })?;
                }
            }

            // common case
            GroupReceiverStatus::INSERT_SUCCESS => {}

            GroupReceiverStatus::WAVE_COMPLETE(..) => {
                // send wave ACK to update progress on adjacent node
                send_wave_ack = true;
            }

            res => {
                log::error!(target: "citadel", "INVALID GroupReceiverStatus obtained: {:?}", res)
            }
        }

        if complete {
            log::trace!(target: "citadel", "Finished receiving file {:?}", file_key);
            let _ = self.inbound_files.remove(&file_key);
            let _ = self.file_transfer_handles.remove(&file_key);
        }

        if send_wave_ack {
            // only send a wave ack if incomplete, since the backend sync will send it
            if !complete {
                let wave_ack = packet_crafter::group::craft_wave_ack(
                    hr,
                    header.context_info.get().into(),
                    get_resp_target_cid_from_header(header),
                    header.group.get(),
                    header.wave_id.get(),
                    ts,
                    None,
                    header.security_level.into(),
                );
                return Ok(PrimaryProcessorResult::ReplyToSender(wave_ack));
            }
        }

        Ok(PrimaryProcessorResult::Void)
    }

    /// This function is called on Alice's side after Bob sends her a WAVE_ACK.
    /// The purpose of this function, for both tcp_only and reliable-udp, is to free memory.
    /// If using reliable-udp, then then this function has an additional purpose: to keep track
    /// of the number of waves ACK'ed. Once the number of waves ACK'ed equals the window size, this function
    /// also re-engages the transmitter
    #[allow(unused_results)]
    pub fn on_wave_ack_received(
        &mut self,
        session_cid: u64,
        header: &Ref<&[u8], HdpHeader>,
    ) -> bool {
        let object_id = header.context_info.get().into();
        let group = header.group.get();
        let wave_id = header.wave_id.get();
        let target_cid = header.session_cid.get();
        let key = GroupKey::new(target_cid, group, object_id);
        let mut delete_group = false;

        // file transfer
        if let Some(transmitter_container) = self.outbound_transmitters.get_mut(&key) {
            // we set has_begun here instead of the transmit_tcp, simply because we want the first wave to ACK
            transmitter_container.has_begun = true;
            let transmitter = transmitter_container
                .burst_transmitter
                .group_transmitter
                .as_mut()
                .expect("Transmitter not found");
            let relative_group_id = transmitter_container.relative_group_id;
            if transmitter.on_wave_tail_ack_received(wave_id) {
                // Group is finished. Delete it
                let elapsed_sec = transmitter_container
                    .transmission_start_time
                    .elapsed()
                    .as_secs_f32();
                let rate_mb_per_s = (transmitter_container.group_plaintext_length as f32
                    / 1_000_000f32)
                    / elapsed_sec;
                log::trace!(target: "citadel", "Transmitter received final wave ack. Alerting local node to continue transmission of next group");
                // if there is n=1 waves, then the below must be ran. The other use of object notifier in this function only applies for multiple waves
                if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                    let _ = next_group_notifier.unbounded_send(());
                    // alert kernel (transmitter side)
                    log::trace!(target: "citadel", "Notified object sender to begin sending the next group");
                }

                let file_key = FileKey::new(object_id);

                if let Some(tx) = self.file_transfer_handles.get(&file_key) {
                    let status = if relative_group_id as usize
                        != transmitter_container
                            .parent_object_total_groups
                            .saturating_sub(1)
                    {
                        ObjectTransferStatus::TransferTick(
                            relative_group_id as usize,
                            transmitter_container.parent_object_total_groups,
                            rate_mb_per_s,
                        )
                    } else {
                        ObjectTransferStatus::TransferComplete
                    };

                    log::trace!(target: "citadel", "Transmitter {session_cid}: {file_key:?} received final wave ack. Sending status to local node: {:?}", status);
                    if let Err(err) = tx.unbounded_send(status.clone()) {
                        // if the server is using an accept-only policy with no further responses, this branch
                        // will be reached
                        log::warn!(target: "citadel", "FileTransfer receiver handle cannot be reached {:?}", err);
                        // drop local async sending subroutines
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }

                    if matches!(status, ObjectTransferStatus::TransferComplete) {
                        // remove the transmitter. Dropping will stop related futures
                        log::trace!(target: "citadel", "FileTransfer is complete! Local is server? {}", self.is_server);
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }
                } else {
                    log::error!(target: "citadel", "Unable to find ObjectTransferHandle for {:?} | Local is {session_cid} | FileKeys available: {:?}", file_key, self.file_transfer_handles.keys().copied().collect::<Vec<_>>());
                }

                delete_group = true;
            }

            // TODO: The problem with premature loading is that the next group loaded may expire while the current is still transferring
            // even though the next GROUP_HEADER is sent out concurrent to this group transferring. Since file transfers use TCP, the TCP
            // stack may not get to it until after this group is done transferring. By the time that happens, the group on the sender side
            // may have expired. Thus, in order to fix this, we should designate a flag `has_begun`, similar to the receiving side
            if transmitter.is_atleast_fifty_percent_done() {
                if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                    let _ = next_group_notifier.unbounded_send(());
                    log::trace!(target: "citadel", "Notified object sender to begin sending the next group");
                }
            }
        } else {
            log::error!(target: "citadel", "File-transfer for object {} does not map to a transmitter container", object_id);
        }

        if delete_group {
            log::trace!(target: "citadel", "Group is done transmitting! Freeing memory ...");
            self.outbound_transmitters.remove(&key);
        }

        true
    }

    /// This should be ran periodically by the session timer
    pub fn keep_alive_subsystem_timed_out(&self, current_timestamp_ns: i64) -> bool {
        if let Some(prev_ka_time) = self.network_stats.last_keep_alive {
            //assert_ne!(self.keep_alive_timeout_ns, 0);
            current_timestamp_ns - prev_ka_time > self.keep_alive_timeout_ns
        } else {
            false
        }
    }

    #[allow(unused_results)]
    pub(crate) fn initiate_rekey(
        &mut self,
        virtual_target: VirtualTargetType,
        ticket: Option<Ticket>,
    ) -> Result<(), NetworkError> {
        fn return_already_in_progress<R: Ratchet>(
            kernel_tx: &UnboundedSender<NodeResult<R>>,
            ticket: Ticket,
            session_cid: u64,
        ) -> Result<(), NetworkError> {
            kernel_tx
                .unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status: ReKeyReturnType::AlreadyInProgress,
                    session_cid,
                }))
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }

        let ticket = ticket.unwrap_or_default();

        if !self.state.is_connected() {
            return Err(NetworkError::InvalidRequest(
                "Cannot initiate rekey since the session is not connected",
            ));
        }

        let (session_cid, target_cid) = match virtual_target {
            VirtualConnectionType::LocalGroupServer { session_cid } => {
                (session_cid, C2S_IDENTITY_CID)
            }

            VirtualConnectionType::LocalGroupPeer {
                peer_cid,
                session_cid,
            } => (session_cid, peer_cid),

            _ => {
                return Err(NetworkError::InvalidRequest(
                    "External group functionality not yet implemented",
                ))
            }
        };

        let v_conn = self.get_endpoint_container(target_cid)?;
        if v_conn.ratchet_manager.is_rekeying() {
            return return_already_in_progress(&self.kernel_tx, ticket, session_cid);
        }

        // Insert into map
        let index = ReKeyIndex { ticket, target_cid };

        if self.triggered_rekeys.lock().insert(index, ticket).is_some() {
            return return_already_in_progress(&self.kernel_tx, ticket, session_cid);
        }

        let to_kernel = self.kernel_tx.clone();

        let ratchet_manager = v_conn.ratchet_manager.clone();
        let task = async move {
            if let Err(err) = ratchet_manager.trigger_rekey().await {
                if let Err(err) = to_kernel.unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status: ReKeyReturnType::Failure { err },
                    session_cid,
                })) {
                    log::error!(target: "citadel", "Unable to send ReKeyResult to kernel: {err}");
                }
            }
        };

        spawn!(task);

        Ok(())
    }

    pub(crate) fn process_outbound_broadcast_command(
        &self,
        ticket: Ticket,
        command: &GroupBroadcast,
    ) -> Result<(), NetworkError> {
        if !self.state.is_connected() {
            log::warn!(target: "citadel", "Unable to execute group command since session is not connected");
            return Ok(());
        }

        let ratchet = self
            .get_virtual_connection_crypto(C2S_IDENTITY_CID)
            .ok_or(NetworkError::InternalError("C2s not loaded"))?
            .get_ratchet(None)
            .unwrap();
        let security_level = self
            .session_security_settings
            .map(|r| r.security_level)
            .unwrap();
        let to_primary_stream = self.get_primary_stream().unwrap();

        let timestamp = self.time_tracker.get_global_time_ns();
        let packet = match command {
            GroupBroadcast::Create { .. }
            | GroupBroadcast::End { .. }
            | GroupBroadcast::Kick { .. }
            | GroupBroadcast::Message { .. }
            | GroupBroadcast::Add { .. }
            | GroupBroadcast::AcceptMembership { .. }
            | GroupBroadcast::DeclineMembership { .. }
            | GroupBroadcast::RequestJoin { .. }
            | GroupBroadcast::ListGroupsFor { .. }
            | GroupBroadcast::LeaveRoom { .. } => {
                packet_crafter::peer_cmd::craft_group_message_packet(
                    &ratchet,
                    command,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                )
            }

            n => {
                return Err(NetworkError::Generic(format!(
                    "{:?} is not a valid group broadcast request",
                    &n
                )));
            }
        };

        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub(crate) fn setup_group_channel_endpoints(
        &mut self,
        key: MessageGroupKey,
        ticket: Ticket,
        session: &CitadelSession<R>,
    ) -> Result<GroupChannel, NetworkError> {
        let (tx, rx) = unbounded();
        let session_cid = self
            .cnac
            .as_ref()
            .map(|r| r.get_cid())
            .ok_or(NetworkError::InternalError("CNAC not loaded"))?;

        if self.group_channels.contains_key(&key) {
            return Err(NetworkError::InternalError(
                "Group channel already exists locally",
            ));
        }

        let _ = self.group_channels.insert(key, tx);

        let (to_session_tx, to_session_rx) =
            crate::proto::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);

        let v_conn_type = VirtualConnectionType::LocalGroupServer { session_cid };

        CitadelSession::spawn_message_sender_function(session.clone(), v_conn_type, to_session_rx);

        Ok(GroupChannel::new(
            to_session_tx,
            key,
            ticket,
            session_cid,
            rx,
        ))
    }

    fn get_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        self.get_virtual_connection(C2S_IDENTITY_CID)
            .ok()?
            .endpoint_container
            .as_ref()?
            .get_direct_p2p_primary_stream()
    }
}
