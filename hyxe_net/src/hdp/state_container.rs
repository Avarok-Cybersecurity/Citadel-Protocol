use std::collections::{HashMap, VecDeque};
use std::fmt::{Display, Formatter, Debug};
use std::ops::RangeInclusive;
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, ConstructorType};
use crate::hdp::packet_processor::primary_group_packet::{attempt_kem_as_alice_finish, get_resp_target_cid_from_header};

use crate::hdp::outbound_sender::{UnboundedSender, unbounded};
use zerocopy::LayoutVerified;

use hyxe_crypt::net::crypt_splitter::{GroupReceiver, GroupReceiverConfig, GroupReceiverStatus};
use netbeam::time_tracker::TimeTracker;
use hyxe_user::client_account::ClientNetworkAccount;

use crate::constants::{GROUP_TIMEOUT_MS, INDIVIDUAL_WAVE_TIMEOUT_MS, KEEP_ALIVE_INTERVAL_MS, GROUP_EXPIRE_TIME_MS, MAX_OUTGOING_UNPROCESSED_REQUESTS};
use crate::hdp::hdp_packet::HdpHeader;
use crate::hdp::hdp_packet::packet_flags;
use crate::hdp::hdp_packet_crafter::{GroupTransmitter, SecureProtocolPacket, RatchetPacketCrafterContainer};
use crate::hdp::packet_processor::includes::{Instant, SocketAddr, HdpSession};
use crate::hdp::hdp_node::{NodeResult, Ticket, NodeRemote, SecrecyMode};
use crate::hdp::outbound_sender::{OutboundUdpSender, OutboundPrimaryStreamSender};
use crate::hdp::state_subcontainers::connect_state_container::ConnectState;
use crate::hdp::state_subcontainers::deregister_state_container::DeRegisterState;
use crate::hdp::state_subcontainers::drill_update_container::RatchetUpdateState;
use crate::hdp::state_subcontainers::preconnect_state_container::PreConnectState;
use crate::hdp::state_subcontainers::register_state_container::RegisterState;
use hyxe_crypt::drill::SecurityLevel;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::hdp::peer::channel::{PeerChannel, UdpChannel};
use crate::hdp::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus};
use crate::hdp::file_transfer::{VirtualFileMetadata, FileTransferStatus, FileTransferHandle, FileTransferOrientation};
use tokio::io::{BufWriter, AsyncWriteExt};
use hyxe_crypt::prelude::SecBuffer;
use crate::hdp::peer::p2p_conn_handler::DirectP2PRemote;
use crate::functional::IfEqConditional;
use futures::StreamExt;
use hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet};
use hyxe_fs::prelude::SyncIO;
use crate::hdp::state_subcontainers::meta_expiry_container::MetaExpiryState;
use crate::hdp::peer::peer_layer::{PeerConnectionType, UdpMode};
use hyxe_fs::env::DirectoryStore;
//use crate::hdp::misc::dual_rwlock::DualRwLock;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::hdp_session::SessionState;
use crate::hdp::misc::ordered_channel::OrderedChannel;
use bytes::Bytes;
use crate::error::NetworkError;
use atomic::Atomic;
use crate::hdp::hdp_packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use either::Either;
use crate::hdp::session_queue_handler::{QueueWorkerResult, SessionQueueWorkerHandle};
use crate::hdp::time::TransferStats;
use crate::hdp::hdp_packet_crafter;
use crate::hdp::misc::dual_late_init::DualLateInit;
use crate::hdp::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::prelude::MessageGroupKey;
use crate::hdp::peer::group_channel::{GroupBroadcastPayload, GroupChannel};
use crate::hdp::packet_processor::PrimaryProcessorResult;
use std::path::PathBuf;

impl Debug for StateContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateContainer")
    }
}

define_outer_struct_wrapper!(StateContainer, StateContainerInner);

/// For keeping track of the stages
pub struct StateContainerInner {
    pub(super) pre_connect_state: PreConnectState,
    pub(super) hdp_server_remote: NodeRemote,
    /// No hashmap here, since register is only for a single target
    pub(super) register_state: RegisterState,
    /// No hashmap here, since connect is only for a single target
    pub(super) connect_state: ConnectState,
    pub(super) ratchet_update_state: RatchetUpdateState,
    pub(super) deregister_state: DeRegisterState,
    pub(super) meta_expiry_state: MetaExpiryState,
    pub(super) network_stats: NetworkStats,
    pub(super) enqueued_packets: HashMap<u64, VecDeque<(Ticket, SecureProtocolPacket, VirtualTargetType, SecurityLevel)>>,
    pub(super) updates_in_progress: HashMap<u64, Arc<AtomicBool>>,
    pub(super) inbound_files: HashMap<FileKey, InboundFileTransfer>,
    pub(super) outbound_files: HashMap<FileKey, OutboundFileTransfer>,
    pub(super) file_transfer_handles: HashMap<FileKey, UnboundedSender<FileTransferStatus>>,
    pub(super) inbound_groups: HashMap<GroupKey, GroupReceiverContainer>,
    pub(super) outbound_transmitters: HashMap<GroupKey, OutboundTransmitterContainer>,
    pub(super) peer_kem_states: HashMap<u64, PeerKemStateContainer>,
    // u64 is peer id, ticket is the local original ticket (ticket may
    // transform if a simultaneous connect)
    pub(super) outgoing_peer_connect_attempts: HashMap<u64, Ticket>,
    pub(super) udp_primary_outbound_tx: Option<OutboundUdpSender>,
    pub(super) kernel_tx: UnboundedSender<NodeResult>,
    pub(super) active_virtual_connections: HashMap<u64, VirtualConnection>,
    pub(super) c2s_channel_container: Option<C2SChannelContainer>,
    pub(crate) keep_alive_timeout_ns: i64,
    pub(crate) state: Arc<Atomic<SessionState>>,
    // whenever a c2s or p2p channel is loaded, this is fired to signal any UDP loaders that it is safe to store the UDP conn in the corresponding v_conn
    pub(super) tcp_loaded_status: Option<tokio::sync::oneshot::Sender<()>>,
    pub(super) hole_puncher_pipes: HashMap<u64, tokio::sync::mpsc::UnboundedSender<Bytes>>,
    pub(super) cnac: Option<ClientNetworkAccount>,
    pub(super) time_tracker: TimeTracker,
    pub(super) session_security_settings: Option<SessionSecuritySettings>,
    pub(super) queue_handle: DualLateInit<SessionQueueWorkerHandle>,
    pub(super) group_channels: HashMap<MessageGroupKey, UnboundedSender<GroupBroadcastPayload>>,
    pub(super) transfer_stats: TransferStats,
    pub(super) udp_mode: UdpMode,
    is_server: bool
}

/// This helps consolidate unique keys between vconns sending data to this node
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct GroupKey {
    target_cid: u64,
    group_id: u64
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct FileKey {
    pub target_cid: u64,
    // wave payload get the object id inscribed
    pub object_id: u32
}

/// when the GROUP_HEADER comes inbound with virtual file metadata, this should be created alongside
/// an async task fired-up on the threadpool
#[allow(dead_code)]
pub(crate) struct InboundFileTransfer {
    pub object_id: u32,
    pub total_groups: usize,
    pub groups_rendered: usize,
    pub last_group_window_len: usize,
    pub last_group_finish_time: Instant,
    pub ticket: Ticket,
    pub virtual_target: VirtualTargetType,
    pub metadata: VirtualFileMetadata,
    pub stream_to_hd: UnboundedSender<Vec<u8>>,
    pub reception_complete_tx: tokio::sync::oneshot::Sender<()>
}

#[allow(dead_code)]
pub(crate) struct OutboundFileTransfer {
    pub object_id: u32,
    pub ticket: Ticket,
    // for alerting the group sender to begin sending the next group
    pub next_gs_alerter: UnboundedSender<()>,
    // for alerting the async task to begin creating GroupSenders
    pub start: Option<tokio::sync::oneshot::Sender<bool>>,
    // This sends a shutdown signal to the async cryptscambler
    pub stop_tx: Option<tokio::sync::oneshot::Sender<()>>
}

impl GroupKey {
    pub fn new(target_cid: u64, group_id: u64) -> Self {
        Self { target_cid, group_id }
    }
}

impl FileKey {
    pub fn new(target_cid: u64, object_id: u32) -> Self {
        Self { target_cid, object_id }
    }
}

/// For keeping track of connections
pub struct VirtualConnection<R: Ratchet = HyperRatchet> {
    /// For determining the type of connection
    pub connection_type: VirtualConnectionType,
    pub last_delivered_message_timestamp: Arc<Atomic<Option<Instant>>>,
    pub is_active: Arc<AtomicBool>,
    // this is Some for server, None for endpoints
    pub sender: Option<(Option<OutboundUdpSender>, OutboundPrimaryStreamSender)>,
    // this is None for server, Some for endpoints
    pub endpoint_container: Option<EndpointChannelContainer<R>>
}

impl VirtualConnection {
    /// If No version is supplied, uses the latest committed version
    pub fn borrow_endpoint_hyper_ratchet(&self, version: Option<u32>) -> Option<&HyperRatchet> {
        let endpoint_container = self.endpoint_container.as_ref()?;
        endpoint_container.endpoint_crypto.get_hyper_ratchet(version)
    }
}


pub struct EndpointChannelContainer<R: Ratchet = HyperRatchet> {
    pub(crate) default_security_settings: SessionSecuritySettings,
    // this is only loaded if STUN-like NAT-traversal works
    pub(crate) direct_p2p_remote: Option<DirectP2PRemote>,
    pub(crate) endpoint_crypto: PeerSessionCrypto<R>,
    to_default_channel: OrderedChannel,
    // for UDP
    pub(crate) to_unordered_channel: Option<UnorderedChannelContainer>,
    #[allow(dead_code)]
    pub(crate) peer_socket_addr: SocketAddr
}

pub struct C2SChannelContainer {
    to_channel: OrderedChannel,
    // for UDP
    pub(crate) to_unordered_channel: Option<UnorderedChannelContainer>,
    is_active: Arc<AtomicBool>,
    primary_outbound_tx: OutboundPrimaryStreamSender,
    pub(crate) channel_signal: Option<NodeResult>
}

pub(crate) struct UnorderedChannelContainer {
    to_channel: UnboundedSender<SecBuffer>,
    stopper_tx: tokio::sync::oneshot::Sender<()>
}

impl EndpointChannelContainer {
    pub fn get_direct_p2p_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        Some(&self.direct_p2p_remote.as_ref()?.p2p_primary_stream)
    }
}

impl<R: Ratchet> Drop for VirtualConnection<R> {
    fn drop(&mut self) {
        self.is_active.store(false, Ordering::SeqCst);
    }
}


/// For determining the nature of a [VirtualConnection]
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum VirtualConnectionType {
    // A peer in the HyperLAN is connected to a peer in the HyperLAN. Contains the target CID
    HyperLANPeerToHyperLANPeer(u64, u64),
    // A peer in the HyperLAN is connected to a peer in the HyperWAN. Contains the target CID
    HyperLANPeerToHyperWANPeer(u64, u64, u64),
    // A peer in the HyperLAN is connected to its own server. Contains the target CID
    HyperLANPeerToHyperLANServer(u64),
    // A peer in the HyperLAN is connected to a HyperWAN Server. Contains the iCID
    HyperLANPeerToHyperWANServer(u64, u64),
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

    pub fn from_header(header: &LayoutVerified<&[u8], HdpHeader>) -> Self {
        if header.target_cid.get() != 0 {
            VirtualTargetType::HyperLANPeerToHyperLANPeer(header.session_cid.get(), header.target_cid.get())
        } else {
            VirtualTargetType::HyperLANPeerToHyperLANServer(header.session_cid.get())
        }
    }

    /// Gets the target cid, agnostic to type
    pub fn get_target_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(_cid) => {
                // by rule of the network, the target CID is zero if a hyperlan peer -> hyperlan serve conn
                0
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => {
                *target_cid
            }

            VirtualConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, target_cid) => {
                *target_cid
            }

            VirtualConnectionType::HyperLANPeerToHyperWANServer(_implicated_cid, icid) => {
                *icid
            }
        }
    }

    /// Gets the target cid, agnostic to type
    pub fn get_implicated_cid(&self) -> u64 {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(cid) => {
                // by rule of the network, the target CID is zero if a hyperlan peer -> hyperlan serve conn
                *cid
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
                *implicated_cid
            }

            VirtualConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, _icid, _target_cid) => {
                *implicated_cid
            }

            VirtualConnectionType::HyperLANPeerToHyperWANServer(implicated_cid, _icid) => {
                *implicated_cid
            }
        }
    }

    /// panics if self is not the supposed type
    pub fn assert_hyperlan_peer_to_hyperlan_peer(self) -> (u64, u64) {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => (implicated_cid, target_cid),
            _ => panic!("Invalid branch selection")
        }
    }

    /// panics if self is not the supposed type
    pub fn assert_hyperlan_peer_to_hyperwan_peer(self) -> (u64, u64, u64) {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => (implicated_cid, icid, target_cid),
            _ => panic!("Invalid branch selection")
        }
    }

    /// panics if self is not the supposed type
    pub fn assert_hyperlan_peer_to_hyperlan_server(self) -> u64 {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => implicated_cid,
            _ => panic!("Invalid branch selection")
        }
    }

    /// panics if self is not the supposed type
    pub fn assert_hyperlan_peer_to_hyperwan_server(self) -> (u64, u64) {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperWANServer(implicated_cid, icid) => (implicated_cid, icid),
            _ => panic!("Invalid branch selection")
        }
    }

    pub fn is_hyperlan(&self) -> bool {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(..) | VirtualConnectionType::HyperLANPeerToHyperLANServer(..) => true,
            _ => false
        }
    }

    pub fn is_hyperwan(&self) -> bool {
        !self.is_hyperlan()
    }

    pub fn try_as_peer_connection(&self) -> Option<PeerConnectionType> {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, peer_cid) => {
                Some(PeerConnectionType::HyperLANPeerToHyperLANPeer(*implicated_cid, *peer_cid))
            }

            VirtualConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, peer_cid) => {
                Some(PeerConnectionType::HyperLANPeerToHyperWANPeer(*implicated_cid, *icid, *peer_cid))
            }

            _ => None
        }
    }

    pub fn set_target_cid(&mut self, target_cid: u64) {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, peer_cid) |
            VirtualConnectionType::HyperLANPeerToHyperWANPeer(_, _, peer_cid) => {
                *peer_cid = target_cid
            }

            _ => {}
        }
    }
}

impl Display for VirtualConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(cid) => {
                write!(f, "HyperLAN Peer to HyperLAN Server ({})", cid)
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                write!(f, "HyperLAN Peer to HyperLAN Peer ({} -> {})", implicated_cid, target_cid)
            }

            VirtualConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => {
                write!(f, "HyperLAN Peer to HyperWAN Peer ({} -> {} -> {})", implicated_cid, icid, target_cid)
            }

            VirtualConnectionType::HyperLANPeerToHyperWANServer(implicated_cid, icid) => {
                write!(f, "HyperLAN Peer to HyperWAN Server ({} -> {})", implicated_cid, icid)
            }
        }
    }
}

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
/// Since it is possible for multiple connections to have an equivalent ticket, we include the CID. This will
/// guarantee uniqueness because each CID keeps track an incrementing ticket
pub(super) struct VirtualKey {
    pub(super) cid: u64,
    pub(super) ticket: Ticket,
}

#[derive(Default)]
pub(super) struct NetworkStats {
    pub(super) last_keep_alive: Option<i64>,
    pub(super) ping_ns: Option<i64>,
    pub(super) jitter_ns: Option<i64>,
    pub(super) rtt_ns: Option<i64>
}

//define_outer_struct_wrapper!(GroupSender, GroupSenderDevice<HDP_HEADER_BYTE_LEN>);

pub(crate) struct OutboundTransmitterContainer {
    ratchet_constructor: Option<HyperRatchetConstructor>,
    pub(crate) burst_transmitter: GroupTransmitter,
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
    pub has_begun: bool
}

impl OutboundTransmitterContainer {
    pub fn new(object_notifier: Option<UnboundedSender<()>>, mut burst_transmitter: GroupTransmitter, group_plaintext_length: usize, parent_object_total_groups: usize, relative_group_id: u32, ticket: Ticket) -> Self {
        let ratchet_constructor = burst_transmitter.hyper_ratchet_container.base_constructor.take();
        let transmission_start_time = Instant::now();
        let has_begun = false;

        Self { ratchet_constructor, has_begun, relative_group_id, ticket, parent_object_total_groups, transmission_start_time, group_plaintext_length, object_notifier, burst_transmitter, waves_in_current_window: 0 }
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
    pub object_id: u32
}

impl GroupReceiverContainer {
    pub fn new(object_id: u32, receiver: GroupReceiver, virtual_target: VirtualTargetType, security_level: SecurityLevel, ticket: Ticket) -> Self {
        Self { has_begun: false, object_id, security_level, virtual_target, receiver, ticket, current_window: 0..=0, waves_in_window_finished: 0, last_window_size: 0, window_drift: 0, next_window_size: 1, max_window_size: 0 }
    }
}

impl StateContainerInner {
    /// Creates a new container
    pub fn new(kernel_tx: UnboundedSender<NodeResult>, hdp_server_remote: NodeRemote, keep_alive_timeout_ns: i64, state: Arc<Atomic<SessionState>>, cnac: Option<ClientNetworkAccount>, time_tracker: TimeTracker, session_security_settings: Option<SessionSecuritySettings>, is_server: bool, transfer_stats: TransferStats, udp_mode: UdpMode) -> StateContainer {
        let inner = Self { outgoing_peer_connect_attempts: Default::default(), file_transfer_handles: HashMap::new(), group_channels: Default::default(), udp_mode, transfer_stats, queue_handle: Default::default(), is_server, session_security_settings, time_tracker, cnac, updates_in_progress: HashMap::new(), hole_puncher_pipes: HashMap::new(), tcp_loaded_status: None, enqueued_packets: HashMap::new(), state, c2s_channel_container: None, keep_alive_timeout_ns, hdp_server_remote, meta_expiry_state: Default::default(), pre_connect_state: Default::default(), udp_primary_outbound_tx: None, deregister_state: Default::default(), ratchet_update_state: Default::default(), active_virtual_connections: Default::default(), network_stats: Default::default(), kernel_tx, register_state: packet_flags::cmd::aux::do_register::STAGE0.into(), connect_state: packet_flags::cmd::aux::do_connect::STAGE0.into(), inbound_groups: HashMap::new(), outbound_transmitters: HashMap::new(), peer_kem_states: HashMap::new(), inbound_files: HashMap::new(), outbound_files: HashMap::new() };
        StateContainer { inner: Arc::new(parking_lot::RwLock::new(inner)) }
    }

    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_ordered_channel(&mut self, target_cid: u64, group_id: u64, data: SecBuffer) -> bool {
        if target_cid == 0 {
            if let Some(c2s_container) = self.c2s_channel_container.as_mut() {
                return c2s_container.to_channel.on_packet_received(group_id, data).is_ok()
            }
        } else {
            if let Some(vconn) = self.active_virtual_connections.get_mut(&target_cid) {
                if let Some(channel) = vconn.endpoint_container.as_mut() {
                    return channel.to_default_channel.on_packet_received(group_id, data).is_ok()
                }
            }
        }

        false
    }

    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_unordered_channel(&self, target_cid: u64, data: SecBuffer) -> bool {
        if target_cid == 0 {
            if let Some(c2s_container) = self.c2s_channel_container.as_ref() {
                if let Some(unordered_channel) = c2s_container.to_unordered_channel.as_ref() {
                    return unordered_channel.to_channel.unbounded_send(data).is_ok()
                }
            }
        } else {
            if let Some(vconn) = self.active_virtual_connections.get(&target_cid) {
                if let Some(channel) = vconn.endpoint_container.as_ref() {
                    if let Some(unordered_channel) = channel.to_unordered_channel.as_ref() {
                        return unordered_channel.to_channel.unbounded_send(data).is_ok()
                    }
                }
            }
        }

        log::warn!(target: "lusna", "Attempted to forward data to unordered channel, but, one or more containers were not present");

        false
    }

    // Requirements: A TCP/reliable ordered conn channel must already be setup in order for the connection to continue
    pub fn insert_udp_channel(&mut self, target_cid: u64, v_conn: VirtualConnectionType, ticket: Ticket, to_udp_stream: OutboundUdpSender, stopper_tx: tokio::sync::oneshot::Sender<()>) -> Option<UdpChannel> {
        if target_cid == 0 {
            if let Some(c2s_container) = self.c2s_channel_container.as_mut() {
                self.udp_primary_outbound_tx = Some(to_udp_stream.clone());
                let (to_channel, rx) = unbounded();
                let udp_channel = UdpChannel::new(to_udp_stream, rx, target_cid,v_conn, ticket, c2s_container.is_active.clone(), self.hdp_server_remote.clone());
                c2s_container.to_unordered_channel = Some(UnorderedChannelContainer { to_channel, stopper_tx });
                // data can now be forwarded
                Some(udp_channel)
            } else {
                None
            }
        } else {
            if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
                if let Some((sender, _)) = p2p_container.sender.as_mut() {
                    *sender = Some(to_udp_stream.clone());
                    if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                        let (to_channel, rx) = unbounded();
                        let udp_channel = UdpChannel::new(to_udp_stream, rx, target_cid,v_conn, ticket, p2p_container.is_active.clone(), self.hdp_server_remote.clone());
                        p2p_endpoint_container.to_unordered_channel = Some(UnorderedChannelContainer { to_channel, stopper_tx });
                        // data can now be forwarded
                        Some(udp_channel)
                    } else {
                        log::trace!(target: "lusna", "WE2");
                        None
                    }
                } else {
                    log::trace!(target: "lusna", "WE1");
                    None
                }
            } else {
                log::trace!(target: "lusna", "WE0");
                None
            }
        }
    }

    pub fn remove_udp_channel(&mut self, target_cid: u64) {
        if target_cid == 0 {
            if let Some(c2s_container) = self.c2s_channel_container.as_mut() {
                if let Some(channel) = c2s_container.to_unordered_channel.take() {
                    let _ = channel.stopper_tx.send(());
                }
            }
        } else {
            if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
                if let Some((sender, _)) = p2p_container.sender.as_mut() {
                    if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                        if let Some(channel) = p2p_endpoint_container.to_unordered_channel.take() {
                            let _ = channel.stopper_tx.send(());
                        }
                        *sender = None;
                    }
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
    pub(crate) fn insert_direct_p2p_connection(&mut self, provisional: DirectP2PRemote, peer_cid: u64) -> Result<(), NetworkError> {
        if let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) {
            if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                log::trace!(target: "lusna", "UPGRADING {} conn type", provisional.from_listener.if_eq(true, "listener").if_false("client"));
                // By setting the below value, all outbound packets will use
                // this direct conn over the proxied TURN-like connection
                vconn.sender = Some((None, provisional.p2p_primary_stream.clone())); // setting this will allow the UDP stream to be upgraded too

                if let Some(_) = endpoint_container.direct_p2p_remote.replace(provisional) {
                    log::warn!(target: "lusna", "Dropped previous p2p remote during upgrade process");
                }

                return Ok(());
            }
        }

        Err(NetworkError::InternalError("Unable to upgrade"))
    }

    #[allow(unused_results)]
    pub fn insert_new_peer_virtual_connection_as_endpoint(&mut self, peer_socket_addr: SocketAddr, default_security_settings: SessionSecuritySettings, channel_ticket: Ticket, target_cid: u64, connection_type: VirtualConnectionType, endpoint_crypto: PeerSessionCrypto, sess: &HdpSession) -> PeerChannel {
        let (channel_tx, channel_rx) = unbounded();
        let (tx, rx) = crate::hdp::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);
        let is_active = Arc::new(AtomicBool::new(true));

        self.updates_in_progress.insert(target_cid, endpoint_crypto.update_in_progress.clone());

        //let (tx, rx) = futures::channel::mpsc::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);
        let peer_channel = PeerChannel::new(self.hdp_server_remote.clone(), target_cid, connection_type, channel_ticket, default_security_settings.security_level, is_active.clone(), channel_rx, tx);
        let to_channel = OrderedChannel::new(channel_tx);
        HdpSession::spawn_message_sender_function(sess.clone(), rx);

        let endpoint_container = Some(EndpointChannelContainer {
            default_security_settings,
            direct_p2p_remote: None,
            endpoint_crypto,
            to_default_channel: to_channel,
            to_unordered_channel: None,
            peer_socket_addr
        });

        let vconn = VirtualConnection {
            last_delivered_message_timestamp: Arc::new(Atomic::new(None)),
            connection_type,
            is_active,
            // this is None for endpoints, as there's no need for this
            sender: None,
            endpoint_container
        };

        self.active_virtual_connections.insert(target_cid, vconn);

        peer_channel
    }

    /// This should be ran at the beginning of a session to provide ordered delivery to clients
    #[allow(unused_results)]
    pub fn init_new_c2s_virtual_connection(&mut self, cnac: &ClientNetworkAccount, security_level: SecurityLevel, channel_ticket: Ticket, implicated_cid: u64, session: &HdpSession) -> PeerChannel {
        let (channel_tx, channel_rx) = unbounded();
        let (tx, rx) = crate::hdp::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);
        let is_active = Arc::new(AtomicBool::new(true));
        let peer_channel = PeerChannel::new(self.hdp_server_remote.clone(), implicated_cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), channel_ticket, security_level, is_active.clone(), channel_rx, tx);
        HdpSession::spawn_message_sender_function(session.clone(), rx);

        let c2s = C2SChannelContainer {
            to_channel: OrderedChannel::new(channel_tx),
            to_unordered_channel: None,
            is_active,
            primary_outbound_tx: session.to_primary_stream.clone().unwrap(),
            channel_signal: None
        };

        self.c2s_channel_container = Some(c2s);

        self.updates_in_progress.insert(0, cnac.visit(|r| r.crypt_container.update_in_progress.clone()));

        if let Some(udp_alerter) = self.tcp_loaded_status.take() {
            let _ = udp_alerter.send(());
        }

        peer_channel
    }

    pub fn setup_tcp_alert_if_udp_c2s(&mut self) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tcp_loaded_status = Some(tx);
        rx
    }

    /// Note: the `endpoint_crypto` container needs to be Some in order for transfer to occur between peers w/o encryption/decryption at the center point
    /// GROUP packets and PEER_CMD::CHANNEL packets bypass the central node's encryption/decryption phase
    pub fn insert_new_virtual_connection_as_server(&mut self, target_cid: u64, connection_type: VirtualConnectionType, target_udp_sender: Option<OutboundUdpSender>, target_tcp_sender: OutboundPrimaryStreamSender) {
        let val = VirtualConnection { last_delivered_message_timestamp: Arc::new(Atomic::new(None)), endpoint_container: None, sender: Some((target_udp_sender, target_tcp_sender)), connection_type, is_active: Arc::new(AtomicBool::new(true)) };
        if self.active_virtual_connections.insert(target_cid, val).is_some() {
            log::warn!(target: "lusna", "Inserted a virtual connection. but overwrote one in the process. Report to developers");
        }

        log::trace!(target: "lusna", "Vconn {} -> {} established", connection_type.get_implicated_cid(), target_cid);
    }

    pub fn get_peer_session_crypto(active_virtual_connections: &mut HashMap<u64, VirtualConnection>, peer_cid: u64) -> Option<&mut PeerSessionCrypto> {
        Some(&mut active_virtual_connections.get_mut(&peer_cid)?.endpoint_container.as_mut()?.endpoint_crypto)
    }

    /// When a keep alive is received, this function gets called. Prior to getting called,
    /// validity must be ensured!
    #[allow(unused_results)]
    pub fn on_keep_alive_received(&mut self, inbound_packet_timestamp_ns: i64, mut current_timestamp_ns: i64) -> bool {
        if self.keep_alive_timeout_ns == 0 {
            return true;
        }

        let mut ping_ns = current_timestamp_ns - inbound_packet_timestamp_ns;
        if ping_ns < 0 {
            // For localhost testing, this sometimes occurs. The clocks might be out of sync a bit.
            current_timestamp_ns = current_timestamp_ns - ping_ns;
            // Negate it, for now. Usually, this wont happen on networks
            ping_ns = -ping_ns;
        }
        // The jitter is the differential of pings. Ping current - ping present
        let jitter_ns = ping_ns - self.network_stats.ping_ns.clone().unwrap_or(0);
        self.network_stats.jitter_ns.replace(jitter_ns);
        self.network_stats.ping_ns.replace(ping_ns);

        let res = if let Some(last_ka) = self.network_stats.last_keep_alive.take() {
            if ping_ns > self.keep_alive_timeout_ns {
                // possible timeout. There COULD be packets being spammed, preventing KAs from getting through. Thus, check the meta expiry container
                if self.meta_expiry_state.expired() {
                    // no packets are backing up the system. We are DC'ed
                    false
                } else {
                    // packets are backed up, return true since other packets are making it across anyways
                    true
                }
            } else {
                self.network_stats.last_keep_alive.replace(current_timestamp_ns);
                // We subtract two keep alive intervals, since it pauses that long on each end. We multiply by 1 million to convert ms to ns
                const PROCESS_TIME_NS: i64 = 2 * KEEP_ALIVE_INTERVAL_MS as i64 * 1_000_000;
                self.network_stats.rtt_ns.replace(current_timestamp_ns - last_ka - PROCESS_TIME_NS);
                true
            }
        } else {
            // This is the first KA in the series
            self.network_stats.last_keep_alive.replace(current_timestamp_ns);
            true
        };

        //log::trace!(target: "lusna", "KEEP ALIVE subsystem statistics: Ping: {}ms | RTT: {}ms | Jitter: {}ms", (ping_ns as f64/1_000_000f64) as f64, (self.network_stats.rtt_ns.clone().unwrap_or(0) as f64/1_000_000f64) as f64, (jitter_ns as f64/1000000f64) as f64);
        res
    }

    /// Like the other functions in this file, ensure that verification is called before running this
    /// Returns the initial wave window
    #[allow(unused_results)]
    pub fn on_group_header_received(&mut self, header: &LayoutVerified<&[u8], HdpHeader>, group_receiver_config: GroupReceiverConfig, virtual_target: VirtualTargetType) -> Option<RangeInclusive<u32>> {
        let group_id = header.group.get();
        let ticket = header.context_info.get();
        let object_id = header.wave_id.get();
        // below, the target_cid in the key is where the packet came from. If it is a client, or a hyperlan conn, the implicated cid stays the same
        let inbound_group_key = GroupKey::new(header.session_cid.get(), group_id);
        if !self.inbound_groups.contains_key(&inbound_group_key) {
            let receiver = GroupReceiver::new(group_receiver_config,INDIVIDUAL_WAVE_TIMEOUT_MS, GROUP_TIMEOUT_MS);
            let security_level = SecurityLevel::for_value(header.security_level as usize)?;
            let mut receiver_container = GroupReceiverContainer::new(object_id, receiver, virtual_target, security_level, ticket.into());
            // check to see if we need to copy the last wave window
            let last_window_size = if object_id != 0 {
                // copy previous window
                let file_key = FileKey::new(header.session_cid.get(), object_id);
                if let Some(inbound_file_transfer) = self.inbound_files.get(&file_key) {
                    inbound_file_transfer.last_group_window_len
                } else {
                    log::error!(target: "lusna", "The GROUP HEADER implied the existence of a file transfer, but the key {:?} does not map to anything", &file_key);
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
                let max_idx = std::cmp::min(last_window_size, waves_in_group - 1) as u32;
                let min_idx = 0; // this is a new group; start at zero
                receiver_container.current_window = min_idx..=max_idx;
                min_idx..=max_idx
            } else {
                // if it was zero, not part of a file. Use the one proposed by the receiver container, by default
                receiver_container.current_window.clone()
            };

            self.inbound_groups.insert(inbound_group_key, receiver_container);
            Some(wave_window)
        } else {
            log::error!(target: "lusna", "Duplicate group HEADER detected ({})", group_id);
            None
        }
    }

    /// This creates an entry in the inbound_files hashmap
    #[allow(unused_results)]
    pub fn on_file_header_received(&mut self, header: &LayoutVerified<&[u8], HdpHeader>, virtual_target: VirtualTargetType, metadata: VirtualFileMetadata, dirs: &DirectoryStore) -> bool {
        let key = FileKey::new(header.session_cid.get(), metadata.object_id);
        let ticket = header.context_info.get().into();

        // TODO: Add file transfer accept request here. Once local accepts, then begin this subroutine
        if !self.inbound_files.contains_key(&key) {
            let (stream_to_hd, stream_to_hd_rx) = unbounded::<Vec<u8>>();
            let name = metadata.name.clone();
            let save_location = dirs.inner.read().hyxe_virtual_dir.clone();
            let save_location = format!("{}{}", save_location, name);
            let save_location = PathBuf::from(save_location);
            if let Ok(file) = std::fs::File::create(&save_location) {
                let file = tokio::fs::File::from_std(file);
                log::trace!(target: "lusna", "Will stream virtual file to: {:?}", &save_location);
                let (reception_complete_tx, success_receiving_rx) = tokio::sync::oneshot::channel::<()>();
                let entry = InboundFileTransfer {
                    last_group_finish_time: Instant::now(),
                    last_group_window_len: 0,
                    object_id: metadata.object_id,
                    total_groups: metadata.group_count,
                    ticket,
                    groups_rendered: 0,
                    virtual_target,
                    metadata: metadata.clone(),
                    reception_complete_tx,
                    stream_to_hd
                };

                self.inbound_files.insert(key, entry);
                let (handle, tx_status) = FileTransferHandle::new(header.session_cid.get(), header.target_cid.get(), FileTransferOrientation::Receiver);
                let _ = tx_status.unbounded_send(FileTransferStatus::ReceptionBeginning(save_location, metadata));
                self.file_transfer_handles.insert(key, tx_status.clone());
                // finally, alert the kernel (receiver)
                let _ = self.kernel_tx.unbounded_send(NodeResult::FileTransferHandle(ticket, handle));

                // now that the InboundFileTransfer is loaded, we just need to spawn the async task that takes the results and streams it to the HD.
                // This is safe since no mutation/reading on the state container or session takes place. This only streams to the hard drive without interrupting
                // the HdpServer's single thread. This will end once a None signal is sent through
                let stream_to_hd_task = async move {
                    let mut writer = BufWriter::new(file);
                    let mut reader = tokio_util::io::StreamReader::new(tokio_stream::wrappers::UnboundedReceiverStream::new(stream_to_hd_rx).map(|r| Ok(std::io::Cursor::new(r)) as Result<std::io::Cursor<Vec<u8>>, std::io::Error>));

                    if let Err(err) = tokio::io::copy(&mut reader, &mut writer).await {
                        log::error!(target: "lusna", "Error while copying from reader to writer: {}", err);
                    }

                    match writer.shutdown().await {
                        Ok(()) => {
                            log::trace!(target: "lusna", "Successfully synced file to HD");
                            let status = match success_receiving_rx.await {
                                Ok(_) => {
                                    FileTransferStatus::ReceptionComplete
                                }

                                Err(_) => {
                                    FileTransferStatus::Fail(format!("An unknown error occurred while receiving file"))
                                }
                            };

                            let _ = tx_status.unbounded_send(status);
                        },
                        Err(err) => {
                            log::error!(target: "lusna", "Unable to shut down streamer: {}", err);
                        },
                    };
                };

                spawn!(stream_to_hd_task);

                true
            } else {
                log::error!(target: "lusna", "Unable to obtain file handle to {:?}", &save_location);
                false
            }
        } else {
            log::error!(target: "lusna", "Duplicate file HEADER detected");
            false
        }
    }

    pub fn on_file_header_ack_received(&mut self, success: bool, implicated_cid: u64, ticket: Ticket, object_id: u32, v_target: VirtualTargetType) -> Option<()>{
        let (key, receiver_cid) = match v_target {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                // since the order hasn't flipped yet, get the implicated cid
                (FileKey::new(implicated_cid, object_id), target_cid)
            }

            VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) =>{
                (FileKey::new(implicated_cid, object_id), 0)
            }

            _ => {
                log::error!(target: "lusna", "HyperWAN functionality not yet enabled");
                return None;
            }
        };

        if success {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.get_mut(&key) {
                // start the async task pulling from the async cryptscrambler
                file_transfer.start.take()?.send(true).ok()?;
                let (handle, tx) = FileTransferHandle::new(implicated_cid, receiver_cid, FileTransferOrientation::Sender);
                tx.unbounded_send(FileTransferStatus::TransferBeginning).ok()?;
                let _ = self.file_transfer_handles.insert(key, tx);
                // alert the kernel that file transfer has begun
                self.kernel_tx.unbounded_send(NodeResult::FileTransferHandle(ticket, handle)).ok()?;
            } else {
                log::error!(target: "lusna", "Attempted to obtain OutboundFileTransfer for {:?}, but it didn't exist", key);
            }
        } else {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.remove(&key) {
                // stop the async cryptscrambler
                file_transfer.stop_tx?.send(()).ok()?;
                // stop the async task pulling from the async cryptscrambler
                file_transfer.start?.send(false).ok()?;
            } else {
                log::error!(target: "lusna", "Attempted to remove OutboundFileTransfer for {:?}, but it didn't exist", key);
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
    pub fn on_group_header_ack_received(&mut self, base_session_secrecy_mode: SecrecyMode, peer_cid: u64, target_cid: u64, group_id: u64, next_window: Option<RangeInclusive<u32>>, transfer: KemTransferStatus, fast_msg: bool, cnac_sess: &ClientNetworkAccount) -> bool {
        let key = GroupKey::new(peer_cid, group_id);

        if let Some(outbound_container) = self.outbound_transmitters.get_mut(&key) {
            let constructor = outbound_container.ratchet_constructor.take().map(ConstructorType::Default);
            if attempt_kem_as_alice_finish(base_session_secrecy_mode, peer_cid, target_cid, transfer, &mut self.active_virtual_connections, constructor, cnac_sess).is_err() {
                return true;
            }

            if fast_msg {
                let _ = self.outbound_transmitters.remove(&key);
                // we don't proceed past here b/c there's no need to send more data
                return true;
            }

            outbound_container.waves_in_current_window = next_window.clone().unwrap_or(0..=0).count();
            // file-transfer, or TCP only mode since next_window is none. Use TCP
            return outbound_container.burst_transmitter.transmit_tcp_file_transfer();
        } else {
            log::error!(target: "lusna", "Outbound transmitter for {:?} does not exist", key);
        }

        true
    }

    pub fn on_group_payload_received(&mut self, header: &HdpHeader, payload: Bytes, hr: &HyperRatchet) -> Result<PrimaryProcessorResult, NetworkError> {
        let target_cid = header.session_cid.get();
        let group_id = header.group.get();
        let group_key = GroupKey::new(target_cid, group_id);
        let grc = self.inbound_groups.get_mut(&group_key).ok_or_else(|| NetworkError::msg(format!("inbound_groups does not contain key for {:?}", group_key)))?;
        let file_key = FileKey::new(target_cid, grc.object_id);
        let file_container = self.inbound_files.get_mut(&file_key).ok_or_else(|| NetworkError::msg(format!("inbound_files does not contain key for {:?}", file_key)))?;
        let file_transfer_handle = self.file_transfer_handles.get_mut(&file_key).ok_or_else(|| NetworkError::msg(format!("file_transfer_handle does not contain key for {:?}", file_key)))?;

        let src = *payload.get(0).ok_or_else(|| NetworkError::InvalidRequest("Bad payload packet [0]"))?;
        let dest = *payload.get(1).ok_or_else(|| NetworkError::InvalidRequest("Bad payload packet [1]"))?;
        let ts = self.time_tracker.get_global_time_ns();

        let true_sequence = hyxe_crypt::packet_vector::generate_packet_coordinates_inv(header.wave_id.get(),
                                                                                       src as u16,
                                                                                       dest as u16,
                                                                                       hr.get_scramble_drill()).ok_or_else(|| NetworkError::InvalidRequest("Unable to obtain true_sequence"))?;

        let mut send_wave_ack = false;
        let mut complete = false;

        match grc.receiver.on_packet_received(group_id, true_sequence, header.wave_id.get(), hr,&payload[2..]) {
            GroupReceiverStatus::GROUP_COMPLETE(_last_wid) => {
                log::trace!(target: "lusna", "GROUP {} COMPLETE. Total groups: {}", group_id, file_container.total_groups);
                let chunk = self.inbound_groups.remove(&group_key).unwrap().receiver.finalize();
                file_container.stream_to_hd.unbounded_send(chunk).map_err(|err| NetworkError::Generic(err.to_string()))?;

                send_wave_ack = true;

                if group_id as usize == file_container.total_groups - 1 {
                    complete = true;
                    let file_container = self.inbound_files.remove(&file_key).unwrap();
                    // status of reception complete now located where the streaming to HD completes
                    // we need only take the sender and send a signal to prove that we finished correctly here
                    file_container.reception_complete_tx.send(()).map_err(|_| NetworkError::msg("reception_complete_tx err"))?;
                } else {
                    file_container.last_group_finish_time = Instant::now();
                    // TODO: Compute Mb/s
                    let status = FileTransferStatus::ReceptionTick(group_id as usize, file_container.total_groups, 0 as f32);
                    // sending the wave ack will complete the group on the initiator side
                    file_transfer_handle.unbounded_send(status).map_err(|err| NetworkError::Generic(err.to_string()))?;
                }
            }

            // common case
            GroupReceiverStatus::INSERT_SUCCESS => {}

            GroupReceiverStatus::WAVE_COMPLETE(..) => {
                // send wave ACK to update progress on adjacent node
            }

            res => {
                log::error!(target: "lusna", "INVALID GroupReceiverStatus obtained: {:?}", res)
            }
        }

        if complete {
            log::trace!(target: "lusna", "Finished receiving file {:?}", file_key);
            let _ = self.inbound_files.remove(&file_key);
            let _ = self.file_transfer_handles.remove(&file_key);
        }

        if send_wave_ack {
            let wave_ack = hdp_packet_crafter::group::craft_wave_ack(hr, header.context_info.get() as u32, get_resp_target_cid_from_header(header), header.group.get(), header.wave_id.get(), ts, None, header.security_level.into());
            return Ok(PrimaryProcessorResult::ReplyToSender(wave_ack))
        }

        Ok(PrimaryProcessorResult::Void)
    }

    /// This function is called on Alice's side after Bob sends her a WAVE_ACK.
    /// The purpose of this function, for both tcp_only and reliable-udp, is to free memory.
    /// If using reliable-udp, then then this function has an additional purpose: to keep track
    /// of the number of waves ACK'ed. Once the number of waves ACK'ed equals the window size, this function
    /// also re-engages the transmitter
    #[allow(unused_results)]
    pub fn on_wave_ack_received(&mut self, _implicated_cid: u64, header: &LayoutVerified<&[u8], HdpHeader>) -> bool {
        let object_id = header.context_info.get();
        let group = header.group.get();
        let wave_id = header.wave_id.get();
        let target_cid = header.session_cid.get();
        let key = GroupKey::new(target_cid, group);
        let mut delete_group = false;

        // file transfer
        if let Some(transmitter_container) = self.outbound_transmitters.get_mut(&key) {
            // we set has_begun here instead of the transmit_tcp, simply because we want the first wave to ACK
            transmitter_container.has_begun = true;
            let ref mut transmitter = transmitter_container.burst_transmitter.group_transmitter;
            let relative_group_id = transmitter_container.relative_group_id;
            if transmitter.on_wave_tail_ack_received(wave_id) {
                // Group is finished. Delete it
                let elapsed_sec = transmitter_container.transmission_start_time.elapsed().as_secs_f32();
                let rate_mb_per_s = (transmitter_container.group_plaintext_length as f32 / 1_000_000f32)/elapsed_sec;
                log::trace!(target: "lusna", "Transmitter received final wave ack. Alerting local node to continue transmission of next group");
                // if there is n=1 waves, then the below must be ran. The other use of object notifier in this function only applies for multiple waves
                if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                    let _ = next_group_notifier.unbounded_send(());
                    // alert kernel (transmitter side)
                    log::warn!(target: "lusna", "Notified object sender to begin sending the next group");
                }

                let file_key = FileKey::new(target_cid, object_id as u32);

                if let Some(tx) = self.file_transfer_handles.get(&file_key) {
                    let status = if relative_group_id as usize != transmitter_container.parent_object_total_groups - 1 {
                        FileTransferStatus::TransferTick(relative_group_id as usize, transmitter_container.parent_object_total_groups, rate_mb_per_s)
                    } else {
                        FileTransferStatus::TransferComplete
                    };

                    if let Err(err) = tx.unbounded_send(status.clone()) {
                        log::error!(target: "lusna", "FileTransfer receiver handle cannot be reached {:?}", err);
                        // drop local async sending subroutines
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }

                    if matches!(status, FileTransferStatus::TransferComplete) {
                        // remove the transmitter. Dropping will stop related futures
                        log::trace!(target: "lusna", "FileTransfer is complete!");
                        let _ = self.file_transfer_handles.remove(&file_key);
                    }
                } else {
                    log::error!(target: "lusna", "Unable to find FileTransferHandle for {:?}", file_key);
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
                    log::warn!(target: "lusna", "Notified object sender to begin sending the next group");
                }
            }
        } else {
            log::error!(target: "lusna", "File-transfer for object {} does not map to a transmitter container", object_id);
        }

        if delete_group {
            log::trace!(target: "lusna", "Group is done transmitting! Freeing memory ...");
            self.outbound_transmitters.remove(&key);
        }

        true
    }

    /// This should be ran periodically by the session timer
    pub fn keep_alive_subsystem_timed_out(&self, current_timestamp_ns: i64) -> bool {
        if let Some(prev_ka_time) = self.network_stats.last_keep_alive.clone() {
            //assert_ne!(self.keep_alive_timeout_ns, 0);
            current_timestamp_ns - prev_ka_time > self.keep_alive_timeout_ns
        } else {
            false
        }
    }

    fn get_secrecy_mode(&self, target_cid: u64) -> Option<SecrecyMode> {
        if target_cid != C2S_ENCRYPTION_ONLY {
            Some(self.active_virtual_connections.get(&target_cid)?.endpoint_container.as_ref()?.default_security_settings.secrecy_mode)
        } else {
            self.session_security_settings.as_ref().map(|r| r.secrecy_mode).clone()
        }
    }

    /// Returns true if a packet was sent, false otherwise. This should only be called when a packet is received
    pub(crate) fn poll_next_enqueued(&mut self, target_cid: u64) -> Result<bool, NetworkError> {
        log::trace!(target: "lusna", "Polling next for {}", target_cid);
        let secrecy_mode = self.get_secrecy_mode(target_cid).ok_or(NetworkError::InternalError("Secrecy mode not loaded"))?;
        match secrecy_mode {
            SecrecyMode::BestEffort => {}

            SecrecyMode::Perfect => {
                // fetch_nand(false
                let update_in_progress = self.updates_in_progress.get(&target_cid).map(|r| r.fetch_nand(false, Ordering::SeqCst)).ok_or(NetworkError::InternalError("Update state not loaded in hashmap!"))?;

                // We have to make sure when this is called, it also sets update_in_progress to true to place a lock. We will also need to reinforce this via a force_mode inside the get_next_constructor fn in the crypt container
                // it's possible in high-stress loads, a new inbound packet triggers update_in_progress to true right after checking below. The fetch_nand w/false helps us achieve this
                if update_in_progress {
                    log::trace!(target: "lusna", "Cannot send packet at this time since update_in_progress"); // in this case, update will happen upon reception of TRUNCATE packet
                    return Ok(false);
                }

                let queue = self.enqueued_packets.entry(target_cid).or_default();
                log::trace!(target: "lusna", "Queue has: {} items", queue.len());
                // since we have a mutable lock on the session, no other attempts will happen. We can safely pop the front of the queue and rest assured that it won't be denied a send this time
                if let Some((ticket, packet, virtual_target, security_level)) = queue.pop_front() {
                    //std::mem::drop(enqueued);
                    return self.process_outbound_message(ticket, packet, virtual_target, security_level, true).map(|_| true);
                } else {
                    log::trace!(target: "lusna", "NO packets enqueued for target {}", target_cid);
                }
            }
        }

        Ok(false)
    }

    fn enqueue_packet(&mut self, target_cid: u64, ticket: Ticket, packet: SecureProtocolPacket, target: VirtualTargetType, security_level: SecurityLevel) {
        self.enqueued_packets
            .entry(target_cid)
            .or_default()
            .push_back((ticket, packet, target, security_level))
    }

    fn has_enqueued(&self, target_cid: u64) -> bool {
        self.enqueued_packets.get(&target_cid).map(|r| r.front().is_some()).unwrap_or(false)
    }


    #[allow(unused_results)]
    pub(crate) fn process_outbound_message(&mut self, ticket: Ticket, packet: SecureProtocolPacket, virtual_target: VirtualTargetType, security_level: SecurityLevel, called_from_poll: bool) -> Result<(), NetworkError> {
        let this = self;

        if this.state.load(Ordering::Relaxed) != SessionState::Connected {
            Err(NetworkError::Generic(format!("Attempted to send data (ticket: {}) outbound, but the session is not connected", ticket)))
        } else {
            // first, make sure that there aren't already packets in the queue (unless we were called from the poll, in which case, we are getting the latest version)
            let secrecy_mode = this.get_secrecy_mode(virtual_target.get_target_cid()).ok_or(NetworkError::InternalError("Secrecy mode not loaded"))?;
            let cnac = this.cnac.as_ref().unwrap();

            let time_tracker = this.time_tracker.clone();

            if secrecy_mode == SecrecyMode::Perfect && !called_from_poll {
                //let mut enqueued = inner_mut!(this.enqueued_packets);
                if this.has_enqueued(virtual_target.get_target_cid()) || this.updates_in_progress.get(&virtual_target.get_target_cid()).map(|r| r.load(Ordering::SeqCst)).ok_or_else(|| NetworkError::InternalError("Update in progress not loaded for client"))? {
                    // If there are packets enqueued, it doesn't matter if an update is in progress or not. Queue this packet
                    //log::trace!(target: "lusna", "[ABX] enqueuing packet for {:?}", virtual_target);
                    this.enqueue_packet(virtual_target.get_target_cid(), ticket, packet, virtual_target, security_level);
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
                    let result = cnac.visit_mut(|mut inner| -> Result<_, NetworkError> {
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
                            let to_primary_stream = this.get_primary_stream().cloned().unwrap();
                            (GroupTransmitter::new_message(to_primary_stream, OBJECT_SINGLETON, RatchetPacketCrafterContainer::new(latest_hyper_ratchet, alice_constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, implicated_cid)
                        }

                        Either::Right(packet) => {
                            // store inside hashmap
                            //let mut enqueued_packets = inner_mut!(this.enqueued_packets);
                            log::trace!(target: "lusna", "[ATC] Enqueuing c2s packet");
                            this.enqueue_packet(C2S_ENCRYPTION_ONLY, ticket, packet, virtual_target, security_level);
                            return Ok(());
                        }
                    }
                }

                VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => {
                    log::trace!(target: "lusna", "Maybe sending HyperLAN peer ({}) <-> HyperLAN Peer ({})", implicated_cid, target_cid);
                    // here, we don't use the base session's PQC. Instead, we use the vconn's pqc and Toolset
                    let default_primary_stream = this.get_primary_stream().cloned().unwrap();

                    if let Some(vconn) = this.active_virtual_connections.get_mut(&target_cid) {
                        if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                            //let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                            let to_primary_stream_preferred = endpoint_container.get_direct_p2p_primary_stream().cloned().unwrap_or_else(|| {
                                log::trace!(target: "lusna", "Reverting to primary stream since p2p conn not loaded");
                                if cfg!(feature = "localhost-testing-assert-no-proxy") {
                                    log::error!(target: "lusna", "*** Feature flag asserted no proxying, yet, message requires proxy ***");
                                    std::process::exit(1);
                                }

                                default_primary_stream
                            });
                            //let to_primary_stream_preferred = this.to_primary_stream.clone().unwrap();
                            let latest_usable_ratchet = endpoint_container.endpoint_crypto.get_hyper_ratchet(None).unwrap().clone();
                            latest_usable_ratchet.verify_level(Some(security_level)).map_err(|_err| NetworkError::Generic(format!("Invalid security level. The maximum security level for this session is {:?}", latest_usable_ratchet.get_default_security_level())))?;
                            let constructor = endpoint_container.endpoint_crypto.get_next_constructor(called_from_poll);

                            match secrecy_mode {
                                SecrecyMode::BestEffort => {
                                    let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                                    (GroupTransmitter::new_message(to_primary_stream_preferred, OBJECT_SINGLETON, RatchetPacketCrafterContainer::new(latest_usable_ratchet, constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, target_cid)
                                }

                                SecrecyMode::Perfect => {
                                    // Note: we can't just add/send here. What if there are packets in the queue? We thus must poll before calling the below function
                                    if constructor.is_some() {
                                        let group_id = endpoint_container.endpoint_crypto.get_and_increment_group_id();
                                        log::trace!(target: "lusna", "[Perfect] will send group {}", group_id);
                                        (GroupTransmitter::new_message(to_primary_stream_preferred, OBJECT_SINGLETON,RatchetPacketCrafterContainer::new(latest_usable_ratchet, constructor), packet, security_level, group_id, ticket, time_tracker).ok_or_else(|| NetworkError::InternalError("Unable to create the outbound transmitter"))?, group_id, target_cid)
                                    } else {
                                        //assert!(!called_from_poll);
                                        // Being called from poll should only happen when a packet needs to be sent, and is ready to be sent. Further, being called from the poll adds a lock ensuring it gets sent
                                        if called_from_poll {
                                            log::error!(target: "lusna", "Should not happen (CFP). {:?}", endpoint_container.endpoint_crypto.lock_set_by_alice.clone());
                                            std::process::exit(1); // for dev purposes
                                        }

                                        //std::mem::drop(state_container);
                                        log::trace!(target: "lusna", "[Perfect] will enqueue packet");
                                        //let mut enqueued_packets = inner_mut!(this.enqueued_packets);
                                        this.enqueue_packet(target_cid, ticket, packet, virtual_target, security_level);
                                        return Ok(());
                                    }
                                }
                            }
                        } else {
                            return Err(NetworkError::InternalError("Endpoint container not found"));
                        }
                    } else {
                        log::error!(target: "lusna", "Unable to find active vconn for the channel");
                        return Ok(());
                    }
                }

                _ => {
                    return Err(NetworkError::InvalidRequest("HyperWAN functionality not yet implemented"));
                }
            };


            // We manually send the header. The tails get sent automatically
            log::trace!(target: "lusna", "[message] Sending GROUP HEADER through primary stream for group {} as {}", group_id, this.is_server.then(|| "Server").unwrap_or("Client"));
            let group_len = transmitter.get_total_plaintext_bytes();
            transmitter.transmit_group_header(virtual_target)?;

            //this.transfer_stats += TransferStats::new(timestamp, group_len as isize);

            let outbound_container = OutboundTransmitterContainer::new(None, transmitter, group_len, 1, 0, ticket);
            // The payload packets won't be sent until a GROUP_HEADER_ACK is received
            // NOTE: Ever since using GroupKeys, we use either the implicated_cid (for client -> server conns) or target_cids (for peer conns)
            let key = GroupKey::new(target_cid, group_id);
            //inner_mut!(this.state_container).outbound_transmitters.insert(key, outbound_container);
            this.outbound_transmitters.insert(key, outbound_container);

            //std::mem::drop(state_container);

            this.queue_handle.insert_ordinary(group_id as usize, target_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                if let Some(transmitter) = state_container.outbound_transmitters.get(&key) {
                    let ref transmitter = transmitter.burst_transmitter.group_transmitter;
                    if transmitter.has_expired(GROUP_EXPIRE_TIME_MS) {
                        if state_container.meta_expiry_state.expired() {
                            log::warn!(target: "lusna", "Outbound group {} has expired; dropping from map", group_id);
                            QueueWorkerResult::Complete
                        } else {
                            log::trace!(target: "lusna", "Other outbound groups being processed; patiently awaiting group {}", group_id);
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

    #[allow(unused_results)]
    pub(crate) fn initiate_drill_update(&mut self, timestamp: i64, virtual_target: VirtualTargetType, ticket: Option<Ticket>) -> Result<(), NetworkError> {
        if !self.meta_expiry_state.expired() {
            log::trace!(target: "lusna", "Drill update will be omitted since packets are being sent");
            return Ok(());
        }

        let cnac = self.cnac.clone().ok_or_else(||NetworkError::InternalError("CNAC not loaded"))?;
        let session_security_settings = self.session_security_settings.clone().unwrap();
        let security_level = session_security_settings.security_level;
        let ref default_primary_stream = self.get_primary_stream().cloned().ok_or_else(||NetworkError::InternalError("Primary stream not loaded"))?;

        match virtual_target {
            VirtualConnectionType::HyperLANPeerToHyperLANServer(_) => {
                let (ratchet, res) = cnac.visit_mut(|mut inner| {
                    let ratchet = inner.crypt_container.get_hyper_ratchet(None).cloned().unwrap();
                    (ratchet, inner.crypt_container.get_next_constructor(false))
                });

                match res {
                    Some(alice_constructor) => {
                        let stage0_packet = hdp_packet_crafter::do_drill_update::craft_stage0(&ratchet, alice_constructor.stage0_alice(), timestamp, C2S_ENCRYPTION_ONLY, security_level);
                        self.ratchet_update_state.alice_hyper_ratchet = Some(alice_constructor);
                        let to_primary_stream = self.get_primary_stream().unwrap();
                        let kernel_tx = &self.kernel_tx;
                        HdpSession::send_to_primary_stream_closure(to_primary_stream, kernel_tx, stage0_packet, ticket)
                    }

                    None => {
                        log::trace!(target: "lusna", "Won't perform update b/c concurrent update occurring");
                        Ok(())
                    }
                }
            }

            VirtualConnectionType::HyperLANPeerToHyperLANPeer(_, peer_cid) => {
                const MISSING: NetworkError = NetworkError::InvalidRequest("Peer not connected");
                let endpoint_container = &mut self.active_virtual_connections.get_mut(&peer_cid).ok_or(MISSING)?.endpoint_container.as_mut().ok_or(MISSING)?;
                let crypt = &mut endpoint_container.endpoint_crypto;
                let alice_constructor = crypt.get_next_constructor(false);
                let latest_hyper_ratchet = crypt.get_hyper_ratchet(None).cloned().ok_or(NetworkError::InternalError("Ratchet not loaded"))?;

                match alice_constructor {
                    Some(alice_constructor) => {
                        let to_primary_stream_preferred = endpoint_container.get_direct_p2p_primary_stream().unwrap_or_else(|| default_primary_stream);
                        let stage0_packet = hdp_packet_crafter::do_drill_update::craft_stage0(&latest_hyper_ratchet, alice_constructor.stage0_alice(), timestamp, peer_cid, security_level);

                        to_primary_stream_preferred.unbounded_send(stage0_packet).map_err(|err| NetworkError::Generic(err.to_string()))?;

                        if let Some(_) = self.ratchet_update_state.p2p_updates.insert(peer_cid, alice_constructor) {
                            log::error!(target: "lusna", "Overwrote pre-existing peer kem. Report to developers");
                        }

                        // to_primary_stream_preferred.unbounded_send(stage0_packet).map_err(|err| NetworkError::Generic(err.to_string()))
                        Ok(())
                    }

                    None => {
                        log::trace!(target: "lusna", "Won't perform update b/c concurrent update occurring");
                        Ok(())
                    }
                }
            }

            _ => {
                Err(NetworkError::InternalError("HyperWAN Not implemented"))
            }
        }
    }

    pub(crate) fn process_outbound_broadcast_command(&self, ticket: Ticket, command: &GroupBroadcast) -> Result<(), NetworkError> {
        if self.state.load(Ordering::Relaxed) != SessionState::Connected {
            return Err(NetworkError::InternalError("Session not connected"));
        }

        let cnac = self.cnac.as_ref().unwrap();
        let security_level = self.session_security_settings.map(|r| r.security_level).clone().unwrap();
        let to_primary_stream = self.get_primary_stream().unwrap();

        cnac.borrow_hyper_ratchet(None, |hyper_ratchet_opt| {
            let hyper_ratchet = hyper_ratchet_opt.ok_or(NetworkError::InternalError("Hyper ratchet missing"))?;
            let timestamp = self.time_tracker.get_global_time_ns();
            let packet = match command {
                GroupBroadcast::Create(..) |
                GroupBroadcast::End(_) |
                GroupBroadcast::Kick(..) |
                GroupBroadcast::Message(..) |
                GroupBroadcast::Add(..) |
                GroupBroadcast::AcceptMembership(_) |
                GroupBroadcast::RequestJoin(..) |
                GroupBroadcast::LeaveRoom(_) => {
                    hdp_packet_crafter::peer_cmd::craft_group_message_packet(hyper_ratchet, command, ticket, C2S_ENCRYPTION_ONLY, timestamp, security_level)
                }

                n => {
                    return Err(NetworkError::Generic(format!("{:?} is not a valid group broadcast request", &n)));
                }
            };

            to_primary_stream.unbounded_send(packet).map_err(|err| NetworkError::Generic(err.to_string()))
        })
    }

    pub(crate) fn setup_group_channel_endpoints(&mut self, key: MessageGroupKey, ticket: Ticket, session: &HdpSession) -> Result<GroupChannel, NetworkError> {
        let (tx, rx) = unbounded();
        let implicated_cid = self.cnac.as_ref().map(|r| r.get_cid()).ok_or_else(|| NetworkError::InternalError("CNAC not loaded"))?;

        if self.group_channels.contains_key(&key) {
            return Err(NetworkError::InternalError("Group channel already exists locally"))
        }

        let _ = self.group_channels.insert(key, tx);

        Ok(GroupChannel::new(session.state_container.clone(), key, ticket, implicated_cid, rx))
    }

    fn get_primary_stream(&self) -> Option<&OutboundPrimaryStreamSender> {
        self.c2s_channel_container.as_ref().map(|r| &r.primary_outbound_tx)
    }
}