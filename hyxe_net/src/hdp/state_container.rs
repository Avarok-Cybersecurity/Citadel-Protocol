use std::collections::{HashMap, BTreeMap};
use std::fmt::{Display, Formatter};
use std::ops::RangeInclusive;
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, ConstructorType};
use crate::hdp::hdp_packet_processor::primary_group_packet::attempt_kem_as_alice_finish;

use crate::hdp::outbound_sender::{UnboundedSender, unbounded, BoundedSender};
use zerocopy::LayoutVerified;

use hyxe_crypt::net::crypt_splitter::{GroupReceiver, GroupReceiverConfig, GroupReceiverStatus, GroupSenderDevice};
use hyxe_nat::time_tracker::TimeTracker;
use hyxe_user::client_account::ClientNetworkAccount;

use crate::constants::{GROUP_TIMEOUT_MS, INDIVIDUAL_WAVE_TIMEOUT_MS, KEEP_ALIVE_INTERVAL_MS, MAX_OUTGOING_UNPROCESSED_REQUESTS, MAX_INCOMING_UNPROCESSED_REQUESTS};
use crate::error::NetworkError;
use crate::hdp::hdp_packet::HdpHeader;
use crate::hdp::hdp_packet::packet_flags;
use crate::hdp::hdp_packet_crafter::GroupTransmitter;
use crate::hdp::hdp_packet_processor::includes::{Duration, Instant, SocketAddr, HdpSession};
use crate::hdp::hdp_server::{HdpServerResult, Ticket, HdpServerRemote, SecrecyMode};
use crate::hdp::outbound_sender::{OutboundUdpSender, OutboundTcpSender};
use crate::hdp::state_subcontainers::connect_state_container::ConnectState;
use crate::hdp::state_subcontainers::deregister_state_container::DeRegisterState;
use crate::hdp::state_subcontainers::drill_update_container::DrillUpdateState;
use crate::hdp::state_subcontainers::preconnect_state_container::PreConnectState;
use crate::hdp::state_subcontainers::register_state_container::RegisterState;
use hyxe_crypt::drill::SecurityLevel;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::hdp::peer::channel::PeerChannel;
use crate::hdp::state_subcontainers::peer_kem_state_container::PeerKemStateContainer;
use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus};
use crate::hdp::file_transfer::{VirtualFileMetadata, FileTransferStatus};
use tokio::io::{BufWriter, AsyncWriteExt};
use hyxe_crypt::sec_bytes::SecBuffer;
use crate::hdp::peer::p2p_conn_handler::DirectP2PRemote;
use crate::functional::IfEqConditional;
use futures::{StreamExt, SinkExt};
use hyxe_crypt::hyper_ratchet::{HyperRatchet, Ratchet};
use hyxe_fs::prelude::SyncIO;
use crate::hdp::state_subcontainers::meta_expiry_container::MetaExpiryState;
use crate::hdp::peer::peer_layer::PeerConnectionType;
use hyxe_fs::env::DirectoryStore;
use crate::hdp::misc::dual_rwlock::DualRwLock;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::misc::dual_cell::DualCell;

#[derive(Clone)]
pub struct StateContainer {
    pub inner: DualRwLock<StateContainerInner>
}

//define_outer_struct_wrapper!(StateContainer, StateContainerInner);

/// For keeping track of the stages
pub struct StateContainerInner {
    pub(super) pre_connect_state: PreConnectState,
    pub(super) hdp_server_remote: HdpServerRemote,
    /// No hashmap here, since register is only for a single target
    pub(super) register_state: RegisterState,
    /// No hashmap here, since connect is only for a single target
    pub(super) connect_state: ConnectState,
    pub(super) drill_update_state: DrillUpdateState,
    pub(super) deregister_state: DeRegisterState,
    pub(super) meta_expiry_state: MetaExpiryState,
    pub(super) network_stats: NetworkStats,
    pub(super) inbound_files: HashMap<FileKey, InboundFileTransfer>,
    pub(super) outbound_files: HashMap<FileKey, OutboundFileTransfer>,
    pub(super) inbound_groups: HashMap<GroupKey, GroupReceiverContainer>,
    pub(super) outbound_transmitters: HashMap<GroupKey, OutboundTransmitterContainer>,
    pub(super) peer_kem_states: HashMap<u64, PeerKemStateContainer>,
    pub(super) udp_sender: Option<OutboundUdpSender>,
    pub(super) kernel_tx: UnboundedSender<HdpServerResult>,
    pub(super) active_virtual_connections: HashMap<u64, VirtualConnection>,
    pub(super) provisional_direct_p2p_conns: HashMap<SocketAddr, DirectP2PRemote>,
    pub(super) c2s_channel_container: Option<C2SChannelContainer>,
    pub(crate) keep_alive_timeout_ns: i64
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
    pub stream_to_hd: UnboundedSender<Vec<u8>>
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
    pub is_active: Arc<AtomicBool>,
    // this is Some for server, None for endpoints
    pub sender: Option<(Option<OutboundUdpSender>, OutboundTcpSender)>,
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
    // this is only loaded if STUN-like NAT-traversal works
    pub(crate) default_security_settings: SessionSecuritySettings,
    pub(crate) direct_p2p_remote: Option<DirectP2PRemote>,
    pub(crate) endpoint_crypto: PeerSessionCrypto<R>,
    to_channel: BoundedSender<SecBuffer>,
    pub(crate) order_map: DualRwLock<BTreeMap<u64, SecBuffer>>,
    #[allow(dead_code)]
    pub(crate) peer_socket_addr: SocketAddr,
    pub(crate) last_delivered_message: DualCell<u64>
}

pub struct C2SChannelContainer {
    to_channel: BoundedSender<SecBuffer>,
    pub(crate) order_map: DualRwLock<BTreeMap<u64, SecBuffer>>,
    pub(crate) last_delivered_message: DualCell<u64>
}

impl EndpointChannelContainer {
    pub fn get_direct_p2p_primary_stream(&self) -> Option<&OutboundTcpSender> {
        Some(&self.direct_p2p_remote.as_ref()?.p2p_primary_stream)
    }
}

impl<R: Ratchet> Drop for VirtualConnection<R> {
    fn drop(&mut self) {
        self.is_active.store(false, Ordering::SeqCst);
        /*if let Some(endpoint_container) = self.endpoint_container.take() {
            // next, since the is_active field is false, send an empty vec through the channel
            // in order to wake the receiving end, thus causing a poll, thus ending it
            if let Err(_) = endpoint_container.to_channel.sen(SecBuffer::empty()) {}
        }*/
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
pub const HYPERLAN_PEER_TO_HYPERLAN_PEER: u8 = 0;
pub const HYPERLAN_PEER_TO_HYPERWAN_PEER: u8 = 1;
pub const HYPERLAN_PEER_TO_HYPERLAN_SERVER: u8 = 2;
pub const HYPERLAN_PEER_TO_HYPERWAN_SERVER: u8 = 3;
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

define_outer_struct_wrapper!(GroupSender, GroupSenderDevice);

pub(crate) struct OutboundTransmitterContainer {
    ratchet_constructor: Option<HyperRatchetConstructor>,
    burst_transmitter: Option<GroupTransmitter>,
    pub reliability_container: GroupSender,
    // in the case of file transfers, it is desirable to wake-up the async task
    // that enqueues the next group
    object_notifier: Option<UnboundedSender<()>>,
    waves_in_current_window: usize,
    wave_acks_in_window_received: usize,
    enqueued_next_range: Option<RangeInclusive<u32>>,
    group_plaintext_length: usize,
    transmission_start_time: Instant,
    parent_object_total_groups: usize,
    relative_group_id: u32,
    ticket: Ticket,
    pub has_begun: bool
}

impl OutboundTransmitterContainer {
    pub fn new(object_notifier: Option<UnboundedSender<()>>, mut burst_transmitter: GroupTransmitter, group_plaintext_length: usize, parent_object_total_groups: usize, relative_group_id: u32, ticket: Ticket) -> Self {
        let reliability_container = burst_transmitter.get_reliability_container();
        let ratchet_constructor = burst_transmitter.hyper_ratchet_container.base_constructor.take();
        let burst_transmitter = Some(burst_transmitter);
        let transmission_start_time = Instant::now();
        let has_begun = false;

        Self { ratchet_constructor, has_begun, relative_group_id, ticket, parent_object_total_groups, transmission_start_time, group_plaintext_length, object_notifier, burst_transmitter, reliability_container, waves_in_current_window: 0, wave_acks_in_window_received: 0, enqueued_next_range: None }
    }

    /// returns Some if the window finished transmitting
    pub fn on_wave_ack_received(&mut self, waves_in_next_window: Option<RangeInclusive<u32>>) -> Option<RangeInclusive<u32>> {
        self.wave_acks_in_window_received += 1;
        if self.wave_acks_in_window_received != self.waves_in_current_window {
            // it is possible that this WAVE_ACK had a range inscribed in it, but arrived earlier than the other wave acks.
            // in this case, store the range for later without affecting the waves_in_current_window value
            if let Some(waves_in_next_window) = waves_in_next_window {
                self.enqueued_next_range = Some(waves_in_next_window);
            }

            None
        } else {
            self.wave_acks_in_window_received = 0;
            // update the waves expected in the next window
            if let Some(waves_in_next_window) = waves_in_next_window {
                // this means this WAVE_ACK arrived in good order
                self.waves_in_current_window = waves_in_next_window.clone().count();
                Some(waves_in_next_window)
            } else {
                // this means that this WAVE_ACK didn't come with the range, however, by necessity a previous ack had to (or panic)
                let waves_in_next_window = self.enqueued_next_range.take().unwrap();
                self.waves_in_current_window = waves_in_next_window.clone().count();
                Some(waves_in_next_window)
            }
        }
    }
}

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

    /// Returns Some(next_window) if the window is finished
    /// Called by: Bob(receiver).
    /// Called when: right before sending a WAVE_ACK
    pub fn on_wave_finished(&mut self) -> Option<RangeInclusive<u32>> {
        // increase the next window size by 1
        self.waves_in_window_finished += 1;
        self.next_window_size += 1;
        if self.waves_in_window_finished != self.current_window.clone().count() {
            None
        } else {
            self.waves_in_window_finished = 0;
            Some(self.update_current_window())
        }
    }

    /// Called by Bob prior to sending a DO_RETRANSMISSION. This updates the next window size
    pub fn on_retransmission_needed(&mut self) {
        if self.next_window_size > self.max_window_size {
            self.max_window_size = self.next_window_size;
        }
        // if the next size is 1, this will remain 1
        //self.next_window_size = self.next_window_size.div_ceil(&2);
        //self.next_window_size = self.next_window_size * 0.95;
        let last_next_window_size = self.next_window_size;
        // cut by 50%
        self.next_window_size = std::cmp::max((self.next_window_size as f32 / 2.0f32) as usize, 1);
        log::warn!("Decreased anticipated window size from {} to {}", last_next_window_size, self.next_window_size);
    }

    /// This should ONLY be called once the waves_in_window_finished equals the waves in the current window
    /// (i.e., the window finished)
    pub fn update_current_window(&mut self) -> RangeInclusive<u32> {
        let last_window_size = self.current_window.clone().count();
        // to take into account any retransmission necessary
        let next_length = self.next_window_size;
        let start = *self.current_window.end() + 1;
        // the RHS needs to be -1 ... if n=2 waves, then k=1 is the max
        let end = std::cmp::min(start + next_length as u32, (self.receiver.get_wave_count() - 1 ) as u32);
        self.last_window_size = last_window_size;
        self.current_window = start..=end;
        self.window_drift = self.current_window.clone().count() as isize - self.last_window_size as isize;
        log::info!("Sliding window range update: {}..={} | Drift: {}", start, end, self.window_drift);
        log::info!("Sliding window | last window: {} | current window: {}", self.last_window_size, next_length);
        start..=end
    }
}

impl StateContainer {
    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
/// (thus bypassing the kernel)
    pub async fn forward_data_to_channel(&self, target_cid: u64, group_id: u64, data: SecBuffer) -> bool {
        let pass_message = |last_delivered_message: DualCell<u64>, mut to_channel: BoundedSender<SecBuffer>, order_map: DualRwLock<BTreeMap<u64, SecBuffer>>| async move {
            async fn send(to_channel: &mut BoundedSender<SecBuffer>, data: SecBuffer) -> bool {
                match to_channel.send(data).await {
                    Ok(_) => {
                        //log::info!("[Channel] Success sending message to channel");
                        true
                    }

                    Err(err) => {
                        log::error!("[Channel] TrySendError: Unable to send data to channel. Reason: {}", err.to_string());
                        false
                    }
                }
            }

            // before forwarding, we need to ensure ordered delivery
            if let Some(last_message_group) = last_delivered_message.get() {
                if last_message_group + 1 == group_id {
                    // is in sequential order; we can just send it
                    last_delivered_message.set(Some(group_id));

                    if send(&mut to_channel, data).await {
                        log::info!("PUSHING Group {} to {}", group_id, target_cid);
                        // first send worked. Now, send all in the order map (if available) until we hit discontinuity
                        loop {
                            let next_group = last_message_group + 1;
                            let mut order_map = inner_mut!(order_map);
                            if let Some(next_packet) = order_map.remove(&next_group) {
                                log::info!("Continuity hit for {}", next_group);
                                // continuity; send item and update last ticket
                                last_delivered_message.set(Some(next_group));

                                log::info!("[loop] PUSHING Group {} to {}", next_group, target_cid);
                                if !send(&mut to_channel, next_packet).await {
                                    return false;
                                }

                            } else {
                                log::info!("Reached discontinuity. Will await future packets ...");
                                // hit discontinuity; return. We need to wait for more packets to come
                                return true;
                            }
                        }
                    } else {
                        false
                    }
                } else {
                    log::info!("Packet {} NOT in order. Will send when other packets arrive", group_id);
                    // not in order. Store in map
                    let mut order_map = inner_mut!(order_map);
                    let prev = order_map.insert(group_id, data);
                    if prev.is_some() {
                        log::error!("Overwrote previous value!! {}", group_id);
                    }
                    true
                }
            } else {
                // this is the first message. Just set the ticket and send
                last_delivered_message.set(Some(group_id));
                send(&mut to_channel, data).await
            }
        };

        let this = inner!(self.inner);

        if target_cid == 0 {
            if let Some(c2s_container) = this.c2s_channel_container.as_ref() {
                let C2SChannelContainer {
                    last_delivered_message,
                    to_channel,
                    order_map,
                    ..
                } = c2s_container;

                let last_delivered_message = last_delivered_message.clone();
                let to_channel = to_channel.clone();
                let order_map = order_map.clone();

                std::mem::drop(this);

                return pass_message(last_delivered_message, to_channel, order_map).await;
            }
        } else {
            if let Some(vconn) = this.active_virtual_connections.get(&target_cid) {
                if let Some(channel) = vconn.endpoint_container.as_ref() {
                    let EndpointChannelContainer {
                        last_delivered_message,
                        to_channel,
                        order_map,
                        ..
                    } = channel;

                    let last_delivered_message = last_delivered_message.clone();
                    let to_channel = to_channel.clone();
                    let order_map = order_map.clone();

                    std::mem::drop(this);

                    return pass_message(last_delivered_message, to_channel, order_map).await;
                }
            }
        }

        false
    }
}

impl StateContainerInner {
    /// Creates a new container
    pub fn new(kernel_tx: UnboundedSender<HdpServerResult>, hdp_server_remote: HdpServerRemote, keep_alive_timeout_ns: i64) -> StateContainer {
        let inner = Self { c2s_channel_container: None, keep_alive_timeout_ns, hdp_server_remote, meta_expiry_state: Default::default(), pre_connect_state: Default::default(), udp_sender: None, deregister_state: Default::default(), drill_update_state: Default::default(), active_virtual_connections: Default::default(), network_stats: Default::default(), kernel_tx, register_state: packet_flags::cmd::aux::do_register::STAGE0.into(), connect_state: packet_flags::cmd::aux::do_connect::STAGE0.into(), inbound_groups: HashMap::new(), outbound_transmitters: HashMap::new(), peer_kem_states: HashMap::new(), inbound_files: HashMap::new(), outbound_files: HashMap::new(), provisional_direct_p2p_conns: HashMap::new() };
        StateContainer { inner: DualRwLock::from(inner) }
    }

    /// The inner P2P handles will get dropped, causing the connections to end
    pub fn end_connections(&mut self) {
        self.active_virtual_connections.clear();
    }

    /// Returns true if the remote was loaded, false if there's already a connection from the addr
    /// being loaded
    pub fn load_provisional_direct_p2p_remote(&mut self, addr: SocketAddr, remote: DirectP2PRemote) -> bool {
        if !self.provisional_direct_p2p_conns.contains_key(&addr) {
            self.provisional_direct_p2p_conns.insert(addr, remote).is_none()
        } else {
            false
        }
    }

    /// In order for the upgrade to work, the peer_addr must be reflective of the peer_addr present when
    /// receiving the packet. As such, the direct p2p-stream MUST have sent the packet
    pub fn upgrade_provisional_direct_p2p_connection(&mut self, peer_addr: SocketAddr, peer_cid: u64, possible_verified_conn: Option<SocketAddr>) -> bool {
        if let Some(provisional) = self.provisional_direct_p2p_conns.remove(&peer_addr) {
            if let Some(vconn) = self.active_virtual_connections.get_mut(&peer_cid) {
                if let Some(endpoint_container) = vconn.endpoint_container.as_mut() {
                    log::info!("UPGRADING {} conn type", provisional.from_listener.if_eq(true, "listener").if_false("client"));
                    if let Some(_) = endpoint_container.direct_p2p_remote.replace(provisional) {
                        log::warn!("Dropped previous p2p remote during upgrade process");
                    }

                    if let Some(previous_conn) = possible_verified_conn {
                        if let Some(_) = self.provisional_direct_p2p_conns.remove(&previous_conn) {
                            log::info!("Dropped previous conn due to initiator preference");
                        }
                    }
                    // now, we need to check to see if we need to drop an older conn

                    return true;
                }
            }
        }

        false
    }

    #[allow(unused_results)]
    pub fn insert_new_peer_virtual_connection_as_endpoint(&mut self, map: &mut HashMap<u64, Arc<AtomicBool>>, peer_socket_addr: SocketAddr, default_security_settings: SessionSecuritySettings, channel_ticket: Ticket, target_cid: u64, connection_type: VirtualConnectionType, endpoint_crypto: PeerSessionCrypto) -> PeerChannel {
        let (channel_tx, channel_rx) = BoundedSender::new(MAX_INCOMING_UNPROCESSED_REQUESTS);
        let is_active = Arc::new(AtomicBool::new(true));

        map.insert(target_cid, endpoint_crypto.update_in_progress.clone());

        let peer_channel = PeerChannel::new(self.hdp_server_remote.clone(), target_cid, connection_type, channel_ticket, default_security_settings.security_level, is_active.clone(), channel_rx);
        let order_map = DualRwLock::from(BTreeMap::new());

        let endpoint_container = Some(EndpointChannelContainer {
            default_security_settings,
            last_delivered_message: Default::default(),
            order_map,
            direct_p2p_remote: None,
            endpoint_crypto,
            to_channel: channel_tx,
            peer_socket_addr
        });

        let vconn = VirtualConnection {
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
    pub fn init_new_c2s_virtual_connection(&mut self, cnac: &ClientNetworkAccount, map: &mut HashMap<u64, Arc<AtomicBool>>, security_level: SecurityLevel, channel_ticket: Ticket, implicated_cid: u64) -> PeerChannel {
        let (channel_tx, channel_rx) = BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS);
        let is_active = Arc::new(AtomicBool::new(true));


        let peer_channel = PeerChannel::new(self.hdp_server_remote.clone(), implicated_cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), channel_ticket, security_level, is_active.clone(), channel_rx);
        let order_map = DualRwLock::from(BTreeMap::new());

        let c2s = C2SChannelContainer {
            to_channel: channel_tx,
            order_map,
            last_delivered_message: Default::default()
        };

        self.c2s_channel_container = Some(c2s);

        map.insert(0, cnac.visit(|r| r.crypt_container.update_in_progress.clone()));

        peer_channel
    }

    /// Note: the `endpoint_crypto` container needs to be Some in order for transfer to occur between peers w/o encryption/decryption at the center point
    /// GROUP packets and PEER_CMD::CHANNEL packets bypass the central node's encryption/decryption phase
    pub fn insert_new_virtual_connection(&mut self, target_cid: u64, connection_type: VirtualConnectionType, target_udp_sender: Option<OutboundUdpSender>, target_tcp_sender: OutboundTcpSender) {
        let val = VirtualConnection { endpoint_container: None, sender: Some((target_udp_sender, target_tcp_sender)), connection_type, is_active: Arc::new(AtomicBool::new(true)) };
        if self.active_virtual_connections.insert(target_cid, val).is_some() {
            log::warn!("Inserted a virtual connection. but overwrote one in the process. Report to developers");
        }

        log::info!("Vconn {} -> {} established", connection_type.get_implicated_cid(), target_cid);
    }

    /// Once NAT-traversal succeeds between two peers, this should be called
    pub fn update_direct_p2p_remote(&mut self, target_cid: u64, remote: Option<DirectP2PRemote>) -> bool {
        if let Some(endpoint_container) = self.active_virtual_connections.get_mut(&target_cid) {
            if let Some(container) = endpoint_container.endpoint_container.as_mut() {
                container.direct_p2p_remote = remote;
                return true;
            }
        }

        false
    }

    /// Determines whether to use the default primary stream or the direct p2p primary stream
    pub fn get_direct_p2p_primary_stream(active_virtual_connections: &HashMap<u64, VirtualConnection>, target_cid: u64) -> Option<&OutboundTcpSender> {
        if target_cid != 0 {
            let endpoint_container = active_virtual_connections.get(&target_cid)?;
            let container = endpoint_container.endpoint_container.as_ref()?;
            container.direct_p2p_remote.as_ref().map(|res| &res.p2p_primary_stream)
        } else {
            None
        }
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

        //log::info!("KEEP ALIVE subsystem statistics: Ping: {}ms | RTT: {}ms | Jitter: {}ms", (ping_ns as f64/1_000_000f64) as f64, (self.network_stats.rtt_ns.clone().unwrap_or(0) as f64/1_000_000f64) as f64, (jitter_ns as f64/1000000f64) as f64);
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
                    log::error!("The GROUP HEADER implied the existence of a file transfer, but the key {:?} does not map to anything", &file_key);
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
            log::error!("Duplicate group HEADER detected ({})", group_id);
            None
        }
    }

    /// This creates an entry in the inbound_files hashmap
    #[allow(unused_results)]
    pub fn on_file_header_received(&mut self, header: &LayoutVerified<&[u8], HdpHeader>, virtual_target: VirtualTargetType, metadata: VirtualFileMetadata, dirs: &DirectoryStore) -> bool {
        let key = FileKey::new(header.session_cid.get(), metadata.object_id);
        let ticket = header.context_info.get().into();

        if !self.inbound_files.contains_key(&key) {
            let (stream_to_hd, stream_to_hd_rx) = unbounded::<Vec<u8>>();
            let name = metadata.name.clone();
            let save_location = dirs.inner.read().hyxe_virtual_dir.clone();
            let save_location = format!("{}{}", save_location, name);
            if let Ok(file) = std::fs::File::create(&save_location) {
                let file = tokio::fs::File::from_std(file);
                log::info!("Will stream virtual file to: {}", &save_location);
                // now that the InboundFileTransfer is loaded, we just need to spawn the async task that takes the results and streams it to the HD.
                // This is safe since no mutation/reading on the state container or session takes place. This only streams to the hard drive without interrupting
                // the HdpServer's single thread. This will end once a None signal is sent through
                tokio::spawn(async move {
                    let mut writer = BufWriter::new(file);
                    let mut reader = tokio_util::io::StreamReader::new(tokio_stream::wrappers::UnboundedReceiverStream::new(stream_to_hd_rx).map(|r| Ok(std::io::Cursor::new(r)) as Result<std::io::Cursor<Vec<u8>>, std::io::Error>));

                    if let Err(err) = tokio::io::copy(&mut reader, &mut writer).await {
                        log::error!("Error while copying from reader to writer: {}", err);
                    }

                    match writer.shutdown().await {
                        Ok(()) => {
                            log::info!("Successfully synced file to HD");
                        },
                        Err(err) => {
                            log::error!("Unable to shut down streamer: {}", err);
                        },
                    };
                });

                let entry = InboundFileTransfer {
                    last_group_finish_time: Instant::now(),
                    last_group_window_len: 0,
                    object_id: metadata.object_id,
                    total_groups: metadata.group_count,
                    ticket,
                    groups_rendered: 0,
                    virtual_target,
                    metadata: metadata.clone(),
                    stream_to_hd
                };

                self.inbound_files.insert(key, entry);
                // finally, alert the kernel (receiver)
                let status = FileTransferStatus::ReceptionBeginning(metadata);
                let _ = self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(header.target_cid.get(), key, ticket, status));
                true
            } else {
                log::error!("Unable to obtain file handle to {}", &save_location);
                false
            }
        } else {
            log::error!("Duplicate file HEADER detected");
            false
        }
    }

    pub fn on_file_header_ack_received(&mut self, success: bool, implicated_cid: u64, ticket: Ticket, object_id: u32, v_target: VirtualTargetType) -> Option<()>{
        let key = match v_target {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => {
                // since the order hasn't flipped yet, get the implicated cid
                FileKey::new(implicated_cid, object_id)
            }

            VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) =>{
                FileKey::new(implicated_cid, object_id)
            }

            _ => {
                log::error!("HyperWAN functionality not yet enabled");
                return None;
            }
        };

        if success {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.get_mut(&key) {
                // start the async task pulling from the async cryptscrambler
                file_transfer.start.take()?.send(true).ok()?;
                // alert the kernel that file transfer has begun
                self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(implicated_cid, key, ticket, FileTransferStatus::TransferBeginning)).ok()?;
            } else {
                log::error!("Attempted to obtain OutboundFileTransfer for {:?}, but it didn't exist", key);
            }
        } else {
            // remove the inbound file transfer, send the signals to end async loops, and tell the kernel
            if let Some(file_transfer) = self.outbound_files.remove(&key) {
                // stop the async cryptscrambler
                file_transfer.stop_tx?.send(()).ok()?;
                // stop the async task pulling from the async cryptscrambler
                file_transfer.start?.send(false).ok()?;
            } else {
                log::error!("Attempted to remove OutboundFileTransfer for {:?}, but it didn't exist", key);
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
    pub fn on_group_header_ack_received(&mut self, base_session_secrecy_mode: SecrecyMode, object_id: u32, peer_cid: u64, target_cid: u64, group_id: u64, next_window: Option<RangeInclusive<u32>>, transfer: KemTransferStatus, fast_msg: bool, cnac_sess: &ClientNetworkAccount) -> bool {
        // the target is where the packet came from (implicated_cid)
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
            if object_id != 0 || next_window.is_none() {
                // file-transfer, or TCP only mode since next_window is none. Use TCP
                if let Some(transmitter) = outbound_container.burst_transmitter.as_mut() {
                    return transmitter.transmit_tcp_file_transfer();
                } else {
                    log::error!("Transmitter already taken. Invalid request");
                }
            } else {
                // message. Use MQ-UDP
                if let Some(udp_sender) = self.udp_sender.as_ref() {
                    if let Some(transmitter) = outbound_container.burst_transmitter.as_mut() {
                        return if let Some(next_window) = next_window {
                            Self::transmit_window_udp(udp_sender, transmitter, next_window)
                        } else {
                            log::error!("MQ-UDP was signalled to be used, but the next window was not provided. Invalid request");
                            false
                        }
                    } else {
                        log::error!("Transmitter already taken. Invalid request");
                    }
                } else {
                    log::error!("MQ-UDP sender does not exist, yet, the request called for its existence");
                }
            }
        } else {
            log::error!("Outbound transmitter for {:?} does not exist", key);
        }

        true
    }

    /// Ensure that the packet has already been verified before using this function.
    ///
    /// At the end of every wave, a WAVE_TAIL is sent. This is used to verify successful transmission of each
    /// wave form
    ///
    /// This may return a WAVE_DO_RETRANSMISSION packet if there are missing packets
    ///
    /// Returns true if the sending process was a success, false otherwise
    ///
    /// safety: DO NOT borrow_mut the state container unless inside the spawn_local, otherwise a BorrowMutError will occur
    pub fn on_window_tail_received(&mut self, hyper_ratchet: &HyperRatchet, session_ref: &HdpSession, header: &LayoutVerified<&[u8], HdpHeader>, waves: RangeInclusive<u32>, time_tracker: &TimeTracker, to_primary_stream_orig: &OutboundTcpSender) -> bool {
        let group = header.group.get();
        let object_id = header.context_info.get() as u32;
        let security_level = header.security_level.into();
        let Self {
            active_virtual_connections,
            ..
        } = self;

        // When receiving the WINDOW_TAIL, we are the recipient. When we need to figure out the target_cid
        // we need to look at the header. Since proxied packets don't have their header changed throughout their flight
        // through the HyperLAN, the target_cid is just the header's original cid (for proxied packet). However, for
        // non-proxied packets, we use ZERO for the target_cid. To determine if the packet was proxied or not, just
        // check the header:
        let (resp_target_cid, to_primary_stream_preferred) = if header.target_cid.get() != 0 {
            // this is thus a proxied packet that has reached its destination
            (header.session_cid.get(), Self::get_direct_p2p_primary_stream(active_virtual_connections, header.target_cid.get()).cloned())
        } else {
            (0, Some(to_primary_stream_orig.clone()))
        };

        let to_primary_stream = to_primary_stream_preferred.unwrap_or_else(|| to_primary_stream_orig.clone());

        // the key's target is always going to be where the packet came from
        let key = GroupKey::new(header.session_cid.get(), group);
        if let Some(group_receiver) = self.inbound_groups.get_mut(&key) {
            let timestamp = time_tracker.get_global_time_ns();
            // when testing on localhost, there might be a negative ping.
            let ping = i64::abs(timestamp - header.timestamp.get());
            let wait_time = ping * 2;

            let missing_packets = waves.clone().into_iter().filter_map(|wave_id| group_receiver.receiver.get_missing_count_in_wave(wave_id)).sum::<usize>();
            if missing_packets != 0 {
                log::warn!("Missing packet in window (before wait): {}", missing_packets);
                // clone these items to allow them to live for 'static when moved into the closure below
                let session_ref = session_ref.clone();
                let hyper_ratchet = hyper_ratchet.clone();
                let time_tracker = time_tracker.clone();

                // Before doing anything, spawn a task to wait for completion

                let _ = spawn!(async move {
                    let wait_time = Duration::from_nanos(wait_time as u64);
                    log::trace!("ASYNC task waiting for {} nanos = {} millis", wait_time.as_nanos(), wait_time.as_millis());
                    tokio::time::sleep(wait_time).await;
                    // now, we can safely use the state container
                    let sess = inner!(session_ref);
                    let mut state_container = inner_mut!(sess.state_container);
                    if let Some(group_receiver) = state_container.inbound_groups.get_mut(&key) {

                        // since we are missing packets, decrease the next window.
                        // NOTE: Since this is the receiver, this node is responsible for setting the window size. As such, call the below function
                        // to adjust for network latency
                        let timestamp = time_tracker.get_global_time_ns();
                        let send_success = waves.clone().into_iter().filter_map(|wave_id_to_check| group_receiver.receiver.get_retransmission_vectors_for(wave_id_to_check, group, &hyper_ratchet))
                            .map(|packet_vectors| crate::hdp::hdp_packet_crafter::group::craft_wave_do_retransmission(&hyper_ratchet, object_id, resp_target_cid, group, packet_vectors[0].wave_id, &packet_vectors, timestamp, security_level))
                            .try_for_each(|packet| {
                                //log::warn!("Sending DO_RETRANSMISSION packet");
                                to_primary_stream.unbounded_send(packet)
                            }).is_ok();

                        group_receiver.on_retransmission_needed();
                        if send_success {
                            log::info!("Success sending DO_WAVE_RETRANSMISSION packets");
                        } else {
                            log::error!("Error sending DO_WAVE_RETRANSMISSION packets");
                        }
                    } else {
                        log::info!("Since waiting, the entire group finished. Ending async task");
                    }
                });

                true
            } else {
                log::warn!("Window tail received, but all waves appear to be cleared. WAVE ACKS will ensure the continuation of flow");
                true
            }
        } else {
            log::info!("Group receiver for group {} does not exist (could be finished)", group);
            true
        }
    }

    /// This function is called on Alice's side after Bob sends her a WAVE_ACK.
    /// The purpose of this function, for both tcp_only and reliable-udp, is to free memory.
    /// If using reliable-udp, then then this function has an additional purpose: to keep track
    /// of the number of waves ACK'ed. Once the number of waves ACK'ed equals the window size, this function
    /// also re-engages the transmitter
    #[allow(unused_results)]
    pub fn on_wave_ack_received(&mut self, implicated_cid: u64, header: &LayoutVerified<&[u8], HdpHeader>, tcp_only: bool, waves_in_next_window: Option<RangeInclusive<u32>>) -> bool {
        let object_id = header.context_info.get();
        let group = header.group.get();
        let wave_id = header.wave_id.get();
        let target_cid = header.session_cid.get();
        let key = GroupKey::new(target_cid, group);
        let mut delete_group = false;

        if object_id != 0 {
            // file transfer
            if let Some(transmitter_container) = self.outbound_transmitters.get_mut(&key) {
                // we set has_begun here instead of the transmit_tcp, simply because we want the first wave to ACK
                transmitter_container.has_begun = true;
                let mut transmitter = inner_mut!(transmitter_container.reliability_container);
                let relative_group_id = transmitter_container.relative_group_id;
                if transmitter.on_wave_tail_ack_received(wave_id) {
                    // Group is finished. Delete it
                    let elapsed_sec = transmitter_container.transmission_start_time.elapsed().as_secs_f32();
                    let rate_mb_per_s = (transmitter_container.group_plaintext_length as f32 / 1_000_000f32)/elapsed_sec;
                    log::info!("Transmitter received final wave ack. Alerting local node to continue transmission of next group");
                    // if there is n=1 waves, then the below must be ran. The other use of object notifier in this function only applies for multiple waves
                    if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                        let _ = next_group_notifier.unbounded_send(());
                        // alert kernel (transmitter side)
                        log::warn!("Notified object sender to begin sending the next group");
                    }
                    let file_key = FileKey::new(target_cid, object_id as u32);
                    let ticket = transmitter_container.ticket;
                    //println!("{}/{}", relative_group_id, transmitter_container.parent_object_total_groups);
                    if relative_group_id as usize != transmitter_container.parent_object_total_groups - 1 {
                        let status = FileTransferStatus::TransferTick(relative_group_id as usize, transmitter_container.parent_object_total_groups, rate_mb_per_s);
                        let _ = self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(implicated_cid, file_key, ticket, status));
                    } else {
                        let status = FileTransferStatus::TransferComplete;
                        let _ = self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(implicated_cid, file_key, ticket, status));
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
                        log::warn!("Notified object sender to begin sending the next group");
                    }
                }
            } else {
                log::error!("File-transfer for object {} does not map to a transmitter container", object_id);
            }
        } else {
            // message
            if let Some(transmitter_container) = self.outbound_transmitters.get_mut(&key) {
                transmitter_container.has_begun = true;
                let mut transmitter = inner_mut!(transmitter_container.reliability_container);
                if transmitter.on_wave_tail_ack_received(wave_id) {
                    // Group is finished. Delete it
                    delete_group = true;
                }

                if transmitter.is_atleast_fifty_percent_done() {
                    if let Some(next_group_notifier) = transmitter_container.object_notifier.take() {
                        let _ = next_group_notifier.unbounded_send(());
                        log::warn!("Notified object sender to begin sending the next group");
                    }
                }

                std::mem::drop(transmitter);

                // if we are deleting the group, no need to resume transmission (or, no need for tcp_only mode either)
                if !tcp_only && !delete_group {
                    if let Some(waves_in_next_window) = transmitter_container.on_wave_ack_received(waves_in_next_window) {
                        // window finished. Begin transmission of next window
                        let udp_sender = self.udp_sender.as_ref().unwrap();
                        return Self::transmit_window_udp(udp_sender, transmitter_container.burst_transmitter.as_mut().unwrap(), waves_in_next_window);
                    }
                }
            } else {
                log::error!("Transmitter for group {} does not exist!", group);
            }
        }

        if delete_group {
            log::info!("Group is done transmitting! Freeing memory ...");
            self.outbound_transmitters.remove(&key);
        }

        true
    }

    /// `waves_in_window`: if None, assuming tcp_only mode
    fn transmit_window_udp(udp_sender: &OutboundUdpSender, sender: &mut GroupTransmitter, waves_in_window: RangeInclusive<u32>) -> bool {
        sender.transmit_next_window_udp(udp_sender, waves_in_window)
    }

    /*
    fn transmit_all_tcp(sender: &mut GroupTransmitter, to_primary_stream: &UnboundedSender<Bytes>) -> bool {
        sender.transmit_tcp(to_primary_stream)
    }*/

    /// Ensure the group packet is valid before calling the function! This function is the last step
    /// over the packet receiving process before the data gets pushed to the kernel.
    ///
    /// This will optionally return some bytes if the packet is done being constructed
    ///
    /// `v_src_port` and `v_local_port`: the relative index, not the actual port
    #[allow(unused_results)]
    pub fn on_group_payload_packet_received(&mut self, v_src_port: u16, v_local_port: u16, hyper_ratchet: &HyperRatchet, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8], time_tracker: &TimeTracker, to_primary_stream: &OutboundTcpSender) -> Result<Option<(Ticket, VirtualTargetType, SecurityLevel, SecBuffer)>, NetworkError> {
        log::trace!("State container is processing group payload packet. Required HyperRatchet v{} | given: v{}", header.drill_version.get(), hyper_ratchet.version());
        let Self {
            inbound_groups,
            active_virtual_connections,
            ..
        } = self;

        // using the same logic described in on_window_tail_received:
        let resp_target_cid = if header.target_cid.get() != 0 {
            // this is thus a proxied packet that has reached its destination
            header.session_cid.get()
        } else {
            0
        };

        let preferred_primary_stream = Self::get_direct_p2p_primary_stream(active_virtual_connections, resp_target_cid).unwrap_or_else(|| to_primary_stream);

        let object_id = header.context_info.get() as u32;
        let group = header.group.get();
        let wave_id = header.wave_id.get();
        let security_level = header.security_level.into();
        let ref _drill_version = header.drill_version.get();
        let mut finished = false;
        let key = GroupKey::new(header.session_cid.get(), group);
        if let Some(group_receiver) = inbound_groups.get_mut(&key) {
            let scramble_drill = hyper_ratchet.get_scramble_drill();
            match hyxe_crypt::drill_algebra::generate_packet_coordinates_inv(wave_id, v_src_port, v_local_port, scramble_drill) {
                Some(true_sequence) => {
                    log::info!("WAVE packet w/ true sequence {} received. Will use hyper ratchet version {} to decrypt", true_sequence, hyper_ratchet.version());

                    match group_receiver.receiver.on_packet_received(group, true_sequence, wave_id, hyper_ratchet, payload) {
                        GroupReceiverStatus::GROUP_COMPLETE(last_wave_id) => {
                            log::info!("Group {} finished!", group);
                            let wave_ack = crate::hdp::hdp_packet_crafter::group::craft_wave_ack(hyper_ratchet, object_id, resp_target_cid, group, last_wave_id, time_tracker.get_global_time_ns(), None, security_level);
                            preferred_primary_stream.unbounded_send(wave_ack)?;
                            finished = true;
                        }

                        GroupReceiverStatus::WAVE_COMPLETE(wave_id) => {
                            // send a wave ack
                            log::info!("Wave {} complete! Sending WAVE ACK", wave_id);

                            // right before sending this WAVE_ACK, we must trigger the GroupReceiverContainer
                            let wave_ack = if let Some(next_window) = group_receiver.on_wave_finished() {
                                log::info!("Window complete! Sending extended WAVE_ACK. Next window: {:?}", &next_window);
                                // Now, we must send a WAVE_ACK with a range
                                crate::hdp::hdp_packet_crafter::group::craft_wave_ack(hyper_ratchet, object_id, resp_target_cid,group, wave_id, time_tracker.get_global_time_ns(), Some(next_window), security_level)
                            } else {
                                log::info!("Wave complete, but the window is not yet done");
                                crate::hdp::hdp_packet_crafter::group::craft_wave_ack(hyper_ratchet, object_id, resp_target_cid, group, wave_id, time_tracker.get_global_time_ns(), None, security_level)
                            };

                            preferred_primary_stream.unbounded_send(wave_ack)?;
                        }

                        // Common
                        GroupReceiverStatus::INSERT_SUCCESS => {}

                        _ => {}
                    }

                    group_receiver.has_begun = true;
                }

                None => {
                    // Bad sequence. Could be a spoofer who sent the packet through the wrong combo.
                    log::error!("Invalid src/dest port combo");
                    return Err(NetworkError::InvalidPacket("Invalid src/local port sequence"));
                }
            }
        } else {
            log::info!("Invalid packet; group inscribed in header does not correspond to packet herein. Dropping");
        }

        if finished {
            // Here, we void the necessity for GROUP_TAILS
            let group_receiver_final = inbound_groups.remove(&key).unwrap();
            let object_id = group_receiver_final.object_id;
            if object_id != 0 {
                // this means the group belongs to an object, in which case we need to stream it to the HD via the InboundFileReceiver
                log::info!("Group done; belongs to object {}, and will thus stream to HD", object_id);
                let key = FileKey::new(header.session_cid.get(), object_id);
                if let Some(mut inbound_file_container) = self.inbound_files.get_mut(&key) {
                    let group_chunk = group_receiver_final.receiver.finalize();
                    let chunk_size = group_chunk.len();
                    if let Err(_) = inbound_file_container.stream_to_hd.unbounded_send(group_chunk) {
                        log::error!("Unable to send data to HD");
                    }
                    // increment the counter, and check to see if completed. If complete, send a None signal to turn off the async task
                    inbound_file_container.groups_rendered += 1;
                    let cid = header.target_cid.get();
                    let ticket = inbound_file_container.ticket;
                    //println!("{}/{}", inbound_file_container.groups_rendered, inbound_file_container.total_groups);
                    return if inbound_file_container.groups_rendered == inbound_file_container.total_groups {
                        // complete
                        log::info!("FILE streaming COMPLETE! Ending related asynchronous tasks ...");
                        let _ = self.inbound_files.remove(&key);
                        // tell the kernel
                        let status = FileTransferStatus::ReceptionComplete;
                        self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(cid, key, ticket, status))?;
                        Ok(None)
                    } else {
                        // there are more groups to render. However, we need to ensure the next group transfers at the rate this just finished
                        // group was transferring at. To do that, take the window from the previous, and copy it into the inbound file container
                        let window = group_receiver_final.current_window;
                        let window_len = window.end() - window.start();
                        let mb_per_s = (chunk_size as f32/1_000_000f32)/inbound_file_container.last_group_finish_time.elapsed().as_secs_f32();

                        inbound_file_container.last_group_window_len = window_len as usize;
                        inbound_file_container.last_group_finish_time = Instant::now();

                        let status = FileTransferStatus::TransferTick(inbound_file_container.groups_rendered, inbound_file_container.total_groups, mb_per_s);
                        self.kernel_tx.unbounded_send(HdpServerResult::FileTransferStatus(cid, key, ticket, status))?;
                        Ok(None)
                    }
                } else {
                    log::error!("Key {:?} did NOT map to an inbound file container", key);
                }

                Ok(None)
            } else {
                // a group singleton (a message)
                Ok(Some((group_receiver_final.ticket, group_receiver_final.virtual_target, group_receiver_final.security_level, group_receiver_final.receiver.finalize().into())))
            }
        } else {
            Ok(None)
        }
    }

    /// This function will split up the payload appropriately and ensure that the values are valid. If valid, then
    /// it will place a resend request into the internal queue which gets checked by `check_system`
    ///
    /// When a do_retransmission packet is received, the window size is implied to get cut in half (done on Bob's end)
    #[allow(unused_results)]
    pub fn on_wave_do_retransmission_received(&mut self, hyper_ratchet: &HyperRatchet, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) {
        let group_id = header.group.get();
        let key = GroupKey::new(header.session_cid.get(), group_id);

        if let Some(sender) = self.outbound_transmitters.get(&key) {
            let sender = inner_mut!(sender.reliability_container);
            let wave_id = header.wave_id.get();
            if let Some(missing_packets) = sender.on_do_wave_retransmission_received(hyper_ratchet, wave_id, payload) {
                log::info!("{} packets are missing from wave {} of group {}", missing_packets.len(), wave_id, group_id);
                // missing packets exist, thus continue to process
                let iter = missing_packets.into_iter();
                let udp_sender = self.udp_sender.as_ref().unwrap();
                for missing_packet in iter {
                    udp_sender.unbounded_send(missing_packet.packet);
                }
            } else {
                log::info!("Invalid WAVE_DO_RETRANSMISSION from wave {} of group {}", wave_id, group_id);
            }
        } else {
            log::error!("A WAVE_DO_TRANSMISSION was received that has no corresponding sender. No return packet needed");
        }
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

    /// Returns true if a timeout occurred
    pub fn provisional_state_has_timed_out(&self) -> bool {
        self.register_state.has_expired() || self.connect_state.has_expired() || self.pre_connect_state.has_expired()
    }
}