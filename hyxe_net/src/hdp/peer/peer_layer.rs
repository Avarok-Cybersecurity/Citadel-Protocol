use std::collections::{VecDeque, HashMap, BTreeMap};
use crate::hdp::file_transfer::VirtualFileMetadata;
use crate::hdp::hdp_server::Ticket;
use tokio::time::error::Error;
use tokio_util::time::{delay_queue, delay_queue::DelayQueue};
use crate::constants::PEER_EVENT_MAILBOX_SIZE;
use crate::error::NetworkError;
use std::pin::Pin;
use futures::task::{Context, Poll};
use tokio::time::Duration;
use futures::Stream;
use crate::hdp::peer::peer_crypt::KeyExchangeProcess;
use std::fmt::{Display, Formatter};
use crate::hdp::peer::message_group::{MessageGroupKey, MessageGroup, MessageGroupPeer};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use serde::{Serialize, Deserialize};
use hyxe_fs::prelude::SyncIO;
use crate::macros::SyncContextRequirements;

#[cfg(feature = "multi-threaded")]
use futures::task::AtomicWaker;
use hyxe_user::external_services::fcm::kem::FcmPostRegister;
use hyxe_user::external_services::fcm::data_structures::{RawExternalPacket, FcmTicket};
use hyxe_crypt::fcm::keys::FcmKeys;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::state_container::VirtualConnectionType;

pub trait PeerLayerTimeoutFunction: FnOnce(PeerSignal) + SyncContextRequirements {}
impl<T: FnOnce(PeerSignal) + SyncContextRequirements> PeerLayerTimeoutFunction for T {}

#[derive(Default)]
/// When HyperLAN client A needs to send a POST_REGISTER signal to HyperLAN client B (who is disconnected),
/// the request needs to stay in memory until either the peer joins OR HyperLAN client A disconnects. Hence the need for this layer
pub struct HyperNodePeerLayerInner {
    pub(crate) mailbox: HashMap<u64, VecDeque<PeerSignal>>,
    // When a signal is routed to the target destination, the server needs to keep track of the state while awaiting
    pub(crate) observed_postings: HashMap<u64, HashMap<Ticket, TrackedPosting>>,
    pub(crate) message_groups: HashMap<u64, (u8, HashMap<u8, MessageGroup>)>,
    delay_queue: DelayQueue<(u64, Ticket)>
}

#[cfg(feature = "multi-threaded")]
#[derive(Clone)]
pub struct HyperNodePeerLayer {
    inner: std::sync::Arc<parking_lot::RwLock<HyperNodePeerLayerInner>>,
    waker: std::sync::Arc<AtomicWaker>
}

#[cfg(not(feature = "multi-threaded"))]
#[derive(Clone)]
pub struct HyperNodePeerLayer {
    inner: std::rc::Rc<std::cell::RefCell<HyperNodePeerLayerInner>>,
    waker: std::rc::Rc<std::cell::RefCell<Option<futures::task::Waker>>>
}

/// We don't use an "on_success" here because it would be structurally redundant. On success, the target node should
/// provide the packet. In that case, upon reception, the correlated [TrackedPosting] should be cleared
pub struct TrackedPosting {
    pub(crate) signal: PeerSignal,
    pub(crate) key: delay_queue::Key,
    pub(crate) on_timeout: Box<dyn PeerLayerTimeoutFunction>
}

impl TrackedPosting {
    pub fn new(signal: PeerSignal, key: delay_queue::Key, on_timeout: impl FnOnce(PeerSignal) + SyncContextRequirements) -> Self {
        Self { signal, key, on_timeout: Box::new(on_timeout) }
    }
}


impl HyperNodePeerLayer {
    #[allow(unused_results)]
    /// This should be called during the DO_CONNECT phase
    pub fn register_peer(&mut self, cid: u64, clear_if_existing: bool) -> Option<MailboxTransfer>{
        let mut this = inner_mut!(self);
        // Add unconditionally, replacing any previous items
        if clear_if_existing {
            log::info!("Force adding mailbox for {}", cid);
            this.mailbox.insert(cid, VecDeque::with_capacity(PEER_EVENT_MAILBOX_SIZE));
            this.observed_postings.insert(cid, HashMap::new());
            this.message_groups.insert(cid, (0, HashMap::new()));
            return None;
        }

        // Otherwise, add only if it doesn't already exist
        if !this.observed_postings.contains_key(&cid) {
            log::info!("Adding observed postings handler for {}", cid);
            this.observed_postings.insert(cid, HashMap::new());
        }

        if !this.message_groups.contains_key(&cid) {
            log::info!("Adding message group hashmap for {}", cid);
            this.message_groups.insert(cid, (0, HashMap::new()));
        }

        if !this.mailbox.contains_key(&cid) {
            log::info!("Adding mailbox for {}", cid);
            this.mailbox.insert(cid, VecDeque::with_capacity(PEER_EVENT_MAILBOX_SIZE));
            None
        } else {
            // drain mailbox, return to user (means there was mail to view)
            let items = this.mailbox.get_mut(&cid).unwrap().drain(..).collect::<Vec<PeerSignal>>();
            if items.len() != 0 {
                log::info!("Returning enqueued mailbox items for {}", cid);
                Some(MailboxTransfer::from(items))
            } else {
                None
            }
        }
    }

    /// Cleans up the internal entries
    #[allow(unused_results)]
    pub fn on_session_shutdown(&self, implicated_cid: u64) {
        let mut this = inner_mut!(self);
        this.mailbox.remove(&implicated_cid);
        this.message_groups.remove(&implicated_cid);
        this.observed_postings.remove(&implicated_cid);
    }

    /// Creates a new [MessageGroup]. Returns the key upon completion
    #[allow(unused_results)]
    pub fn create_new_message_group(&self, implicated_cid: u64, initial_peers: &Vec<u64>) -> Option<MessageGroupKey> {
        let mut this = inner_mut!(self);
        let (next_idx, map) = this.message_groups.get_mut(&implicated_cid)?;
        let mgid = *next_idx;
        if mgid != 255 {
            if !map.contains_key(&mgid) {
                let mut message_group = MessageGroup { concurrent_peers: HashMap::new(), pending_peers: HashMap::with_capacity(initial_peers.len()) };
                // insert peers into the pending_peers map to allow/process AcceptMembership signals
                for peer_cid in initial_peers {
                    let peer_cid = *peer_cid;
                    message_group.pending_peers.insert(peer_cid, MessageGroupPeer { peer_cid });
                }

                // add the implicated_cid to the concurrent peers
                message_group.concurrent_peers.insert(implicated_cid, MessageGroupPeer { peer_cid: implicated_cid });

                map.insert(mgid, message_group);
                // increment so the next call to this function returns a valid entry
                *next_idx = (*next_idx).saturating_add(1);
                Some(MessageGroupKey {cid: implicated_cid, mgid})
            } else {
                None
            }
        } else {
            log::warn!("The maximum number of groups per session has been reached for {}", implicated_cid);
            None
        }
    }

    /// removes a [MessageGroup]
    pub fn remove_message_group(&self, key: MessageGroupKey) -> Option<MessageGroup> {
        let mut this = inner_mut!(self);
        let (_idx, map) = this.message_groups.get_mut(&key.cid)?;
        map.remove(&key.mgid)
    }

    #[allow(unused_results)]
    pub fn add_pending_peers_to_group(&self, key: MessageGroupKey, peers: Vec<u64>) {
        let mut this = inner_mut!(self);
        if let Some((_idx, map)) = this.message_groups.get_mut(&key.cid) {
            if let Some(entry) = map.get_mut(&key.mgid) {
                for peer_cid in peers {
                    let insert = MessageGroupPeer { peer_cid };
                    entry.pending_peers.insert(peer_cid, insert);
                }
            } else {
                log::warn!("Unable to locate MGID. Peers will not be able to accept");
            }
        }
    }

    #[allow(unused_results)]
    // Upgrades a peer from pending to concurrent (enabled reception of broadcasts)
    pub fn upgrade_peer_in_group(&self, key: MessageGroupKey, peer_cid: u64) -> bool {
        let mut this = inner_mut!(self);
        if let Some((_idx, map)) = this.message_groups.get_mut(&key.cid) {
            if let Some(entry) = map.get_mut(&key.mgid) {
                if let Some(peer) = entry.pending_peers.remove(&peer_cid) {
                    entry.concurrent_peers.insert(peer_cid, peer);
                    return true
                }
            }
        }

        false
    }

    /// Determines if the [MessageGroupKey] maps to a [MessageGroup]
    pub fn message_group_exists(&self, key: MessageGroupKey) -> bool {
        let this = inner!(self);
        if let Some((_idx, map)) = this.message_groups.get(&key.cid) {
            map.contains_key(&key.mgid)
        } else {
            false
        }
    }

    /// Returns the set of peers in a [MessageGroup]
    pub fn get_peers_in_message_group(&self, key: MessageGroupKey) -> Option<Vec<u64>> {
        let this = inner!(self);
        let (_idx, map) = this.message_groups.get(&key.cid)?;
        let message_group = map.get(&key.mgid)?;
        let peers = message_group.concurrent_peers.keys().cloned().collect::<Vec<u64>>();
        if peers.is_empty() {
            None
        } else {
            Some(peers)
        }
    }

    /// Removes the provided peers from the group. Returns a set of peers that were removed successfully, as well as the remaining peers
    pub fn remove_peers_from_message_group(&self, key: MessageGroupKey, mut peers: Vec<u64>) -> Result<(Vec<u64>, Vec<u64>), ()> {
        let mut this = inner_mut!(self);
        let (_idx, map) = this.message_groups.get_mut(&key.cid).ok_or(())?;
        let message_group = map.get_mut(&key.mgid).ok_or(())?;
        //let mut peers_removed = Vec::new();
        // Keep all the peers that were not removed. I.e., if the remove operation returns None
        // then that peer wasn't removed and hence should stay in the vec
        peers.retain(|peer| {
            message_group.concurrent_peers.remove(peer).is_some()
        });

        let peers_remaining = message_group.concurrent_peers.keys().cloned().collect::<Vec<u64>>();
        let peers_successfully_removed = peers;

        Ok((peers_successfully_removed, peers_remaining))
    }

    /// returns true if added successfully, or false if not (mailbox may be overloaded)
    /// `add_queue_if_non_existing`: Creates an event queue if non-existing (useful if target not connected yet)
    /// `target_cid`: Should be the destination
    #[allow(unused_results)]
    pub fn try_add_mailbox(&self, add_queue_if_non_existing: bool, target_cid: u64, signal: PeerSignal) -> bool {
        let mut this = inner_mut!(self);
        if let Some(queue) = this.mailbox.get_mut(&target_cid) {
            if queue.len() > PEER_EVENT_MAILBOX_SIZE {
                false
            } else {
                queue.push_back(signal);
                true
            }
        } else {
            if add_queue_if_non_existing {
                let mut queue = VecDeque::with_capacity(PEER_EVENT_MAILBOX_SIZE);
                queue.push_back(signal);
                this.mailbox.insert(target_cid, queue);
                true
            } else {
                false
            }
        }
    }

    /// Returns the next event in the queue. Returns None if the queue does not exist
    /// OR if there are no more events
    #[allow(dead_code)]
    pub fn get_next_mailbox_item(&self, target_cid: u64) -> Option<PeerSignal> {
        let mut this = inner_mut!(self);
        if let Some(queue) = this.mailbox.get_mut(&target_cid) {
            queue.pop_front()
        } else {
            None
        }
    }

    /// Returns ALL enqueued events
    #[allow(dead_code)]
    pub fn get_mailbox_items(&self, target_cid: u64) -> Option<Vec<PeerSignal>> {
        let mut this = inner_mut!(self);
        if let Some(queue) = this.mailbox.get_mut(&target_cid) {
            if queue.len() != 0 {
                Some(queue.drain(..).collect::<Vec<PeerSignal>>())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Same as get_events, but doesn't allocate a new vector; it applies the provided function instead.
    /// This function returns the number of signals processed
    #[allow(dead_code)]
    pub fn enter_mailbox<E: ToString, F: Fn(PeerSignal) -> Result<(), E>>(&self, target_cid: u64, fx: F) -> Result<Option<usize>, NetworkError>{
        let mut this = inner_mut!(self);
        if let Some(queue) = this.mailbox.get_mut(&target_cid) {
            let len = queue.len();
            if len != 0 {
                queue.drain(..).try_for_each(|signal| fx(signal))
                    .map_err(|err| NetworkError::Generic(err.to_string()))
                    .and_then(|_| Ok(Some(len)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// An observed posting is associated with the `implicated_cid`
    /// `on_timeout`: This function will be called if a timeout occurs. The provided session belongs to `implicated_cid`
    /// NOTE: the ticket MUST be unique per session, otherwise unexpired items may disappear unnecessarily! If the ticket ID's are provided
    /// by the HyperLAN client's side, this should work out
    #[allow(unused_results)]
    pub fn insert_tracked_posting(&self, implicated_cid: u64, timeout: Duration, ticket: Ticket, signal: PeerSignal, on_timeout: impl FnOnce(PeerSignal) + SyncContextRequirements) {
        let this_ref = self.clone();
        let future = async move {
            let mut this = inner_mut!(this_ref);
            let delay_key = this.delay_queue
                .insert((implicated_cid, ticket), timeout);
            log::info!("Creating TrackedPosting {} (Ticket: {})", implicated_cid, ticket);

            if let Some(map) = this.observed_postings.get_mut(&implicated_cid) {
                let tracked_posting = TrackedPosting::new(signal, delay_key, on_timeout);
                map.insert(ticket, tracked_posting);

                std::mem::drop(this);
                this_ref.wake();
            } else {
                log::error!("Unable to find implicated_cid in observed_posting. Bad init state?");
            }
        };

        spawn!(future);
    }

    /// Removes a [TrackedPosting] from the internal queue, and returns the signal
    #[allow(unused_results)]
    pub fn remove_tracked_posting(&self, implicated_cid: u64, ticket: Ticket) -> Option<PeerSignal> {
        let mut this = inner_mut!(self);
        log::info!("Removing tracked posting for {} (ticket: {})", implicated_cid, ticket);
        let active_postings = this.observed_postings.get_mut(&implicated_cid)?;
        let active_posting = active_postings.remove(&ticket)?;
        this.delay_queue.remove(&active_posting.key);
        Some(active_posting.signal)
    }

    // Single-thread note: re-entrancy is okay since we can hold multiple borrow at once, but not multiple borrow_muts
    fn register_waker(&self, waker: &futures::task::Waker) {
        #[cfg(feature = "multi-threaded")]
            {
                self.waker.register(waker)
            }

        #[cfg(not(feature = "multi-threaded"))]
            {
                *self.waker.borrow_mut() = Some(waker.clone());
            }
    }

    fn wake(&self) {
        #[cfg(feature = "multi-threaded")]
            {
                self.waker.wake();
            }

        #[cfg(not(feature = "multi-threaded"))]
            {
                let borrow = self.waker.borrow();
                if let Some(waker) = borrow.as_ref() {
                    waker.wake_by_ref();
                }
            }
    }

    pub(self) fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.register_waker(cx.waker());
        let mut this = inner_mut!(self);

        while let Some(res) = futures::ready!(this.delay_queue.poll_expired(cx)) {
            let (implicated_cid, ticket) = res?.into_inner();
            if let Some(active_postings) = this.observed_postings.get_mut(&implicated_cid) {
                if let Some(posting) = active_postings.remove(&ticket) {
                    log::warn!("Running on_timeout for active posting {} for CID {}", ticket, implicated_cid);
                    (posting.on_timeout)(posting.signal)
                } else {
                    log::error!("Attempted to remove active posting {} for CID {}, but failed", implicated_cid, ticket);
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl Stream for HyperNodePeerLayer {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.poll_purge(cx)) {
            Ok(_) => {
                Poll::Pending
            }

            Err(_) => {
                Poll::Ready(None)
            }
        }
    }
}

impl futures::Future for HyperNodePeerLayer {
    type Output = Result<(), NetworkError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.poll_next(cx)) {
            Some(_) => Poll::Pending,
            None => Poll::Ready(Err(NetworkError::InternalError("Queue handler signalled shutdown")))
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(variant_size_differences)]
pub enum PeerSignal {
    // implicated_cid, icid (0 if hyperlan), target_cid (0 if all), use fcm
    PostRegister(PeerConnectionType, Username, Option<Ticket>, Option<PeerResponse>, FcmPostRegister),
    // implicated_cid, icid, target_cid, use_fcm
    Deregister(PeerConnectionType, bool),
    // implicated_cid, icid, target_cid, udp enabled
    PostConnect(PeerConnectionType, Option<Ticket>, Option<PeerResponse>, SessionSecuritySettings, UdpMode),
    // implicated_cid, icid, target cid
    Disconnect(PeerConnectionType, Option<PeerResponse>),
    DisconnectUDP(VirtualConnectionType),
    // implicated_cid, icid
    BroadcastConnected(GroupBroadcast),
    // implicated_cid, icid, target cid
    PostFileUploadRequest(PeerConnectionType, VirtualFileMetadata, Ticket),
    // implicated_cid, icid, target cid
    AcceptFileUploadRequest(PeerConnectionType, Ticket),
    // Retrieves a list of registered peers
    GetRegisteredPeers(HypernodeConnectionType, Option<PeerResponse>, Option<i32>),
    // returns a list of mutuals for implicated cid, icid. Can be used to sync between the HyperLAN client and HyperLAN server
    GetMutuals(HypernodeConnectionType, Option<PeerResponse>),
    // Returned when an error occurs
    SignalError(Ticket, String),
    // deregistration succeeded (contains peer cid)
    DeregistrationSuccess(u64, bool),
    // Signal has been processed; response may or may not occur
    SignalReceived(Ticket),
    // for key-exchange
    Kem(PeerConnectionType, KeyExchangeProcess),
    // For redundant fcm transfers, ensuring no loss of packets when using FCM
    Fcm(FcmTicket, RawExternalPacket),
    // For polling for packets
    FcmFetch(Option<HashMap<u64, BTreeMap<u64, RawExternalPacket>>>),
    // For denoting that reg info changed
    FcmTokenUpdate(FcmKeys)
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum UdpMode {
    Enabled, Disabled
}

impl Default for UdpMode {
    fn default() -> Self {
        Self::Enabled
    }
}

// Channel packets don't get decrypted/encrypted at the central node; only at the endpoints
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ChannelPacket {
    // payload
    Message(Vec<u8>)
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum PeerConnectionType {
    // implicated_cid, target_cid
    HyperLANPeerToHyperLANPeer(u64, u64),
    // implicated_cid, icid, target_cid
    HyperLANPeerToHyperWANPeer(u64, u64, u64)
}

impl PeerConnectionType {
    pub fn get_original_implicated_cid(&self) -> u64 {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => *implicated_cid,
            PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, _icid, _target_cid) => *implicated_cid
        }
    }

    pub fn get_original_target_cid(&self) -> u64 {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => *target_cid,
            PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, target_cid) => *target_cid
        }
    }

    pub fn reverse(&self) -> PeerConnectionType {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => PeerConnectionType::HyperLANPeerToHyperLANPeer(*target_cid, *implicated_cid),
            PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => PeerConnectionType::HyperLANPeerToHyperWANPeer(*target_cid, *icid, *implicated_cid)
        }
    }

    pub fn as_virtual_connection(self) -> VirtualConnectionType {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => VirtualConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid),
            PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => VirtualConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid)
        }
    }
}

impl Display for PeerConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => write!(f, "hLAN {} <-> {}", implicated_cid, target_cid),
            PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => write!(f, "hWAN {} <-> {} <-> {}", implicated_cid, icid, target_cid)
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum HypernodeConnectionType {
    // implicated_cid
    HyperLANPeerToHyperLANServer(u64),
    // implicated_cid, icid
    HyperLANPeerToHyperWANServer(u64, u64)
}

impl HypernodeConnectionType {
    pub fn get_implicated_cid(&self) -> u64 {
        match self {
            HypernodeConnectionType::HyperLANPeerToHyperLANServer(implicated_cid) => *implicated_cid,
            HypernodeConnectionType::HyperLANPeerToHyperWANServer(implicated_cid, _) => *implicated_cid
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(variant_size_differences)]
pub enum PeerResponse {
    Ok(Option<String>),
    Accept(Option<String>),
    Decline,
    Err(Option<String>),
    Disconnected(String),
    Group(GroupBroadcast),
    None,
    ServerReceivedRequest,
    Timeout,
    RegisteredCids(Vec<u64>, Vec<bool>)
}

impl PeerResponse {
    /// no allocation occurs
    pub const fn empty_registered() -> PeerResponse {
        PeerResponse::RegisteredCids(Vec::new(), Vec::new())
    }
}

pub type Username = String;

impl Into<Vec<u8>> for PeerSignal {
    fn into(self) -> Vec<u8> {
        self.serialize_to_vector().unwrap()
    }
}

impl Default for HyperNodePeerLayer {
    fn default() -> Self {
        let inner = HyperNodePeerLayerInner { delay_queue: DelayQueue::new(), ..Default::default() };
        #[cfg(feature = "multi-threaded")]
            {
                let waker = std::sync::Arc::new(AtomicWaker::new());
                let inner = std::sync::Arc::new(parking_lot::RwLock::new(inner));
                Self { inner, waker }
            }

        #[cfg(not(feature = "multi-threaded"))]
            {
                let waker = std::rc::Rc::new(std::cell::RefCell::new(None));
                let inner = std::rc::Rc::new(std::cell::RefCell::new(inner));
                Self { inner, waker }
            }
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub enum MailboxTransfer {
    Signals(Vec<PeerSignal>)
}

impl From<Vec<PeerSignal>> for MailboxTransfer {
    fn from(signals: Vec<PeerSignal>) -> Self {
        MailboxTransfer::Signals(signals)
    }
}