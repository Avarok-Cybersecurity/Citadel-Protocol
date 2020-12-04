use std::collections::{HashMap, VecDeque};
use std::fmt::{Display, Formatter};
use std::pin::Pin;

use futures::Stream;
use futures::task::{Context, Poll, Waker};
use nanoserde::{DeBin, SerBin};
use tokio::time::Duration;
use tokio::time::error::Error;
use tokio_util::time::{delay_queue, DelayQueue};

use crate::constants::PEER_EVENT_MAILBOX_SIZE;
use crate::error::NetworkError;
use crate::hdp::file_transfer::VirtualFileMetadata;
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::peer::message_group::{MessageGroup, MessageGroupKey, MessageGroupPeer};
use crate::hdp::peer::peer_crypt::KeyExchangeProcess;

#[derive(Default)]
/// When HyperLAN client A needs to send a POST_REGISTER signal to HyperLAN client B (who is disconnected),
/// the request needs to stay in memory until either the peer joins OR HyperLAN client A disconnects. Hence the need for this layer
pub struct HyperNodePeerLayerInner {
    pub(crate) mailbox: HashMap<u64, VecDeque<PeerSignal>>,
    // When a signal is routed to the target destination, the server needs to keep track of the state while awaiting
    pub(crate) observed_postings: HashMap<u64, HashMap<Ticket, TrackedPosting>>,
    pub(crate) message_groups: HashMap<u64, (u8, HashMap<u8, MessageGroup>)>,
    delay_queue: DelayQueue<(u64, Ticket)>,
    waker: Option<Waker>
}

define_outer_struct_wrapper!(HyperNodePeerLayer, HyperNodePeerLayerInner);

/// We don't use an "on_success" here because it would be structurally redundant. On success, the target node should
/// provide the packet. In that case, upon reception, the correlated [TrackedPosting] should be cleared
pub struct TrackedPosting {
    pub(crate) signal: PeerSignal,
    pub(crate) key: delay_queue::Key,
    pub(crate) on_timeout: Box<dyn FnOnce(PeerSignal) + 'static>
}

impl TrackedPosting {
    pub fn new(signal: PeerSignal, key: delay_queue::Key, on_timeout: impl FnOnce(PeerSignal) + 'static) -> Self {
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
    pub fn insert_tracked_posting(&self, implicated_cid: u64, timeout: Duration, ticket: Ticket, signal: PeerSignal, on_timeout: impl FnOnce(PeerSignal) + 'static) -> bool {
        let mut this = inner_mut!(self);
        let delay_key = this.delay_queue
            .insert((implicated_cid, ticket), timeout);
        log::info!("Creating TrackedPosting {} (Ticket: {})", implicated_cid, ticket);

        if let Some(map) = this.observed_postings.get_mut(&implicated_cid) {
            let tracked_posting = TrackedPosting::new(signal, delay_key, on_timeout);
            map.insert(ticket, tracked_posting);
            if let Some(waker) = this.waker.as_ref() {
                waker.wake_by_ref();
            }

            true
        } else {
            false
        }
    }

    /// Useful for entries that will only have a bried lifetime in the `observed_postings` structure. Will only allocated one spot
    #[allow(unused_results, dead_code)]
    pub fn insert_provisional_posting(&self, implicated_cid: u64, timeout: Duration, ticket: Ticket, signal: PeerSignal, on_timeout: impl FnOnce(PeerSignal) + 'static) -> bool {
        let mut this = inner_mut!(self);
        let delay_key = this.delay_queue
            .insert((implicated_cid, ticket), timeout);
        log::info!("Creating TrackedPosting {} (Ticket: {})", implicated_cid, ticket);

        if !this.observed_postings.contains_key(&implicated_cid) {
            let mut map = HashMap::with_capacity(1);
            let tracked_posting = TrackedPosting::new(signal, delay_key, on_timeout);
            map.insert(ticket, tracked_posting);
            if let Some(waker) = this.waker.as_ref() {
                waker.wake_by_ref();
            }
            this.observed_postings.insert(implicated_cid, map);
            true
        } else {
            false
        }
    }

    /// Removes the hashmap and correspoding internal [TrackedPosting]
    #[allow(unused_results, dead_code)]
    pub fn remove_provisional_posting(&self, implicated_cid: u64, ticket: Ticket) -> Option<PeerSignal> {
        let mut this = inner_mut!(self);
        log::info!("Removing tracked posting for {} (ticket: {})", implicated_cid, ticket);
        let mut active_postings = this.observed_postings.remove(&implicated_cid)?;
        let active_posting = active_postings.remove(&ticket)?;
        this.delay_queue.remove(&active_posting.key);
        Some(active_posting.signal)
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

    pub(self) fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut this = inner_mut!(self);
        if this.waker.is_none() {
            this.waker = Some(cx.waker().clone());
        }

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

#[derive(Debug, SerBin, DeBin, Clone)]
pub enum PeerSignal {
    // implicated_cid, icid (0 if hyperlan), target_cid (0 if all)
    PostRegister(PeerConnectionType, Username, Option<Ticket>, Option<PeerResponse>),
    // implicated_cid, icid, target_cid
    Deregister(PeerConnectionType),
    // implicated_cid, icid, target_cid
    PostConnect(PeerConnectionType, Option<Ticket>, Option<PeerResponse>),
    // implicated_cid, icid, target cid
    Disconnect(PeerConnectionType, Option<PeerResponse>),
    // implicated_cid, icid
    BroadcastConnected(GroupBroadcast),
    // implicated_cid, icid, target cid
    PostFileUploadRequest(PeerConnectionType, VirtualFileMetadata, Ticket),
    // implicated_cid, icid, target cid
    AcceptFileUploadRequest(PeerConnectionType, Ticket),
    // Retrieves a list of registered peers
    GetRegisteredPeers(HypernodeConnectionType, Option<PeerResponse>),
    // returns a list of mutuals for implicated cid, icid. Can be used to sync between the HyperLAN client and HyperLAN server
    GetMutuals(HypernodeConnectionType, Option<PeerResponse>),
    // Returned when an error occurs
    SignalError(Ticket, String),
    // Signal has been processed; response may or may not occur
    SignalReceived(Ticket),
    // for key-exchange
    Kem(PeerConnectionType, KeyExchangeProcess)
}

// Channel packets don't get decrypted/encrypted at the central node; only at the endpoints
#[derive(Debug, SerBin, DeBin, Clone)]
pub enum ChannelPacket {
    // payload
    Message(Vec<u8>)
}

#[derive(PartialEq, Debug, SerBin, DeBin, Copy, Clone)]
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
}

impl Display for PeerConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, target_cid) => write!(f, "hLAN {} <-> {}", implicated_cid, target_cid),
            PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, icid, target_cid) => write!(f, "hWAN {} <-> {} <-> {}", implicated_cid, icid, target_cid)
        }
    }
}

#[derive(PartialEq, Debug, SerBin, DeBin, Copy, Clone)]
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

#[derive(Debug, SerBin, DeBin, Clone)]
pub enum PeerResponse {
    Ok(Option<String>),
    Accept(Option<String>),
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
    pub fn empty_registered() -> PeerResponse {
        PeerResponse::RegisteredCids(Vec::with_capacity(0), Vec::with_capacity(0))
    }
}

pub type Username = String;

impl PeerSignal {
    pub fn serialize_bytes(&self) -> Vec<u8> {
        SerBin::serialize_bin(self)
    }

    pub fn deserialize_from_bytes<T: AsRef<[u8]>>(this: T) -> Option<Self> {
        DeBin::deserialize_bin(this.as_ref()).ok()
    }
}

impl Into<Vec<u8>> for PeerSignal {
    fn into(self) -> Vec<u8> {
        self.serialize_bytes()
    }
}

impl Default for HyperNodePeerLayer {
    fn default() -> Self {
        let inner = HyperNodePeerLayerInner { delay_queue: DelayQueue::new(), ..Default::default() };
        Self::from(inner)
    }
}


#[derive(SerBin, DeBin, Debug)]
pub enum MailboxTransfer {
    Signals(Vec<PeerSignal>)
}

impl MailboxTransfer {
    pub fn deserialize_from(input: &[u8]) -> Option<Self> {
        DeBin::deserialize_bin(input).ok()
    }

    pub fn len(&self) -> usize {
        match self {
            MailboxTransfer::Signals(signals) => signals.len()
        }
    }
}

impl From<Vec<PeerSignal>> for MailboxTransfer {
    fn from(signals: Vec<PeerSignal>) -> Self {
        MailboxTransfer::Signals(signals)
    }
}