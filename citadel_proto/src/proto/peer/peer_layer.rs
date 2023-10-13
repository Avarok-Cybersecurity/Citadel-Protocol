use crate::error::NetworkError;
use crate::macros::SyncContextRequirements;
use crate::proto::misc::session_security_settings::SessionSecuritySettings;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::message_group::{
    GroupType, MessageGroup, MessageGroupKey, MessageGroupOptions, MessageGroupPeer,
};
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::remote::Ticket;
use crate::proto::state_container::VirtualConnectionType;
use citadel_user::backend::utils::VirtualObjectMetadata;
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use futures::task::AtomicWaker;
use futures::task::{Context, Poll};
use futures::Stream;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use tokio::time::error::Error;
use tokio::time::Duration;
use tokio_util::time::{delay_queue, delay_queue::DelayQueue};
use uuid::Uuid;

pub trait PeerLayerTimeoutFunction: FnOnce(PeerSignal) + SyncContextRequirements {}
impl<T: FnOnce(PeerSignal) + SyncContextRequirements> PeerLayerTimeoutFunction for T {}

/// When HyperLAN client A needs to send a POST_REGISTER signal to HyperLAN client B (who is disconnected),
/// the request needs to stay in memory until either the peer joins OR HyperLAN client A disconnects. Hence the need for this layer
pub struct HyperNodePeerLayerInner {
    // When a signal is routed to the target destination, the server needs to keep track of the state while awaiting
    pub(crate) persistence_handler: PersistenceHandler,
    pub(crate) message_groups: HashMap<u64, HashMap<u128, MessageGroup>>,
    waker: Arc<AtomicWaker>,
    inner: Arc<citadel_io::RwLock<SharedInner>>,
}

#[derive(Default)]
struct SharedInner {
    observed_postings: HashMap<u64, HashMap<Ticket, TrackedPosting>>,
    delay_queue: DelayQueue<(u64, Ticket)>,
}

// message group byte map key layout:
// implicated cid = implicated cid -> key = (u128."concurrent" OR u128."pending") -> u64 (peer cid)

const MAILBOX: &str = "mailbox";

#[derive(Clone)]
pub struct HyperNodePeerLayer {
    pub(crate) inner: std::sync::Arc<tokio::sync::RwLock<HyperNodePeerLayerInner>>,
    waker: std::sync::Arc<AtomicWaker>,
}

pub struct HyperNodePeerLayerExecutor {
    inner: Arc<citadel_io::RwLock<SharedInner>>,
    waker: Arc<AtomicWaker>,
}

/// We don't use an "on_success" here because it would be structurally redundant. On success, the target node should
/// provide the packet. In that case, upon reception, the correlated [`TrackedPosting`] should be cleared
pub struct TrackedPosting {
    pub(crate) signal: PeerSignal,
    pub(crate) key: delay_queue::Key,
    pub(crate) on_timeout: Box<dyn PeerLayerTimeoutFunction>,
}

impl TrackedPosting {
    pub fn new(
        signal: PeerSignal,
        key: delay_queue::Key,
        on_timeout: impl FnOnce(PeerSignal) + SyncContextRequirements,
    ) -> Self {
        Self {
            signal,
            key,
            on_timeout: Box::new(on_timeout),
        }
    }
}

impl HyperNodePeerLayer {
    pub fn new(persistence_handler: PersistenceHandler) -> HyperNodePeerLayer {
        let waker = std::sync::Arc::new(AtomicWaker::new());
        let inner = HyperNodePeerLayerInner {
            waker: waker.clone(),
            inner: Arc::new(citadel_io::RwLock::new(Default::default())),
            persistence_handler,
            message_groups: HashMap::new(),
        };
        let inner = std::sync::Arc::new(tokio::sync::RwLock::new(inner));

        Self { inner, waker }
    }

    pub async fn create_executor(&self) -> HyperNodePeerLayerExecutor {
        HyperNodePeerLayerExecutor {
            waker: self.waker.clone(),
            inner: self.inner.read().await.inner.clone(),
        }
    }

    #[allow(unused_results)]
    /// This should be called during the DO_CONNECT phase
    pub async fn register_peer(&self, cid: u64) -> Result<Option<MailboxTransfer>, NetworkError> {
        let pers = {
            let mut this_orig = self.inner.write().await;

            this_orig.message_groups.entry(cid).or_insert_with(|| {
                log::trace!(target: "citadel", "Adding message group hashmap for {}", cid);
                HashMap::new()
            });

            let mut this = this_orig.inner.write();

            // Otherwise, add only if it doesn't already exist
            this.observed_postings.entry(cid).or_insert_with(|| {
                log::trace!(target: "citadel", "Adding observed postings handler for {}", cid);
                HashMap::new()
            });

            this_orig.persistence_handler.clone()
        };

        // drain mailbox, return to user (means there was mail to view)
        let items = pers.remove_byte_map_values_by_key(cid, 0, MAILBOX).await?;
        if !items.is_empty() {
            log::trace!(target: "citadel", "Returning enqueued mailbox items for {}", cid);
            Ok(Some(MailboxTransfer::from(
                items
                    .into_values()
                    .map(PeerSignal::deserialize_from_owned_vector)
                    .try_collect::<PeerSignal, Vec<PeerSignal>, _>()
                    .map_err(|err| NetworkError::Generic(err.into_string()))?,
            )))
        } else {
            Ok(None)
        }
    }

    /// Cleans up the internal entries
    #[allow(unused_results)]
    pub async fn on_session_shutdown(&self, implicated_cid: u64) -> Result<(), NetworkError> {
        let pers = {
            let mut this = self.inner.write().await;
            this.message_groups.remove(&implicated_cid);
            this.inner.write().observed_postings.remove(&implicated_cid);
            this.persistence_handler.clone()
        };

        let _ = pers
            .remove_byte_map_values_by_key(implicated_cid, 0, MAILBOX)
            .await?;
        Ok(())
    }

    /// Creates a new [MessageGroup]. Returns the key upon completion
    #[allow(unused_results)]
    pub async fn create_new_message_group(
        &self,
        implicated_cid: u64,
        initial_peers: &Vec<u64>,
        options: MessageGroupOptions,
    ) -> Option<MessageGroupKey> {
        let mut this = self.inner.write().await;
        let map = this.message_groups.get_mut(&implicated_cid)?;
        let mgid = options.id;
        if map.len() <= u8::MAX as usize {
            if let std::collections::hash_map::Entry::Vacant(e) = map.entry(mgid) {
                let mut message_group = MessageGroup {
                    concurrent_peers: HashMap::new(),
                    pending_peers: HashMap::with_capacity(initial_peers.len()),
                    options,
                };
                // insert peers into the pending_peers map to allow/process AcceptMembership signals
                for peer_cid in initial_peers {
                    let peer_cid = *peer_cid;
                    message_group
                        .pending_peers
                        .insert(peer_cid, MessageGroupPeer { peer_cid });
                }

                // add the implicated_cid to the concurrent peers
                message_group.concurrent_peers.insert(
                    implicated_cid,
                    MessageGroupPeer {
                        peer_cid: implicated_cid,
                    },
                );

                e.insert(message_group);
                Some(MessageGroupKey {
                    cid: implicated_cid,
                    mgid,
                })
            } else {
                None
            }
        } else {
            log::warn!(target: "citadel", "The maximum number of groups per session has been reached for {}", implicated_cid);
            None
        }
    }

    /// removes a [MessageGroup]
    pub async fn remove_message_group(&self, key: MessageGroupKey) -> Option<MessageGroup> {
        let mut this = self.inner.write().await;
        let map = this.message_groups.get_mut(&key.cid)?;
        map.remove(&key.mgid)
    }

    #[allow(unused_results)]
    pub async fn add_pending_peers_to_group(&self, key: MessageGroupKey, peers: Vec<u64>) {
        let mut this = self.inner.write().await;
        if let Some(map) = this.message_groups.get_mut(&key.cid) {
            if let Some(entry) = map.get_mut(&key.mgid) {
                for peer_cid in peers {
                    let insert = MessageGroupPeer { peer_cid };
                    entry.pending_peers.insert(peer_cid, insert);
                }
            } else {
                log::warn!(target: "citadel", "Unable to locate MGID. Peers will not be able to accept");
            }
        }
    }

    #[allow(unused_results)]
    // Upgrades a peer from pending to concurrent (enabled reception of broadcasts)
    pub async fn upgrade_peer_in_group(&self, key: MessageGroupKey, peer_cid: u64) -> bool {
        let mut this = self.inner.write().await;
        if let Some(map) = this.message_groups.get_mut(&key.cid) {
            if let Some(entry) = map.get_mut(&key.mgid) {
                if let Some(peer) = entry.pending_peers.remove(&peer_cid) {
                    entry.concurrent_peers.insert(peer_cid, peer);
                    return true;
                }
            }
        }

        false
    }

    /// Determines if the [MessageGroupKey] maps to a [MessageGroup]
    pub async fn message_group_exists(&self, key: MessageGroupKey) -> bool {
        let this = self.inner.read().await;
        if let Some(map) = this.message_groups.get(&key.cid) {
            map.contains_key(&key.mgid)
        } else {
            false
        }
    }

    /// Returns the set of peers in a [MessageGroup]
    pub async fn get_peers_in_message_group(&self, key: MessageGroupKey) -> Option<Vec<u64>> {
        let this = self.inner.read().await;
        let map = this.message_groups.get(&key.cid)?;
        let message_group = map.get(&key.mgid)?;
        let peers = message_group
            .concurrent_peers
            .keys()
            .cloned()
            .collect::<Vec<u64>>();
        if peers.is_empty() {
            None
        } else {
            Some(peers)
        }
    }

    /// Removes the provided peers from the group. Returns a set of peers that were removed successfully, as well as the remaining peers
    pub async fn remove_peers_from_message_group(
        &self,
        key: MessageGroupKey,
        mut peers: Vec<u64>,
    ) -> Result<(Vec<u64>, Vec<u64>), ()> {
        let mut this = self.inner.write().await;
        let map = this.message_groups.get_mut(&key.cid).ok_or(())?;
        let message_group = map.get_mut(&key.mgid).ok_or(())?;
        //let mut peers_removed = Vec::new();
        // Keep all the peers that were not removed. I.e., if the remove operation returns None
        // then that peer wasn't removed and hence should stay in the vec
        peers.retain(|peer| message_group.concurrent_peers.remove(peer).is_some());

        let peers_remaining = message_group
            .concurrent_peers
            .keys()
            .cloned()
            .collect::<Vec<u64>>();
        let peers_successfully_removed = peers;

        Ok((peers_successfully_removed, peers_remaining))
    }

    pub async fn list_message_groups_for(&self, cid: u64) -> Option<Vec<MessageGroupKey>> {
        Some(
            self.inner
                .read()
                .await
                .message_groups
                .get(&cid)?
                .keys()
                .copied()
                .map(|mgid| MessageGroupKey { cid, mgid })
                .collect(),
        )
    }

    /// returns true if auto-accepted, false if requires the owner to accept
    /// returns None if the key does not match an active group
    pub async fn request_join(&self, peer_cid: u64, key: MessageGroupKey) -> Option<bool> {
        let mut write = self.inner.write().await;
        let group = write.message_groups.get_mut(&key.cid)?.get_mut(&key.mgid)?;
        if group.options.group_type == GroupType::Public {
            let _ = group
                .concurrent_peers
                .insert(peer_cid, MessageGroupPeer { peer_cid });
            Some(true)
        } else {
            Some(false)
        }
    }

    /// returns true if added successfully, or false if not (mailbox may be overloaded)
    /// `add_queue_if_non_existing`: Creates an event queue if non-existing (useful if target not connected yet)
    /// `target_cid`: Should be the destination
    #[allow(unused_results)]
    pub async fn try_add_mailbox(
        pers: &PersistenceHandler,
        target_cid: u64,
        signal: PeerSignal,
    ) -> Result<(), NetworkError> {
        let serialized = signal
            .serialize_to_vector()
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        let sub_key = Uuid::new_v4().to_string();

        let _ = pers
            .store_byte_map_value(target_cid, 0, MAILBOX, &sub_key, serialized)
            .await?;
        Ok(())
    }
}

impl HyperNodePeerLayerExecutor {
    pub(self) fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.waker.register(cx.waker());

        let mut this = self.inner.write();

        while let Some(res) = futures::ready!(this.delay_queue.poll_expired(cx)) {
            let (implicated_cid, ticket) = res.into_inner();
            if let Some(active_postings) = this.observed_postings.get_mut(&implicated_cid) {
                if let Some(posting) = active_postings.remove(&ticket) {
                    log::warn!(target: "citadel", "Running on_timeout for active posting {} for CID {}", ticket, implicated_cid);
                    (posting.on_timeout)(posting.signal)
                } else {
                    log::warn!(target: "citadel", "Attempted to remove active posting {} for CID {}, but failed", implicated_cid, ticket);
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl HyperNodePeerLayerInner {
    /// Determines if `peer_cid` is already attempting to register to `implicated_cid`
    /// Returns the target's ticket for their corresponding request
    pub fn check_simultaneous_register(
        &mut self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous register between {} and {}", implicated_cid, peer_cid);

        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::PostRegister(conn, _, _, _, None) = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from conn={:?} ~ {:?}", conn, implicated_cid);
            if let PeerConnectionType::LocalGroupPeer { implicated_cid: _, peer_cid: b } = conn {
                *b == implicated_cid
            } else {
                false
            }
        } else {
            false
        })
    }

    /// Determines if `peer_cid` is already attempting to connect to `implicated_cid`
    /// Returns the target's ticket and signal for their corresponding request
    pub fn check_simultaneous_connect(
        &mut self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous register between {} and {}", implicated_cid, peer_cid);

        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::PostConnect(conn, _, _, _, _) = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from conn={:?} ~ {:?}", conn, implicated_cid);
            if let PeerConnectionType::LocalGroupPeer { implicated_cid: _, peer_cid: b } = conn {
                *b == implicated_cid
            } else {
                false
            }
        } else {
            false
        })
    }

    pub fn check_simulataneous_deregister(
        &mut self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous deregister between {} and {}", implicated_cid, peer_cid);
        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::DeregistrationSuccess(peer) = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from {} == {}", peer, implicated_cid);
            *peer == implicated_cid
        } else {
            false
        })
    }

    fn check_simultaneous_event(
        &mut self,
        peer_cid: u64,
        fx: impl Fn(&TrackedPosting) -> bool,
    ) -> Option<Ticket> {
        let this = self.inner.read();
        let peer_map = this.observed_postings.get(&peer_cid)?;
        log::trace!(target: "citadel", "[simultaneous checking] peer_map len: {}", peer_map.len());
        peer_map
            .iter()
            .find(|(_, posting)| (fx)(posting))
            .map(|(ticket, _)| *ticket)
    }

    /// An observed posting is associated with the `implicated_cid`
    /// `on_timeout`: This function will be called if a timeout occurs. The provided session belongs to `implicated_cid`
    /// NOTE: the ticket MUST be unique per session, otherwise unexpired items may disappear unnecessarily! If the ticket ID's are provided
    /// by the HyperLAN client's side, this should work out
    #[allow(unused_results)]
    pub async fn insert_tracked_posting(
        &self,
        implicated_cid: u64,
        timeout: Duration,
        ticket: Ticket,
        signal: PeerSignal,
        on_timeout: impl FnOnce(PeerSignal) + SyncContextRequirements,
    ) {
        let mut this = self.inner.write();
        let delay_key = this.delay_queue.insert((implicated_cid, ticket), timeout);
        log::trace!(target: "citadel", "Creating TrackedPosting {} (Ticket: {})", implicated_cid, ticket);

        if let Some(map) = this.observed_postings.get_mut(&implicated_cid) {
            let tracked_posting = TrackedPosting::new(signal, delay_key, on_timeout);
            map.insert(ticket, tracked_posting);

            std::mem::drop(this);
            self.waker.wake();
        } else {
            log::error!(target: "citadel", "Unable to find implicated_cid in observed_posting. Bad init state?");
        }
    }

    pub fn remove_tracked_posting_inner(
        &mut self,
        implicated_cid: u64,
        ticket: Ticket,
    ) -> Option<PeerSignal> {
        log::trace!(target: "citadel", "Removing tracked posting for {} (ticket: {})", implicated_cid, ticket);
        let mut this = self.inner.write();
        if let Some(active_postings) = this.observed_postings.get_mut(&implicated_cid) {
            if let Some(active_posting) = active_postings.remove(&ticket) {
                log::trace!(target: "citadel", "Successfully removed tracked posting {} (ticket: {})", implicated_cid, ticket);
                let _ = this.delay_queue.remove(&active_posting.key);
                std::mem::drop(this);
                self.waker.wake();
                Some(active_posting.signal)
            } else {
                log::warn!(target: "citadel", "Tracked posting for {} (ticket: {}) does not exist since key for ticket does not exist", implicated_cid, ticket);
                None
            }
        } else {
            log::warn!(target: "citadel", "Tracked posting for {} (ticket: {}) does not exist since key for cid does not exist", implicated_cid, ticket);
            None
        }
    }
}

impl Stream for HyperNodePeerLayerExecutor {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.poll_purge(cx)) {
            Ok(_) => {
                // This will be awaken the next time an element is added or removed
                Poll::Pending
            }

            Err(_) => Poll::Ready(None),
        }
    }
}

impl futures::Future for HyperNodePeerLayerExecutor {
    type Output = Result<(), NetworkError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.poll_next(cx)) {
            Some(_) => Poll::Pending,
            None => Poll::Ready(Err(NetworkError::InternalError(
                "Queue handler signalled shutdown",
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(variant_size_differences)]
pub enum PeerSignal {
    // implicated_cid, icid (0 if hyperlan), target_cid (0 if all), use fcm
    PostRegister(
        PeerConnectionType,
        Username,
        Option<Username>,
        Option<Ticket>,
        Option<PeerResponse>,
    ),
    // implicated_cid, icid, target_cid
    Deregister(PeerConnectionType),
    // implicated_cid, icid, target_cid, udp enabled
    PostConnect(
        PeerConnectionType,
        Option<Ticket>,
        Option<PeerResponse>,
        SessionSecuritySettings,
        UdpMode,
    ),
    // implicated_cid, icid, target cid
    Disconnect(PeerConnectionType, Option<PeerResponse>),
    DisconnectUDP(VirtualConnectionType),
    // implicated_cid, icid
    BroadcastConnected(u64, GroupBroadcast),
    // implicated_cid, icid, target cid
    PostFileUploadRequest(PeerConnectionType, VirtualObjectMetadata, Ticket),
    // implicated_cid, icid, target cid
    AcceptFileUploadRequest(PeerConnectionType, Ticket),
    // Retrieves a list of registered peers
    GetRegisteredPeers(NodeConnectionType, Option<PeerResponse>, Option<i32>),
    // returns a list of mutuals for implicated cid, icid. Can be used to sync between the HyperLAN client and HyperLAN server
    GetMutuals(NodeConnectionType, Option<PeerResponse>),
    // Returned when an error occurs
    SignalError(Ticket, String),
    // deregistration succeeded (contains peer cid)
    DeregistrationSuccess(u64),
    // Signal has been processed; response may or may not occur
    SignalReceived(Ticket),
    // for key-exchange
    Kem(PeerConnectionType, KeyExchangeProcess),
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum UdpMode {
    Enabled,
    Disabled,
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
    Message(Vec<u8>),
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, Eq, Hash)]
pub enum PeerConnectionType {
    // implicated_cid, target_cid
    LocalGroupPeer {
        implicated_cid: u64,
        peer_cid: u64,
    },
    // implicated_cid, icid, target_cid
    ExternalGroupPeer {
        implicated_cid: u64,
        interserver_cid: u64,
        peer_cid: u64,
    },
}

impl PeerConnectionType {
    pub fn get_original_implicated_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: _target_cid,
            } => *implicated_cid,
            PeerConnectionType::ExternalGroupPeer {
                implicated_cid,
                interserver_cid: _icid,
                peer_cid: _target_cid,
            } => *implicated_cid,
        }
    }

    pub fn get_original_target_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer {
                implicated_cid: _implicated_cid,
                peer_cid: target_cid,
            } => *target_cid,
            PeerConnectionType::ExternalGroupPeer {
                implicated_cid: _implicated_cid,
                interserver_cid: _icid,
                peer_cid: target_cid,
            } => *target_cid,
        }
    }

    pub fn reverse(&self) -> PeerConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: target_cid,
            } => PeerConnectionType::LocalGroupPeer {
                implicated_cid: *target_cid,
                peer_cid: *implicated_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                implicated_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => PeerConnectionType::ExternalGroupPeer {
                implicated_cid: *target_cid,
                interserver_cid: *icid,
                peer_cid: *implicated_cid,
            },
        }
    }

    pub fn as_virtual_connection(self) -> VirtualConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: target_cid,
            } => VirtualConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: target_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                implicated_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => VirtualConnectionType::ExternalGroupPeer {
                implicated_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            },
        }
    }
}

impl Display for PeerConnectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerConnectionType::LocalGroupPeer {
                implicated_cid,
                peer_cid: target_cid,
            } => {
                write!(f, "hLAN {implicated_cid} <-> {target_cid}")
            }
            PeerConnectionType::ExternalGroupPeer {
                implicated_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => {
                write!(f, "hWAN {implicated_cid} <-> {icid} <-> {target_cid}")
            }
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum NodeConnectionType {
    // implicated_cid
    LocalGroupPeerToLocalGroupServer(u64),
    // implicated_cid, icid
    LocalGroupPeerToExternalGroupServer(u64, u64),
}

impl NodeConnectionType {
    pub fn get_implicated_cid(&self) -> u64 {
        match self {
            NodeConnectionType::LocalGroupPeerToLocalGroupServer(implicated_cid) => *implicated_cid,
            NodeConnectionType::LocalGroupPeerToExternalGroupServer(implicated_cid, _) => {
                *implicated_cid
            }
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
    RegisteredCids(Vec<u64>, Vec<bool>),
}

impl PeerResponse {
    /// no allocation occurs
    pub const fn empty_registered() -> PeerResponse {
        PeerResponse::RegisteredCids(Vec::new(), Vec::new())
    }
}

pub type Username = String;

impl From<PeerSignal> for Vec<u8> {
    fn from(val: PeerSignal) -> Self {
        val.serialize_to_vector().unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MailboxTransfer {
    Signals(Vec<PeerSignal>),
}

impl From<Vec<PeerSignal>> for MailboxTransfer {
    fn from(signals: Vec<PeerSignal>) -> Self {
        MailboxTransfer::Signals(signals)
    }
}
