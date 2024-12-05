/*!
# Peer Layer Module

This module implements the core peer-to-peer networking layer for the Citadel Protocol, providing high-level abstractions for managing peer connections, message groups, and peer signal routing.

## Features
- **Peer Signal Management**: Handles routing and tracking of peer signals between nodes
- **Message Group Support**: Implements group messaging functionality with support for concurrent and pending peers
- **Ticket-based Connection Handling**: Uses unique tickets for tracking connection attempts and simultaneous connections
- **Timeout Management**: Provides configurable timeouts for peer operations with callback support
- **HyperLAN Integration**: Specialized support for HyperLAN client communication and state management

## Core Components
- `HyperNodePeerLayer`: Main interface for peer operations and message group management
- `PeerSignal`: Enum representing different types of peer-to-peer communication signals
- `MessageGroup`: Handles group messaging with support for concurrent and pending peers
- `TrackedPosting`: Tracks peer signal states with timeout support

## Example Usage
```rust
let peer_layer = HyperNodePeerLayer::new(persistence_handler);

// Create a new message group
let group_key = peer_layer.create_new_message_group(
    session_cid,
    &initial_peers,
    message_group_options
)?;

// Add peers to the group
peer_layer.add_pending_peers_to_group(group_key, new_peers);

// Upgrade a peer from pending to concurrent
peer_layer.upgrade_peer_in_group(group_key, peer_cid);
```

## Important Notes
1. Peer signals are tracked using unique tickets per session to prevent unintended expiration
2. Message groups support both concurrent (active) and pending (invited) peers
3. The module integrates with HyperLAN for advanced networking capabilities
4. Proper cleanup is handled through the `on_session_shutdown` method

## Related Components
- `session`: Manages the overall session state
- `packet_processor`: Handles packet processing and routing
- `state_container`: Manages connection state
- `message_group`: Implements group messaging functionality

*/

use crate::error::NetworkError;
use crate::macros::SyncContextRequirements;
use crate::prelude::PreSharedKey;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::message_group::{MessageGroup, MessageGroupPeer};
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::remote::Ticket;
use crate::proto::state_container::VirtualConnectionType;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_io::tokio::time::error::Error;
use citadel_io::tokio::time::Duration;
use citadel_io::tokio_util::time::{delay_queue, delay_queue::DelayQueue};
use citadel_types::prelude::PeerInfo;
use citadel_types::proto::{
    GroupType, MessageGroupKey, MessageGroupOptions, SessionSecuritySettings, UdpMode,
    VirtualObjectMetadata,
};
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
use uuid::Uuid;

pub trait PeerLayerTimeoutFunction: FnOnce(PeerSignal) + SyncContextRequirements {}
impl<T: FnOnce(PeerSignal) + SyncContextRequirements> PeerLayerTimeoutFunction for T {}

/// When HyperLAN client A needs to send a POST_REGISTER signal to HyperLAN client B (who is disconnected),
/// the request needs to stay in memory until either the peer joins OR HyperLAN client A disconnects. Hence the need for this layer
pub struct CitadelNodePeerLayerInner<R: Ratchet> {
    // When a signal is routed to the target destination, the server needs to keep track of the state while awaiting
    pub(crate) persistence_handler: PersistenceHandler<R, R>,
    pub(crate) message_groups: HashMap<u64, HashMap<u128, MessageGroup>>,
    pub(crate) simultaneous_ticket_mappings: HashMap<u64, HashMap<Ticket, Ticket>>,
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
pub struct CitadelNodePeerLayer<R: Ratchet> {
    pub(crate) inner: std::sync::Arc<citadel_io::tokio::sync::RwLock<CitadelNodePeerLayerInner<R>>>,
    waker: std::sync::Arc<AtomicWaker>,
}

pub struct CitadelNodePeerLayerExecutor {
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

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new(persistence_handler: PersistenceHandler<R, R>) -> CitadelNodePeerLayer<R> {
        let waker = Arc::new(AtomicWaker::new());
        let inner = CitadelNodePeerLayerInner {
            waker: waker.clone(),
            inner: Arc::new(citadel_io::RwLock::new(Default::default())),
            simultaneous_ticket_mappings: Default::default(),
            persistence_handler,
            message_groups: HashMap::new(),
        };
        let inner = Arc::new(citadel_io::tokio::sync::RwLock::new(inner));

        Self { inner, waker }
    }

    pub async fn create_executor(&self) -> CitadelNodePeerLayerExecutor {
        CitadelNodePeerLayerExecutor {
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
    pub async fn on_session_shutdown(&self, session_cid: u64) -> Result<(), NetworkError> {
        let pers = {
            let mut this = self.inner.write().await;
            this.message_groups.remove(&session_cid);
            this.inner.write().observed_postings.remove(&session_cid);
            this.persistence_handler.clone()
        };

        let _ = pers
            .remove_byte_map_values_by_key(session_cid, 0, MAILBOX)
            .await?;
        Ok(())
    }

    /// Creates a new [MessageGroup]. Returns the key upon completion
    #[allow(unused_results)]
    pub async fn create_new_message_group(
        &self,
        session_cid: u64,
        initial_peers: &Vec<u64>,
        options: MessageGroupOptions,
    ) -> Option<MessageGroupKey> {
        let mut this = self.inner.write().await;
        let map = this.message_groups.get_mut(&session_cid)?;
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

                // add the session_cid to the concurrent peers
                message_group.concurrent_peers.insert(
                    session_cid,
                    MessageGroupPeer {
                        peer_cid: session_cid,
                    },
                );

                e.insert(message_group);
                Some(MessageGroupKey {
                    cid: session_cid,
                    mgid,
                })
            } else {
                None
            }
        } else {
            log::warn!(target: "citadel", "The maximum number of groups per session has been reached for {}", session_cid);
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

    #[allow(unused_results)]
    // Removes a peer from pending
    pub async fn remove_pending_peer_from_group(
        &self,
        key: MessageGroupKey,
        peer_cid: u64,
    ) -> bool {
        let mut this = self.inner.write().await;
        if let Some(map) = this.message_groups.get_mut(&key.cid) {
            if let Some(entry) = map.get_mut(&key.mgid) {
                if entry.pending_peers.remove(&peer_cid).is_some() {
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
        pers: &PersistenceHandler<R, R>,
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

impl CitadelNodePeerLayerExecutor {
    pub(self) fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.waker.register(cx.waker());

        let mut this = self.inner.write();

        while let Some(res) = futures::ready!(this.delay_queue.poll_expired(cx)) {
            let (session_cid, ticket) = res.into_inner();
            if let Some(active_postings) = this.observed_postings.get_mut(&session_cid) {
                if let Some(posting) = active_postings.remove(&ticket) {
                    log::warn!(target: "citadel", "Running on_timeout for active posting {} for CID {}", ticket, session_cid);
                    (posting.on_timeout)(posting.signal)
                } else {
                    log::warn!(target: "citadel", "Attempted to remove active posting {} for CID {}, but failed", session_cid, ticket);
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<R: Ratchet> CitadelNodePeerLayerInner<R> {
    pub fn insert_mapped_ticket(&mut self, cid: u64, ticket: Ticket, mapped_ticket: Ticket) {
        self.simultaneous_ticket_mappings
            .entry(cid)
            .or_default()
            .insert(ticket, mapped_ticket);
    }

    pub fn take_mapped_ticket(&mut self, cid: u64, ticket: Ticket) -> Option<Ticket> {
        self.simultaneous_ticket_mappings
            .get_mut(&cid)?
            .remove(&ticket)
    }
    /// Determines if `peer_cid` is already attempting to register to `session_cid`
    /// Returns the target's ticket for their corresponding request
    pub fn check_simultaneous_register(
        &mut self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous register between {} and {}", session_cid, peer_cid);

        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::PostRegister { peer_conn_type: conn, inviter_username: _, invitee_username: _, ticket_opt: _, invitee_response: None, .. } = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from conn={:?} ~ {:?}", conn, session_cid);
            if let PeerConnectionType::LocalGroupPeer { session_cid: _, peer_cid: b } = conn {
                *b == session_cid
            } else {
                false
            }
        } else {
            false
        })
    }

    /// Determines if `peer_cid` is already attempting to connect to `session_cid`
    /// Returns the target's ticket and signal for their corresponding request
    pub fn check_simultaneous_connect(
        &mut self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous register between {} and {}", session_cid, peer_cid);

        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::PostConnect { peer_conn_type: conn, ticket_opt: _, invitee_response: _, session_security_settings: _, udp_mode: _, .. } = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from conn={:?} ~ {:?}", conn, session_cid);
            if let PeerConnectionType::LocalGroupPeer { session_cid: _, peer_cid: b } = conn {
                *b == session_cid
            } else {
                false
            }
        } else {
            false
        })
    }

    pub fn check_simultaneous_deregister(
        &mut self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Option<Ticket> {
        log::trace!(target: "citadel", "Checking simultaneous deregister between {} and {}", session_cid, peer_cid);
        self.check_simultaneous_event(peer_cid, |posting| if let PeerSignal::DeregistrationSuccess { peer_conn_type: peer } = &posting.signal {
            log::trace!(target: "citadel", "Checking if posting from {} == {}", peer, session_cid);
            peer.get_original_target_cid() == session_cid
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
        log::trace!(target: "citadel", "[simultaneous checking] peer_map len: {} | {:?}", peer_map.len(), peer_map.values().map(|r| &r.signal).collect::<Vec<_>>());
        peer_map
            .iter()
            .find(|(_, posting)| (fx)(posting))
            .map(|(ticket, _)| *ticket)
    }

    /// An observed posting is associated with the `session_cid`
    /// `on_timeout`: This function will be called if a timeout occurs. The provided session belongs to `session_cid`
    /// NOTE: the ticket MUST be unique per session, otherwise unexpired items may disappear unnecessarily! If the ticket ID's are provided
    /// by the HyperLAN client's side, this should work out
    #[allow(unused_results)]
    pub async fn insert_tracked_posting(
        &self,
        session_cid: u64,
        timeout: Duration,
        ticket: Ticket,
        signal: PeerSignal,
        on_timeout: impl FnOnce(PeerSignal) + SyncContextRequirements,
    ) {
        let mut this = self.inner.write();
        let delay_key = this.delay_queue.insert((session_cid, ticket), timeout);
        log::trace!(target: "citadel", "Creating TrackedPosting {} (Ticket: {})", session_cid, ticket);

        if let Some(map) = this.observed_postings.get_mut(&session_cid) {
            let tracked_posting = TrackedPosting::new(signal, delay_key, on_timeout);
            map.insert(ticket, tracked_posting);

            std::mem::drop(this);
            self.waker.wake();
        } else {
            log::error!(target: "citadel", "Unable to find session_cid in observed_posting. Bad init state?");
        }
    }

    pub fn remove_tracked_posting_inner(
        &mut self,
        session_cid: u64,
        ticket: Ticket,
    ) -> Option<PeerSignal> {
        log::trace!(target: "citadel", "Removing tracked posting for {} (ticket: {})", session_cid, ticket);
        let mut this = self.inner.write();
        if let Some(active_postings) = this.observed_postings.get_mut(&session_cid) {
            if let Some(active_posting) = active_postings.remove(&ticket) {
                log::trace!(target: "citadel", "Successfully removed tracked posting {} (ticket: {})", session_cid, ticket);
                let _ = this.delay_queue.remove(&active_posting.key);
                std::mem::drop(this);
                self.waker.wake();
                Some(active_posting.signal)
            } else {
                log::warn!(target: "citadel", "Tracked posting for {} (ticket: {}) does not exist since key for ticket does not exist", session_cid, ticket);
                None
            }
        } else {
            log::warn!(target: "citadel", "Tracked posting for {} (ticket: {}) does not exist since key for cid does not exist", session_cid, ticket);
            None
        }
    }
}

impl Stream for CitadelNodePeerLayerExecutor {
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

impl futures::Future for CitadelNodePeerLayerExecutor {
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
    PostRegister {
        peer_conn_type: PeerConnectionType,
        inviter_username: Username,
        invitee_username: Option<Username>,
        ticket_opt: Option<Ticket>,
        invitee_response: Option<PeerResponse>,
    },
    Deregister {
        peer_conn_type: PeerConnectionType,
    },
    PostConnect {
        peer_conn_type: PeerConnectionType,
        ticket_opt: Option<Ticket>,
        invitee_response: Option<PeerResponse>,
        session_security_settings: SessionSecuritySettings,
        udp_mode: UdpMode,
        // On the wire, this should be set to None. Should always be set to some value when submitting.
        #[serde(skip)]
        session_password: Option<PreSharedKey>,
    },
    Disconnect {
        peer_conn_type: PeerConnectionType,
        disconnect_response: Option<PeerResponse>,
    },
    DisconnectUDP {
        peer_conn_type: PeerConnectionType,
    },
    // This is used for the mailbox
    BroadcastConnected {
        session_cid: u64,
        group_broadcast: GroupBroadcast,
    },
    PostFileUploadRequest {
        peer_conn_type: PeerConnectionType,
        object_metadata: VirtualObjectMetadata,
        ticket: Ticket,
    },
    AcceptFileUploadRequest {
        peer_conn_type: PeerConnectionType,
        ticket: Ticket,
    },
    GetRegisteredPeers {
        peer_conn_type: NodeConnectionType,
        response: Option<PeerResponse>,
        limit: Option<i32>,
    },
    GetMutuals {
        v_conn_type: NodeConnectionType,
        response: Option<PeerResponse>,
    },
    SignalError {
        ticket: Ticket,
        error: String,
        peer_connection_type: PeerConnectionType,
    },
    DeregistrationSuccess {
        peer_conn_type: PeerConnectionType,
    },
    SignalReceived {
        ticket: Ticket,
    },
    #[doc(hidden)]
    Kex {
        peer_conn_type: PeerConnectionType,
        kex_payload: KeyExchangeProcess,
    },
}

// Channel packets don't get decrypted/encrypted at the central node; only at the endpoints
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ChannelPacket {
    // payload
    Message(Vec<u8>),
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, Eq, Hash)]
pub enum PeerConnectionType {
    // session_cid, target_cid
    LocalGroupPeer {
        session_cid: u64,
        peer_cid: u64,
    },
    // session_cid, icid, target_cid
    ExternalGroupPeer {
        session_cid: u64,
        interserver_cid: u64,
        peer_cid: u64,
    },
}

impl PeerConnectionType {
    pub fn get_original_session_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _target_cid,
            } => *session_cid,
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: _icid,
                peer_cid: _target_cid,
            } => *session_cid,
        }
    }

    pub fn get_original_target_cid(&self) -> u64 {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid: _session_cid,
                peer_cid: target_cid,
            } => *target_cid,
            PeerConnectionType::ExternalGroupPeer {
                session_cid: _session_cid,
                interserver_cid: _icid,
                peer_cid: target_cid,
            } => *target_cid,
        }
    }

    pub fn reverse(&self) -> PeerConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: target_cid,
            } => PeerConnectionType::LocalGroupPeer {
                session_cid: *target_cid,
                peer_cid: *session_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => PeerConnectionType::ExternalGroupPeer {
                session_cid: *target_cid,
                interserver_cid: *icid,
                peer_cid: *session_cid,
            },
        }
    }

    pub fn as_virtual_connection(self) -> VirtualConnectionType {
        match self {
            PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: target_cid,
            } => VirtualConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: target_cid,
            },
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => VirtualConnectionType::ExternalGroupPeer {
                session_cid,
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
                session_cid,
                peer_cid: target_cid,
            } => {
                write!(f, "hLAN {session_cid} <-> {target_cid}")
            }
            PeerConnectionType::ExternalGroupPeer {
                session_cid,
                interserver_cid: icid,
                peer_cid: target_cid,
            } => {
                write!(f, "hWAN {session_cid} <-> {icid} <-> {target_cid}")
            }
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum NodeConnectionType {
    // session_cid
    LocalGroupPeerToLocalGroupServer(u64),
    // session_cid, icid
    LocalGroupPeerToExternalGroupServer(u64, u64),
}

impl NodeConnectionType {
    pub fn get_session_cid(&self) -> u64 {
        match self {
            NodeConnectionType::LocalGroupPeerToLocalGroupServer(session_cid) => *session_cid,
            NodeConnectionType::LocalGroupPeerToExternalGroupServer(session_cid, _) => *session_cid,
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
    RegisteredCids(Vec<Option<PeerInfo>>, Vec<bool>),
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
