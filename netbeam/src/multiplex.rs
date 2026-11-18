//! # Network Stream Multiplexing
//!
//! Provides a robust multiplexing system for network streams, allowing multiple logical connections
//! to share a single underlying network connection. This module implements connection multiplexing
//! with automatic stream management and bi-directional communication support.
//!
//! ## Features
//!
//! * Dynamic stream multiplexing over a single connection
//! * Automatic stream ID generation and management
//! * Bi-directional communication channels
//! * Thread-safe subscription management
//! * Pre-action and post-action hooks for stream lifecycle
//! * Support for custom connection key types
//! * Reliable ordered message delivery
//! * Automatic cleanup of dropped streams
//!
//! ## Important Notes
//!
//! * Streams are automatically cleaned up when dropped
//! * All operations are thread-safe and async-aware
//! * Messages within each multiplexed stream maintain order
//! * Custom key types must implement MultiplexedConnKey trait
//! * Pre-action signals ensure proper stream initialization
//! * Post-action signals handle graceful stream closure
//!
//! ## Related Components
//!
//! * `reliable_conn`: Underlying reliable stream implementation
//! * `sync::subscription`: Stream subscription management
//! * `sync::network_application`: Network action handling
//! * `sync::RelativeNodeType`: Node type identification
//!

use crate::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use crate::sync::network_application::{PostActionChannel, PreActionChannel, INITIAL_CAPACITY};
use crate::sync::pairing::Pairing;
use crate::sync::subscription::{
    close_sequence_for_multiplexed_bistream, Subscribable, SubscriptionBiStream,
};
use crate::sync::wire::{Topic, WireRevision};
use crate::sync::{RelativeNodeType, SymmetricConvID};
use anyhow::Error;
use async_trait::async_trait;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Mutex;
use citadel_io::RwLock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// A trait representing a multiplexed connection key.
pub trait MultiplexedConnKey:
    Debug + Eq + Hash + Copy + Send + Sync + Serialize + DeserializeOwned + IDGen<Self>
{
}
impl<T: Debug + Eq + Hash + Copy + Send + Sync + Serialize + DeserializeOwned + IDGen<Self>>
    MultiplexedConnKey for T
{
}

/// A trait for generating IDs for multiplexed connections.
pub trait IDGen<Key: MultiplexedConnKey> {
    /// The type of container used to generate IDs.
    type Container: Send + Sync;
    /// Generates a new container for ID generation.
    fn generate_container() -> Self::Container;
    /// Generates the next ID in the sequence.
    fn generate_next(container: &Self::Container) -> Self;
    /// Gets the proposed next ID in the sequence.
    fn get_proposed_next(container: &Self::Container) -> Key;
    /// Advance `container` so the last-handed-out id becomes `id`, tolerating forward gaps and never
    /// moving backward. Returns `true` if `id` was the strictly-next id (the normal, no-gap case).
    /// A gap appears when a peer operation was cancelled/retried mid-handshake, leaving this side's
    /// counter behind the peer's; the skipped ids are dead (their subscriptions belonged to the
    /// cancelled attempt), so catching up to `id` is safe and keeps both sides paired.
    fn catch_up_to(container: &Self::Container, id: Key) -> bool;
}

impl IDGen<SymmetricConvID> for SymmetricConvID {
    type Container = Arc<AtomicU64>;

    fn generate_container() -> Self::Container {
        Arc::new(AtomicU64::new(0))
    }

    fn generate_next(container: &Self::Container) -> SymmetricConvID {
        (1 + container.fetch_add(1, Ordering::Relaxed)).into()
    }

    fn get_proposed_next(container: &Self::Container) -> SymmetricConvID {
        (1 + container.load(Ordering::Relaxed)).into()
    }

    fn catch_up_to(container: &Self::Container, id: SymmetricConvID) -> bool {
        let id_val: u64 = id.into();
        // `fetch_max` advances to `id` only if it is ahead (forward catch-up), never backward, and
        // returns the prior value. `prior + 1 == id` iff there was no gap (the normal case).
        let prior = container.fetch_max(id_val, Ordering::Relaxed);
        prior + 1 == id_val
    }
}

/// A multiplexed connection.
pub struct MultiplexedConn<K: MultiplexedConnKey = SymmetricConvID> {
    inner: Arc<MultiplexedConnInner<K>>,
    /// The topic `initiate_subscription` opens on (see [`MultiplexedConn::on`]).
    topic: Topic,
}

/// The inner implementation of a multiplexed connection.
pub struct MultiplexedConnInner<K: MultiplexedConnKey> {
    /// The underlying reliable connection.
    pub(crate) conn: Arc<dyn ReliableOrderedStreamToTarget>,
    /// A map of subscribers.
    subscribers: RwLock<HashMap<K, MemorySender>>,
    /// A channel for pre-action signals.
    pre_open_container: PreActionChannel<K>,
    /// A channel for post-action signals.
    post_close_container: PostActionChannel<K>,
    /// The ID generator.
    id_gen: K::Container,
    /// The current latest subscribed ID.
    current_latest_subscribed: K::Container,
    /// The node type.
    node_type: RelativeNodeType,
    /// What both ends speak (see [`WireRevision`]).
    wire: WireRevision,
    /// Subscription pairing under [`WireRevision::Exchanged`].
    pairing: Pairing<K>,
    /// Set once the transport can deliver nothing more.
    transport_closed: AtomicBool,
}

/// Bytes the peer may send to a subscription id before this side claims it. Past this the id is
/// refused: its buffer is dropped and a later claim fails, rather than the peer growing this
/// side's memory for as long as nobody reads that id.
pub const UNCLAIMED_BUFFER_LIMIT: usize = 1 << 20;

/// A memory sender.
pub struct MemorySender {
    /// The sender.
    tx: UnboundedSender<Vec<u8>>,
    /// The pre-reserved receiver.
    pre_reserved_rx: Option<UnboundedReceiver<Vec<u8>>>,
    /// Bytes buffered while `pre_reserved_rx` was unclaimed.
    unclaimed_bytes: AtomicUsize,
}

impl MemorySender {
    fn reserved() -> Self {
        let (tx, pre_reserved_rx) = unbounded_channel();
        Self {
            tx,
            pre_reserved_rx: Some(pre_reserved_rx),
            unclaimed_bytes: AtomicUsize::new(0),
        }
    }

    /// Whether `len` more bytes fit, counting only while nobody has claimed the id.
    pub(crate) fn admits(&self, len: usize) -> bool {
        if self.pre_reserved_rx.is_none() {
            return true;
        }
        let buffered = self.unclaimed_bytes.fetch_add(len, Ordering::Relaxed) + len;
        buffered <= UNCLAIMED_BUFFER_LIMIT
    }
}

impl Deref for MemorySender {
    type Target = UnboundedSender<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl<K: MultiplexedConnKey> Deref for MultiplexedConn<K> {
    type Target = MultiplexedConnInner<K>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// A multiplexed packet.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) enum MultiplexedPacket<K: MultiplexedConnKey> {
    /// An application layer packet.
    ApplicationLayer { id: K, payload: Vec<u8> },
    /// A post-drop packet.
    PostDrop { id: K },
    /// A pre-create packet.
    PreCreate { id: K },
    /// A greeter packet.
    Greeter,
    /// [`WireRevision::Exchanged`]: the receiver proposes `id` for `topic`.
    Open { topic: Topic, id: K },
    /// [`WireRevision::Exchanged`]: the initiator took the proposed `id`.
    OpenAck { id: K },
}

impl<K: MultiplexedConnKey> MultiplexedConn<K> {
    /// Creates a new multiplexed connection.
    pub fn new<T: ReliableOrderedStreamToTarget + 'static>(
        node_type: RelativeNodeType,
        conn: T,
        wire: WireRevision,
    ) -> Self {
        let id_gen = K::generate_container();
        // Only the count-paired wire opens ids without asking the peer.
        let pre_reserved = match wire {
            WireRevision::CountPaired => INITIAL_CAPACITY,
            WireRevision::Exchanged => 0,
        };
        let ids: Vec<K> = (0..pre_reserved)
            .map(|_| <K as IDGen<K>>::generate_next(&id_gen))
            .collect();
        // the next two lines will generate a list of pre-established bistreams
        let post_close_container = PostActionChannel::new(&ids);
        let subscribers = ids
            .into_iter()
            .map(|id| (id, MemorySender::reserved()))
            .collect::<HashMap<_, _>>();

        let current_latest_subscribed = K::generate_container();

        Self {
            inner: Arc::new(MultiplexedConnInner {
                conn: Arc::new(conn),
                subscribers: RwLock::new(subscribers),
                pre_open_container: PreActionChannel::new(),
                post_close_container,
                current_latest_subscribed,
                id_gen,
                node_type,
                wire,
                pairing: Pairing::new(),
                transport_closed: AtomicBool::new(false),
            }),
            topic: Topic::GENERAL,
        }
    }

    /// This connection with its subscriptions opened on `topic`: they pair only with the peer's
    /// subscriptions on the same topic (under [`WireRevision::Exchanged`]; the count-paired wire
    /// has no topics).
    pub fn on(&self, topic: Topic) -> Self {
        Self {
            inner: self.inner.clone(),
            topic,
        }
    }

    pub fn wire_revision(&self) -> WireRevision {
        self.wire
    }

    pub(crate) fn mark_transport_closed(&self) {
        self.transport_closed.store(true, Ordering::Release);
        self.pairing.close();
    }
}

impl<K: MultiplexedConnKey> Clone for MultiplexedConn<K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            topic: self.topic,
        }
    }
}

/// A multiplexed subscription.
pub struct MultiplexedSubscription<'a, K: MultiplexedConnKey = SymmetricConvID> {
    /// A reference to the multiplexed connection.
    ptr: &'a MultiplexedConn<K>,
    /// The receiver.
    receiver: Option<Mutex<UnboundedReceiver<Vec<u8>>>>,
    /// The ID.
    id: K,
}

impl<K: MultiplexedConnKey> SubscriptionBiStream for MultiplexedSubscription<'_, K> {
    type Conn = Arc<dyn ReliableOrderedStreamToTarget + 'static>;
    type ID = K;

    fn conn(&self) -> &Self::Conn {
        &self.ptr.conn
    }

    fn receiver(&self) -> &Mutex<UnboundedReceiver<Vec<u8>>> {
        self.receiver.as_ref().unwrap()
    }

    fn id(&self) -> Self::ID {
        self.id
    }

    fn node_type(&self) -> RelativeNodeType {
        self.ptr.node_type
    }

    fn wire_revision(&self) -> WireRevision {
        self.ptr.wire
    }
}

impl<K: MultiplexedConnKey> From<MultiplexedSubscription<'_, K>>
    for OwnedMultiplexedSubscription<K>
{
    fn from(mut this: MultiplexedSubscription<'_, K>) -> Self {
        let ret = Self {
            ptr: this.ptr.clone(),
            receiver: this.receiver.take().unwrap(),
            id: this.id,
        };

        // prevent destructor from running
        std::mem::forget(this);
        ret
    }
}

/// An owned multiplexed subscription.
pub struct OwnedMultiplexedSubscription<K: MultiplexedConnKey + 'static = SymmetricConvID> {
    /// The multiplexed connection.
    ptr: MultiplexedConn<K>,
    /// The receiver.
    receiver: Mutex<UnboundedReceiver<Vec<u8>>>,
    /// The ID.
    id: K,
}

impl<K: MultiplexedConnKey> SubscriptionBiStream for OwnedMultiplexedSubscription<K> {
    type Conn = Arc<dyn ReliableOrderedStreamToTarget + 'static>;
    type ID = K;

    fn conn(&self) -> &Self::Conn {
        &self.ptr.conn
    }

    fn receiver(&self) -> &Mutex<UnboundedReceiver<Vec<u8>>> {
        &self.receiver
    }

    fn id(&self) -> Self::ID {
        self.id
    }

    fn node_type(&self) -> RelativeNodeType {
        self.ptr.node_type
    }

    fn wire_revision(&self) -> WireRevision {
        self.ptr.wire
    }
}

#[async_trait]
impl<K: MultiplexedConnKey + 'static> Subscribable for MultiplexedConn<K> {
    type ID = K;
    type UnderlyingConn = Arc<dyn ReliableOrderedStreamToTarget + 'static>;
    type SubscriptionType = OwnedMultiplexedSubscription<K>;
    //type BorrowedSubscriptionType<'a> = MultiplexedSubscription<'a, K>;
    type BorrowedSubscriptionType = OwnedMultiplexedSubscription<K>;

    fn underlying_conn(&self) -> &Self::UnderlyingConn {
        &self.conn
    }

    fn subscriptions(&self) -> &RwLock<HashMap<Self::ID, MemorySender>> {
        &self.subscribers
    }

    fn post_close_container(&self) -> &PostActionChannel<Self::ID> {
        &self.post_close_container
    }

    fn pre_action_container(&self) -> &PreActionChannel<Self::ID> {
        &self.pre_open_container
    }

    async fn recv_post_close_signal_from_stream(&self, id: Self::ID) -> Result<(), Error> {
        self.post_close_container.recv(id).await
    }

    async fn send_post_close_signal(&self, id: Self::ID) -> Result<(), Error> {
        Ok(self
            .conn
            .send_serialized(MultiplexedPacket::PostDrop { id })
            .await?)
    }

    async fn send_pre_open_signal(&self, id: Self::ID) -> Result<(), Error> {
        Ok(self
            .conn
            .send_serialized(MultiplexedPacket::PreCreate { id })
            .await?)
    }

    async fn send_open(&self, topic: Topic, id: Self::ID) -> Result<(), Error> {
        Ok(self
            .conn
            .send_serialized(MultiplexedPacket::Open { topic, id })
            .await?)
    }

    async fn send_open_ack(&self, id: Self::ID) -> Result<(), Error> {
        Ok(self
            .conn
            .send_serialized(MultiplexedPacket::OpenAck { id })
            .await?)
    }

    fn node_type(&self) -> RelativeNodeType {
        self.node_type
    }

    fn wire_revision(&self) -> WireRevision {
        self.wire
    }

    fn topic(&self) -> Topic {
        self.topic
    }

    fn pairing(&self) -> &Pairing<Self::ID> {
        &self.pairing
    }

    fn transport_closed(&self) -> bool {
        self.transport_closed.load(Ordering::Acquire)
    }

    fn get_next_prereserved(&self) -> Option<Self::BorrowedSubscriptionType> {
        let mut lock = self.subscribers.write();
        let next_key = K::get_proposed_next(&self.current_latest_subscribed);
        let pre_reserved_stream = lock.get_mut(&next_key)?;
        let sub = MultiplexedSubscription {
            ptr: self,
            receiver: Some(Mutex::new(pre_reserved_stream.pre_reserved_rx.take()?)),
            id: next_key,
        };
        assert_eq!(K::generate_next(&self.current_latest_subscribed), next_key);
        Some(sub.into())
    }

    fn reserve(&self, id: Self::ID) {
        self.subscribers
            .write()
            .entry(id)
            .or_insert_with(MemorySender::reserved);
    }

    fn claim_reserved(&self, id: Self::ID) -> Option<Self::BorrowedSubscriptionType> {
        let receiver = self
            .subscribers
            .write()
            .get_mut(&id)?
            .pre_reserved_rx
            .take()?;
        let sub = MultiplexedSubscription {
            ptr: self,
            receiver: Some(Mutex::new(receiver)),
            id,
        };
        // as in `subscribe`: the peer drives the id
        let _ = K::catch_up_to(&self.current_latest_subscribed, id);
        Some(sub.into())
    }

    fn subscribe(&self, id: Self::ID) -> Self::BorrowedSubscriptionType {
        let mut lock = self.subscribers.write();
        let (tx, receiver) = unbounded_channel();
        let sub = MultiplexedSubscription {
            ptr: self,
            receiver: Some(Mutex::new(receiver)),
            id,
        };
        assert!(lock
            .insert(
                id,
                MemorySender {
                    tx,
                    pre_reserved_rx: None,
                    unclaimed_bytes: AtomicUsize::new(0),
                }
            )
            .is_none());
        // Catch up to the peer-driven `id` instead of asserting a strict +1 sequence. A forward gap
        // means a prior peer operation was cancelled/retried mid-handshake, leaving this side's
        // counter behind; the skipped ids are dead, and panicking here (the old assert_eq!) is what
        // desynced every subsequent subscription and silently failed the hole-punch consensus on
        // retry. Duplicate/backward ids are still rejected by the `insert(...).is_none()` assert
        // above. No-op in the normal no-gap case.
        if !K::catch_up_to(&self.current_latest_subscribed, id) {
            log::trace!(target: "citadel", "Multiplex: tolerated subscription id gap up to {id:?} (a prior peer op was cancelled/retried)");
        }
        // TODO: on GAT stabalization, remove into
        sub.into()
    }

    fn owned_subscription(&self, id: Self::ID) -> Self::SubscriptionType {
        self.subscribe(id)
    }

    fn get_next_id(&self) -> Self::ID {
        <K as IDGen<K>>::generate_next(&self.id_gen)
    }
}

impl<K: MultiplexedConnKey + 'static> Drop for OwnedMultiplexedSubscription<K> {
    fn drop(&mut self) {
        close_sequence_for_multiplexed_bistream(self.id, self.ptr.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::multiplex::OwnedMultiplexedSubscription;
    use crate::reliable_conn::ReliableOrderedStreamToTargetExt;
    use crate::sync::network_application::NetworkApplication;
    use crate::sync::subscription::{Subscribable, SubscriptionBiStreamExt};
    use crate::sync::test_utils::create_streams;
    use crate::sync::SymmetricConvID;
    use async_recursion::async_recursion;
    use citadel_io::tokio;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Packet(usize);

    // Validates the primitive behind the hole-punch retry-desync fix: a node that has fallen behind
    // (because a prior peer subscription was cancelled/retried, skipping ids) must be able to CATCH
    // UP to the peer-driven id instead of panicking — while never moving its counter backward.
    #[test]
    fn catch_up_to_tolerates_forward_gaps_only() {
        use crate::multiplex::IDGen;
        use crate::sync::SymmetricConvID;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        type S = SymmetricConvID;
        let c = Arc::new(AtomicU64::new(0));
        // Sequential ids: no gap.
        assert!(<S as IDGen<S>>::catch_up_to(&c, 1.into()));
        assert!(<S as IDGen<S>>::catch_up_to(&c, 2.into()));
        assert_eq!(c.load(Ordering::Relaxed), 2);
        // Forward gap (3,4,5 were dead ids from a cancelled attempt): tolerated, counter catches up.
        assert!(!<S as IDGen<S>>::catch_up_to(&c, 6.into()));
        assert_eq!(c.load(Ordering::Relaxed), 6);
        // Sequential again from the caught-up base.
        assert!(<S as IDGen<S>>::catch_up_to(&c, 7.into()));
        // Backward id never moves the counter back (true duplicates are caught by the subscriber map).
        assert!(!<S as IDGen<S>>::catch_up_to(&c, 5.into()));
        assert_eq!(c.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn nested_multiplexed_stream() {
        let (outer_stream_server, outer_stream_client) = create_streams().await;
        // 50 recursions deep ....
        nested(0, 50, outer_stream_server, outer_stream_client).await;
    }

    // Clippy 1.99's double_must_use fires on async_recursion's generated #[must_use] (1.1.1 is
    // the newest release); the attribute is the macro's, not ours.
    #[allow(clippy::double_must_use)]
    #[async_recursion]
    async fn nested(
        idx: usize,
        max: usize,
        server_stream: NetworkApplication,
        client_stream: NetworkApplication,
    ) -> (NetworkApplication, NetworkApplication) {
        if idx == max {
            return (server_stream, client_stream);
        }

        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_stream0, client_stream0) = (server_stream.clone(), client_stream.clone());

        let server = citadel_io::tokio::spawn(async move {
            // get one substream from the input stream
            let next_stream: OwnedMultiplexedSubscription =
                server_stream.initiate_subscription().await.unwrap();
            next_stream.send_serialized(Packet(idx)).await.unwrap();
            rx.await.unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let client = citadel_io::tokio::spawn(async move {
            let next_stream: OwnedMultiplexedSubscription =
                client_stream.initiate_subscription().await.unwrap();
            let val = next_stream.recv_serialized::<Packet>().await.unwrap();
            assert_eq!(val.0, idx);
            tx.send(()).unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let (tx1, rx1) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server1 = citadel_io::tokio::spawn(async move {
            // get one substream from the input stream
            let next_stream: OwnedMultiplexedSubscription =
                server_stream0.initiate_subscription().await.unwrap();
            next_stream.send_serialized(Packet(idx + 10)).await.unwrap();
            rx1.await.unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let client1 = citadel_io::tokio::spawn(async move {
            let next_stream: OwnedMultiplexedSubscription =
                client_stream0.initiate_subscription().await.unwrap();
            let val = next_stream.recv_serialized::<Packet>().await.unwrap();
            assert_eq!(val.0, idx + 10);
            tx1.send(()).unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let (next_server_stream, next_client_stream, _, _) =
            citadel_io::tokio::join!(server, client, server1, client1);

        nested(
            idx + 1,
            max,
            next_server_stream.unwrap(),
            next_client_stream.unwrap(),
        )
        .await
    }
}

#[cfg(test)]
#[path = "multiplex_unclaimed_tests.rs"]
mod unclaimed_tests;
