//! # Subscription Stream Implementation
//!
//! Provides bidirectional subscription-based streaming capabilities for multiplexed
//! network connections, enabling reliable ordered communication between nodes.
//!
//! ## Features
//!
//! - **Bidirectional Streaming**:
//!   - Reliable ordered message delivery
//!   - Automatic stream management
//!   - Multiplexed connections
//!   - Stream identification
//!
//! - **Subscription Management**:
//!   - Stream subscription handling
//!   - Connection lifecycle management
//!   - Node type awareness
//!   - Resource cleanup
//!
//! - **Multiplexing Support**:
//!   - Stream multiplexing
//!   - Connection sharing
//!   - Stream isolation
//!   - Connection pooling
//!
//! ## Important Notes
//!
//! - Implements async/await patterns
//! - Ensures thread-safety
//! - Handles connection cleanup
//! - Maintains message ordering
//!
//! ## Related Components
//!
//! - [`MultiplexedConn`]: Connection multiplexing
//! - [`ReliableOrderedStreamToTarget`]: Stream reliability
//! - [`network_application`]: Application integration
//! - [`RelativeNodeType`]: Node type management

use crate::multiplex::{MemorySender, MultiplexedConn, MultiplexedConnKey, MultiplexedPacket};
use crate::reliable_conn::ReliableOrderedStreamToTarget;
use crate::sync::network_application::{
    PostActionChannel, PostActionSync, PreActionChannel, PreActionSync,
};
use crate::sync::RelativeNodeType;
use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_io::tokio::sync::Mutex;
use citadel_io::RwLock;
use std::collections::HashMap;

#[async_trait]
pub trait SubscriptionBiStream: Send + Sync {
    type Conn: ReliableOrderedStreamToTarget + 'static;
    type ID: MultiplexedConnKey;

    fn conn(&self) -> &Self::Conn;
    fn receiver(&self) -> &Mutex<UnboundedReceiver<Vec<u8>>>;
    fn id(&self) -> Self::ID;
    fn node_type(&self) -> RelativeNodeType;
}

#[async_trait]
pub trait SubscriptionBiStreamExt: SubscriptionBiStream {
    /// Creates a new multiplexed level capable of obtaining more subscribers.
    /// Uses Self as a reliable ordered connection, while using NewId to identify the substreams in the created next level
    async fn multiplex<NewID: MultiplexedConnKey + 'static>(
        self,
    ) -> Result<MultiplexedConn<NewID>, anyhow::Error>
    where
        Self: Sized + 'static,
    {
        MultiplexedConn::register(self.node_type(), self).await
    }
}

impl<T: SubscriptionBiStream> SubscriptionBiStreamExt for T {}

#[async_trait::async_trait]
pub trait Subscribable: Send + Sync + Sized {
    type ID: MultiplexedConnKey;
    type UnderlyingConn: ReliableOrderedStreamToTarget + 'static;
    type SubscriptionType: SubscriptionBiStream;
    type BorrowedSubscriptionType: SubscriptionBiStream<ID = Self::ID, Conn = Self::UnderlyingConn>
        + Into<Self::SubscriptionType>;
    // TODO on stabalization of GATs: type BorrowedSubscriptionType<'a>: SubscriptionBiStream<ID=Self::ID, Conn=Self::UnderlyingConn> + Into<Self::SubscriptionType>;

    fn underlying_conn(&self) -> &Self::UnderlyingConn;
    fn subscriptions(&self) -> &RwLock<HashMap<Self::ID, MemorySender>>;
    fn post_close_container(&self) -> &PostActionChannel<Self::ID>;
    fn pre_action_container(&self) -> &PreActionChannel<Self::ID>;

    async fn recv_post_close_signal_from_stream(&self, id: Self::ID) -> Result<(), anyhow::Error>;
    async fn send_post_close_signal(&self, id: Self::ID) -> Result<(), anyhow::Error>;
    async fn send_pre_open_signal(&self, id: Self::ID) -> Result<(), anyhow::Error>;

    fn node_type(&self) -> RelativeNodeType;

    fn initiate_subscription(&self) -> PreActionSync<'_, Self, Self::UnderlyingConn> {
        PreActionSync::new(self)
    }

    fn get_next_prereserved(&self) -> Option<Self::BorrowedSubscriptionType>;
    fn subscribe(&self, id: Self::ID) -> Self::BorrowedSubscriptionType;
    fn owned_subscription(&self, id: Self::ID) -> Self::SubscriptionType;
    fn get_next_id(&self) -> Self::ID;
}

#[async_trait]
impl<R: SubscriptionBiStream + ?Sized> ReliableOrderedStreamToTarget for R {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        let packet = MultiplexedPacket::ApplicationLayer {
            id: self.id(),
            payload: input.to_vec(),
        };
        self.conn()
            .send_to_peer(&bincode::serialize(&packet).unwrap())
            .await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.receiver()
            .lock()
            .await
            .recv()
            .await
            .map(Bytes::from)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Receiver died")
            })
    }
}

pub(crate) fn close_sequence_for_multiplexed_bistream<
    S: Subscribable<ID = K> + 'static,
    K: MultiplexedConnKey + 'static,
>(
    id: K,
    ptr: S,
) {
    log::trace!(target: "citadel", "Running DROP on {:?}", id);

    fn close<S: Subscribable<ID = K>, K: MultiplexedConnKey>(id: K, ptr: &S) {
        let _ = ptr.subscriptions().write().remove(&id);
        log::trace!(target: "citadel", "DROPPED id = {:?}", id);
    }

    // the runtime may not exist while dropping
    if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
        rt.spawn(async move {
            if let Err(err) = PostActionSync::new(&ptr, id).await {
                log::warn!(target: "citadel", "[MetaActionSync/close] error: {:?}", err.to_string())
            }

            close(id, &ptr)
        });
    } else {
        close(id, &ptr);
    }
}
