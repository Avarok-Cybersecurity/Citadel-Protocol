
use crate::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use parking_lot::RwLock;
use std::collections::HashMap;
use crate::sync::{SymmetricConvID, RelativeNodeType};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel, UnboundedReceiver};
use std::hash::Hash;
use crate::sync::subscription::{SubscriptionBiStream, close_sequence_for_multiplexed_bistream, Subscribable};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use anyhow::Error;
use crate::sync::network_application::{PostActionChannel, PreActionChannel};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use async_trait::async_trait;

pub trait MultiplexedConnKey: Debug + Eq + Hash + Copy + Send + Sync + Serialize + DeserializeOwned + IDGen<Self> {}
impl<T: Debug + Eq + Hash + Copy + Send + Sync + Serialize + DeserializeOwned + IDGen<Self>> MultiplexedConnKey for T {}

pub trait IDGen<Key: MultiplexedConnKey> {
    type Container: Send + Sync;
    fn generate_container() -> Self::Container;
    fn generate_next(container: &Self::Container) -> Self;
}

impl IDGen<SymmetricConvID> for SymmetricConvID {
    type Container = Arc<AtomicU64>;

    fn generate_container() -> Self::Container {
        Arc::new(AtomicU64::new(0))
    }

    fn generate_next(container: &Self::Container) -> SymmetricConvID {
        (1 + container.fetch_add(1, Ordering::Relaxed)).into()
    }
}

pub struct MultiplexedConn<K: MultiplexedConnKey = SymmetricConvID> {
    inner: Arc<MultiplexedConnInner<K>>
}

pub struct MultiplexedConnInner<K: MultiplexedConnKey> {
    pub(crate) conn: Arc<dyn ReliableOrderedStreamToTarget>,
    subscribers: RwLock<HashMap<K, UnboundedSender<Vec<u8>>>>,
    pre_open_container: PreActionChannel<K>,
    post_close_container: PostActionChannel<K>,
    id_gen: K::Container,
    node_type: RelativeNodeType
}

impl<K: MultiplexedConnKey> Deref for MultiplexedConn<K> {
    type Target = MultiplexedConnInner<K>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound="")]
pub(crate) enum MultiplexedPacket<K: MultiplexedConnKey> {
    ApplicationLayer { id: K, payload: Vec<u8> },
    PostDrop { id: K },
    PreCreate { id: K },
    Greeter
}

impl<K: MultiplexedConnKey> MultiplexedConn<K> {
    pub fn new<T: ReliableOrderedStreamToTarget + 'static>(node_type: RelativeNodeType, conn: T) -> Self {
        Self { inner: Arc::new(MultiplexedConnInner { conn: Arc::new(conn), subscribers: RwLock::new(HashMap::new()), pre_open_container: PreActionChannel::new(), post_close_container: PostActionChannel::new(), id_gen: K::generate_container(), node_type })}
    }
}

impl<K: MultiplexedConnKey> Clone for MultiplexedConn<K> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

pub struct MultiplexedSubscription<'a, K: MultiplexedConnKey = SymmetricConvID> {
    ptr: &'a MultiplexedConn<K>,
    receiver: Option<Mutex<UnboundedReceiver<Vec<u8>>>>,
    id: K
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
}

impl<K: MultiplexedConnKey> From<MultiplexedSubscription<'_, K>> for OwnedMultiplexedSubscription<K> {
    fn from(mut this: MultiplexedSubscription<'_, K>) -> Self {
        let ret = Self {
            ptr: this.ptr.clone(),
            receiver: this.receiver.take().unwrap(),
            id: this.id
        };

        // prevent destructor from running
        std::mem::forget(this);
        ret
    }
}

pub struct OwnedMultiplexedSubscription<K: MultiplexedConnKey + 'static = SymmetricConvID> {
    ptr: MultiplexedConn<K>,
    receiver: Mutex<UnboundedReceiver<Vec<u8>>>,
    id: K
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
}

#[async_trait]
impl<K: MultiplexedConnKey + 'static> Subscribable for MultiplexedConn<K> {
    type ID = K;
    type UnderlyingConn = Arc<dyn ReliableOrderedStreamToTarget + 'static>;
    type SubscriptionType = OwnedMultiplexedSubscription<K>;
    type BorrowedSubscriptionType<'a> = MultiplexedSubscription<'a, K>;

    fn underlying_conn(&self) -> &Self::UnderlyingConn {
        &self.conn
    }

    fn subscriptions(&self) -> &RwLock<HashMap<Self::ID, UnboundedSender<Vec<u8>>>> {
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
        Ok(self.conn.send_serialized(MultiplexedPacket::PostDrop { id }).await?)
    }

    async fn send_pre_open_signal(&self, id: Self::ID) -> Result<(), Error> {
        Ok(self.conn.send_serialized(MultiplexedPacket::PreCreate { id }).await?)
    }

    fn node_type(&self) -> RelativeNodeType {
        self.node_type
    }

    fn subscribe(&self, id: Self::ID) -> Self::BorrowedSubscriptionType<'_> {
        let mut lock = self.subscribers.write();
        let (tx, receiver) = unbounded_channel();
        let sub = MultiplexedSubscription { ptr: self, receiver: Some(Mutex::new(receiver)), id };
        let _ = lock.insert(id, tx);
        sub
    }

    fn owned_subscription(&self, id: Self::ID) -> Self::SubscriptionType {
        self.subscribe(id).into()
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
    use crate::sync::test_utils::create_streams;
    use crate::reliable_conn::ReliableOrderedStreamToTargetExt;
    use crate::sync::network_application::NetworkApplication;
    use crate::sync::subscription::{Subscribable, SubscriptionBiStreamExt};
    use serde::{Serialize, Deserialize};
    use crate::multiplex::OwnedMultiplexedSubscription;
    use crate::sync::SymmetricConvID;
    use async_recursion::async_recursion;

    #[derive(Serialize, Deserialize)]
    struct Packet(usize);

    #[tokio::test]
    async fn nested_multiplexed_stream() {

        let (outer_stream_server, outer_stream_client) = create_streams().await;
        // 50 recursions deep ....
        nested(0, 50, outer_stream_server, outer_stream_client).await;
    }

    #[async_recursion]
    async fn nested(idx: usize, max: usize, server_stream: NetworkApplication, client_stream: NetworkApplication) -> (NetworkApplication, NetworkApplication) {
        if idx == max {
            return (server_stream, client_stream)
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (server_stream0, client_stream0) = (server_stream.clone(), client_stream.clone());

        let server = tokio::spawn(async move {
            // get one substream from the input stream
            let next_stream: OwnedMultiplexedSubscription = server_stream.initiate_subscription().await.unwrap().into();
            next_stream.send_serialized(Packet(idx)).await.unwrap();
            rx.await.unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let client = tokio::spawn(async move {
            let next_stream: OwnedMultiplexedSubscription = client_stream.initiate_subscription().await.unwrap().into();
            let val = next_stream.recv_serialized::<Packet>().await.unwrap();
            assert_eq!(val.0, idx);
            tx.send(()).unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let (tx1, rx1) = tokio::sync::oneshot::channel::<()>();

        let server1 = tokio::spawn(async move {
            // get one substream from the input stream
            let next_stream: OwnedMultiplexedSubscription = server_stream0.initiate_subscription().await.unwrap().into();
            next_stream.send_serialized(Packet(idx+10)).await.unwrap();
            rx1.await.unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let client1 = tokio::spawn(async move {
            let next_stream: OwnedMultiplexedSubscription = client_stream0.initiate_subscription().await.unwrap().into();
            let val = next_stream.recv_serialized::<Packet>().await.unwrap();
            assert_eq!(val.0, idx + 10);
            tx1.send(()).unwrap();
            next_stream.multiplex::<SymmetricConvID>().await.unwrap()
        });

        let (next_server_stream, next_client_stream, _, _) = tokio::join!(server, client, server1, client1);

        return nested(idx+1, max,next_server_stream.unwrap(), next_client_stream.unwrap()).await
    }
}