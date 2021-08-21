use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::multiplex::{MultiplexedConn, MultiplexedConnKey, MultiplexedPacket};
use crate::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use crate::sync::{RelativeNodeType, SymmetricConvID};
use crate::sync::operations::net_join::NetJoin;
use crate::sync::operations::net_select::NetSelect;
use crate::sync::operations::net_select_ok::NetSelectOk;
use crate::sync::operations::net_try_join::NetTryJoin;
use crate::sync::primitives::net_mutex::{NetMutex, NetMutexLoader};
use crate::sync::primitives::NetObject;
use crate::sync::subscription::Subscribable;
use crate::sync::sync_start::NetSyncStart;
use crate::sync::primitives::net_rwlock::{NetRwLockLoader, NetRwLock};

pub type NetworkApplication = MultiplexedConn<SymmetricConvID>;

pub struct PreActionChannel<K: MultiplexedConnKey = SymmetricConvID> {
    tx: tokio::sync::mpsc::Sender<K>,
    rx: Mutex<tokio::sync::mpsc::Receiver<K>>
}

impl<K: MultiplexedConnKey> PreActionChannel<K> {
    pub(crate) fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Self { tx, rx: Mutex::new(rx) }
    }
}

pub struct PostActionChannel<K: MultiplexedConnKey = SymmetricConvID> {
    tx: Mutex<HashMap<K, tokio::sync::oneshot::Sender<()>>>,
    rx: Mutex<HashMap<K, tokio::sync::oneshot::Receiver<()>>>
}

impl<K: MultiplexedConnKey> PostActionChannel<K> {
    pub(crate) async fn send(&self, id: K) -> Result<(), anyhow::Error> {
        Ok(self.tx.lock().await.remove(&id).ok_or_else(|| anyhow::Error::msg("TX Channel does not exist (x0)"))?.send(()).map_err(|_| anyhow::Error::msg("Post-action channel for symmetric conv died"))?)
    }

    pub(crate) async fn recv(&self, id: K) -> Result<(), anyhow::Error> {
        Ok(self.rx.lock().await.remove(&id).ok_or_else(|| anyhow::Error::msg("RX Channel does not exist (x0)"))?.await?)
    }

    pub(crate) async fn setup_channel(&self, id: K) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.lock().await.insert(id, tx);
        self.rx.lock().await.insert(id, rx);
    }
}

impl<K: MultiplexedConnKey> PostActionChannel<K> {
    pub(crate) fn new() -> Self {
        let (tx, rx) = (HashMap::new(), HashMap::new());
        Self { tx: Mutex::new(tx), rx: Mutex::new(rx) }
    }
}

impl<K: MultiplexedConnKey + 'static> MultiplexedConn<K> {
    pub async fn register<T: ReliableOrderedStreamToTarget + 'static>(relative_node_type: RelativeNodeType, t: T) -> Result<Self, anyhow::Error> {
        // we begin with the receiver as usual since it is the last one to instantiate this
        match relative_node_type {
            RelativeNodeType::Receiver => {
                t.send_serialized(MultiplexedPacket::<K>::Greeter).await?;
            }

            RelativeNodeType::Initiator => {
                // wait to get the invitation from the initiator
                let _ = t.recv_serialized::<MultiplexedPacket<K>>().await?;
            }
        }

        let this = Self::new(relative_node_type, t);
        let conn_task = this.clone();

        tokio::task::spawn(async move {
            while let Ok(ref packet) = conn_task.conn.recv().await {
                if let Err(err) = conn_task.forward_packet(packet).await {
                    log::warn!("Error forwarding packet: {:?}", err.to_string());
                }
            }
        });

        Ok(this)
    }

    pub async fn forward_packet(&self, packet: &[u8]) -> Result<(), anyhow::Error> {
        let deserialized = bincode2::deserialize::<MultiplexedPacket<K>>(packet)?;
        match deserialized {
            MultiplexedPacket::ApplicationLayer { id, payload } => {
                let lock = self.subscriptions().read();
                log::info!("Looking for channel id: {:?} amongst {:?}", id, lock.keys());
                let channel_tx = lock.get(&id).ok_or_else(|| anyhow::Error::msg("Channel ID does not exist"))?;
                Ok(channel_tx.send(payload)?)
            }

            MultiplexedPacket::PreCreate{ id } => {
                Ok(self.pre_action_container().tx.send(id).await?)
            }

            MultiplexedPacket::PostDrop { id } => {
                self.post_close_container().send(id).await
            }

            _ => {
                Err(anyhow::Error::msg("Unexpected packet type"))
            }
        }
    }

    /*
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.conn.peer_addr()
    }*/

    /// Both nodes execute a function, returning once one of the functions gets evaluated
    pub fn net_select<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetSelect<'a, R>
        where
            F: Future<Output=R> {
        NetSelect::new(self, self.node_type(), future)
    }

    /// Both nodes execute a function, returning once one of the nodes achieves an Ok result
    pub fn net_select_ok<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetSelectOk<'a, R>
        where
            F: Future<Output=Result<R, anyhow::Error>> {
        NetSelectOk::new(self, self.node_type(), future)
    }

    /// Both nodes execute a function, returning the output once both nodes finish the operation
    pub fn net_join<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetJoin<'a, R>
        where
            F: Future<Output=R> {
        NetJoin::new(self, self.node_type(), future)
    }

    /// Both nodes attempt to execute a fallible function. Returns once both functions return Ok, or, when one returns an error
    pub fn net_try_join<'a, F: Send + 'a, R: Send + 'a, E: Send + 'a>(&'a self, future: F) -> NetTryJoin<'a, R, E>
        where
            F: Future<Output=Result<R, E>> {
        NetTryJoin::new(self, self.node_type(), future)
    }

    /// returns at about the same time as the adjacent node
    pub fn sync(&self) -> NetSyncStart<()> {
        NetSyncStart::<()>::new_sync_only(self, self.node_type())
    }

    /// Returns the payload to the adjacent node at about the same time. This node receives the payload sent by the adjacent node (exchange)
    pub fn sync_exchange_payload<'a, R: 'a>(&'a self, payload: R) -> NetSyncStart<'a, R>
        where
            R: Serialize + DeserializeOwned + Send + Sync {
        NetSyncStart::exchange_payload(self, self.node_type(), payload)
    }

    /// Executes a function at about the same time as the adjacent node
    /// - payload: an element to exchange with the opposite node
    pub fn sync_execute<'a, F: 'a, Fx: 'a, P: Serialize + DeserializeOwned + Send + Sync + 'a, R: 'a>(&'a self, future: Fx, payload: P) -> NetSyncStart<'a, R>
        where
            F: Future<Output=R>,
            F: Send,
            Fx: FnOnce(P) -> F,
            Fx: Send {
        NetSyncStart::new(self, self.node_type(), future, payload)
    }

    /// Creates a Mutex with an adjacent node on the network. One node must set the initial value, the other must set None
    pub fn mutex<R: NetObject + 'static>(&self, value: Option<R>) -> NetMutexLoader<R, Self> {
        NetMutex::new(self, value)
    }

    /// Creates a RwLock with an adjacent node on the network. One node must set the initial value, the other must set None
    pub fn rwlock<R: NetObject + 'static>(&self, value: Option<R>) -> NetRwLockLoader<R, Self> {
        NetRwLock::new(self, value)
    }
}

/// Ensures that the symmetric conversation ID exists between both endpoints when starting
pub struct PreActionSync<'a, S: Subscribable<UnderlyingConn=T>, T> {
    future: Pin<Box<dyn Future<Output=Result<<S as Subscribable>::BorrowedSubscriptionType<'a>, anyhow::Error>> + Send + 'a>>
}

impl<'a, S: Subscribable<UnderlyingConn=T> + 'a, T: ReliableOrderedStreamToTarget + 'static> PreActionSync<'a, S, T> {
    pub(crate) fn new(conn: &'a S) -> Self {
        Self { future: Box::pin(preaction_sync(conn)) }
    }
}

impl<'a, S: Subscribable<UnderlyingConn=T> + 'a, T: ReliableOrderedStreamToTarget + 'static> Future for PreActionSync<'a, S, T> {
    type Output = Result<<S as Subscribable>::BorrowedSubscriptionType<'a>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn preaction_sync<'a, S: Subscribable<UnderlyingConn=T, ID = K> + 'a, T: ReliableOrderedStreamToTarget + 'static, K: MultiplexedConnKey>(ptr: &'a S) -> Result<<S as Subscribable>::BorrowedSubscriptionType<'a>, anyhow::Error> {
    let mut recv_lock = ptr.pre_action_container().rx.lock().await;
    //let _post_lock = ptr.post_action_channel.rx.lock().await;
    match ptr.node_type() {
        RelativeNodeType::Receiver => {

            // generate the subscription to ensure local can begin receiving packet
            let next_id = ptr.get_next_id();
            let subscription = ptr.subscribe(next_id);
            ptr.post_close_container().setup_channel(next_id).await;

            ptr.send_pre_open_signal(next_id).await?;
            let recvd_id = recv_lock.recv().await.ok_or_else(|| anyhow::Error::msg("rx dead"))?;

            if recvd_id != next_id {
                log::error!("Invalid sync ID received. {:?} != {:?}", recvd_id, next_id);
            }

            Ok(subscription)
        }

        RelativeNodeType::Initiator => {
            let next_id = recv_lock.recv().await.ok_or_else(|| anyhow::Error::msg("rx dead"))?;
            let subscription = ptr.subscribe(next_id);
            ptr.post_close_container().setup_channel(next_id).await;
            ptr.send_pre_open_signal(next_id).await?;
            // we can safely return, knowing the adjacent node will still have the conv open to receive messages
            Ok(subscription)
        }
    }
}

pub(crate) struct PostActionSync<'a> {
    future: Pin<Box<dyn Future<Output=Result<(), anyhow::Error>> + Send + 'a>>
}

impl<'a> PostActionSync<'a> {
    pub(crate) fn new<S: Subscribable<ID=K> + 'a, K: MultiplexedConnKey + 'a>(subscribable: &'a S, id_to_close: K) -> Self {
        Self { future: Box::pin(postaction_sync(subscribable, id_to_close)) }
    }
}

impl<'a> Future for PostActionSync<'a> {
    type Output = Result<(), anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn postaction_sync<'a, S: Subscribable<ID=K> + 'a, K: MultiplexedConnKey>(subscribable: &'a S, close_id: K) -> Result<(), anyhow::Error> {
    log::info!("[Postaction] on {:?}", subscribable.node_type());
    match subscribable.node_type() {
        RelativeNodeType::Receiver => {
            subscribable.send_post_close_signal(close_id).await?;
            subscribable.recv_post_close_signal_from_stream(close_id).await?;

            Ok(())
        }

        RelativeNodeType::Initiator => {
            subscribable.recv_post_close_signal_from_stream(close_id).await?;
            subscribable.send_post_close_signal(close_id).await?;

            Ok(())
        }
    }
}