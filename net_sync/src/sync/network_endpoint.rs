use std::sync::Arc;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use parking_lot::RwLock;
use std::collections::HashMap;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, unbounded_channel};
use bytes::Bytes;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;
use async_trait::async_trait;

use std::future::Future;
use crate::sync::net_select_ok::NetSelectOk;
use crate::sync::sync_start::NetSyncStart;
use serde::de::DeserializeOwned;
use crate::sync::net_select::NetSelect;
use crate::sync::net_try_join::NetTryJoin;
use crate::sync::net_join::NetJoin;
use crate::sync::{SymmetricConvID, RelativeNodeType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::ops::Deref;

pub struct NetworkEndpoint<T: ReliableOrderedConnectionToTarget> {
    inner: Arc<NetworkEndpointInner<T>>
}

pub struct NetworkEndpointInner<T: ReliableOrderedConnectionToTarget> {
    conn: T,
    registrants: RwLock<HashMap<SymmetricConvID, UnboundedSender<Vec<u8>>>>,
    id_generator: AtomicU64,
    pre_action_channel: PreActionChannel,
    post_action_channel: PostActionChannel,
    relative_node_type: RelativeNodeType
}

pub struct Subscription<'a, T: ReliableOrderedConnectionToTarget + 'static> {
    ptr: &'a NetworkEndpoint<T>,
    receiver: Mutex<UnboundedReceiver<Vec<u8>>>,
    pub(crate) id: SymmetricConvID
}

struct PreActionChannel {
    tx: tokio::sync::mpsc::Sender<SymmetricConvID>,
    rx: Mutex<tokio::sync::mpsc::Receiver<SymmetricConvID>>
}

impl PreActionChannel {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Self { tx, rx: Mutex::new(rx) }
    }
}

struct PostActionChannel {
    tx: Mutex<HashMap<SymmetricConvID, tokio::sync::oneshot::Sender<()>>>,
    rx: Mutex<HashMap<SymmetricConvID, tokio::sync::oneshot::Receiver<()>>>
}

impl PostActionChannel {
    async fn send(&self, id: SymmetricConvID) -> Result<(), anyhow::Error> {
        Ok(self.tx.lock().await.remove(&id).ok_or_else(|| anyhow::Error::msg("TX Channel does not exist (x0)"))?.send(()).map_err(|_| anyhow::Error::msg("Post-action channel for symmetric conv died"))?)
    }

    async fn recv(&self, id: SymmetricConvID) -> Result<(), anyhow::Error> {
        Ok(self.rx.lock().await.remove(&id).ok_or_else(|| anyhow::Error::msg("RX Channel does not exist (x0)"))?.await?)
    }

    async fn setup_channel(&self, id: SymmetricConvID) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.lock().await.insert(id, tx);
        self.rx.lock().await.insert(id, rx);
    }
}

impl PostActionChannel {
    fn new() -> Self {
        let (tx, rx) = (HashMap::new(), HashMap::new());
        Self { tx: Mutex::new(tx), rx: Mutex::new(rx) }
    }
}

#[derive(Serialize, Deserialize)]
enum Packet {
    ApplicationLayer { id: SymmetricConvID, payload: Vec<u8> },
    PreActionVerify { expected_id: SymmetricConvID },
    PostActionVerify { close_id: SymmetricConvID }
}

impl<T: ReliableOrderedConnectionToTarget + 'static> NetworkEndpoint<T> {
    pub async fn register(relative_node_type: RelativeNodeType, t: T) -> Result<Self, anyhow::Error> {
        // we begin with the receiver as usual since it is the last one to instantiate this
        match relative_node_type {
            RelativeNodeType::Receiver => {
                t.send_serialized(Packet::PreActionVerify { expected_id: SymmetricConvID(0) }).await?;
            }

            RelativeNodeType::Initiator => {
                // wait to get the invitation from the initiator
                let _ = t.recv_serialized::<Packet>().await?;
            }
        }

        let pre_action_channel = PreActionChannel::new();
        let post_action_channel = PostActionChannel::new();
        let this = Self { inner: Arc::new(NetworkEndpointInner { conn: t, pre_action_channel, post_action_channel, registrants: RwLock::new(HashMap::new()), id_generator: AtomicU64::new(0), relative_node_type }) };
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
        let deserialized = bincode2::deserialize::<Packet>(packet)?;
        match deserialized {
            Packet::ApplicationLayer { id, payload } => {
                let lock = self.registrants.read();
                log::info!("Looking for channel id: {:?} amongst {:?}", id, lock.keys());
                let channel_tx = lock.get(&id).ok_or_else(|| anyhow::Error::msg("Channel ID does not exist"))?;
                Ok(channel_tx.send(payload)?)
            }

            Packet::PreActionVerify { expected_id } => {
                Ok(self.pre_action_channel.tx.send(expected_id).await?)
            }

            Packet::PostActionVerify { close_id } => {
                self.post_action_channel.send(close_id).await
            }
        }
    }

    /// Returns a future which, upon resolution, ensures the next action can be safely executed
    /// This should only be called if you know what you're doing
    pub fn subscribe_internal(&self) -> PreActionSync<'_, T> {
        PreActionSync::new(self)
    }

    fn subscribe_inner(&self, id: SymmetricConvID) -> Subscription<'_, T> {
        let mut lock = self.registrants.write();
        let (tx, receiver) = unbounded_channel();
        let sub = Subscription { ptr: self, receiver: Mutex::new(receiver), id };
        let _ = lock.insert(id, tx);
        sub
    }

    pub fn node_type(&self) -> RelativeNodeType {
        self.relative_node_type
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.conn.peer_addr()
    }

    /// Both nodes execute a function, returning once one of the functions gets evaluated
    pub fn net_select<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetSelect<'a, R>
        where
            F: Future<Output=R> {
        NetSelect::new(self, self.relative_node_type, future)
    }

    /// Both nodes execute a function, returning once one of the nodes achieves an Ok result
    pub fn net_select_ok<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetSelectOk<'a, R>
        where
            F: Future<Output=Result<R, anyhow::Error>> {
        NetSelectOk::new(self, self.relative_node_type, future)
    }

    /// Both nodes execute a function, returning the output once both nodes finish the operation
    pub fn net_join<'a, F: Send + 'a, R: Send + 'a>(&'a self, future: F) -> NetJoin<'a, R>
        where
            F: Future<Output=R> {
        NetJoin::new(self, self.relative_node_type, future)
    }

    /// Both nodes attempt to execute a fallible function. Returns once both functions return Ok, or, when one returns an error
    pub fn net_try_join<'a, F: Send + 'a, R: Send + 'a, E: Send + 'a>(&'a self, future: F) -> NetTryJoin<'a, R, E>
        where
            F: Future<Output=Result<R, E>> {
        NetTryJoin::new(self, self.relative_node_type, future)
    }

    /// returns at about the same time as the adjacent node
    pub fn sync(&self) -> NetSyncStart<()> {
        NetSyncStart::<()>::new_sync_only(self, self.relative_node_type)
    }

    /// Returns the payload to the adjacent node at about the same time. This node receives the payload sent by the adjacent node (exchange)
    pub fn sync_exchange_payload<'a, R: 'a>(&'a self, payload: R) -> NetSyncStart<'a, R>
        where
            R: Serialize + DeserializeOwned + Send + Sync {
        NetSyncStart::exchange_payload(self, self.relative_node_type, payload)
    }

    /// Executes a function at about the same time as the adjacent node
    /// - payload: an element to exchange with the opposite node
    pub fn sync_execute<'a, F: 'a, Fx: 'a, P: Serialize + DeserializeOwned + Send + Sync + 'a, R: 'a>(&'a self, future: Fx, payload: P) -> NetSyncStart<'a, R>
        where
            F: Future<Output=R>,
            F: Send,
            Fx: FnOnce(P) -> F,
            Fx: Send {
        NetSyncStart::new(self, self.relative_node_type, future, payload)
    }
}

#[async_trait]
impl<T: ReliableOrderedConnectionToTarget> ReliableOrderedConnectionToTarget for Subscription<'_, T> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        let packet = Packet::ApplicationLayer { id: self.id, payload: input.to_vec() };
        self.ptr.conn.send_to_peer(&bincode2::serialize(&packet).unwrap()).await
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.receiver.lock().await.recv().await.map(Bytes::from).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Receiver died"))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.ptr.conn.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.ptr.conn.peer_addr()
    }
}

impl<T: ReliableOrderedConnectionToTarget + 'static> Drop for Subscription<'_, T> {
    fn drop(&mut self) {
        log::info!("Running DROP on {:?}", self.id);
        let id = self.id;
        let ptr = self.ptr.clone();

        fn close<T: ReliableOrderedConnectionToTarget>(id: SymmetricConvID, ptr: &NetworkEndpoint<T>) {
            let _ = ptr.registrants.write().remove(&id);
            log::info!("DROPPED id = {:?}", id);
        }


        // the runtime may not exist while dropping
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Err(err) = PostActionSync::new(&ptr, id).await {
                    log::warn!("[MetaActionSync/close] error: {:?}", err.to_string())
                } else {
                    log::info!("QWERTY success");
                }

                close(id, &ptr)
            });
        } else {
            close(id, &ptr);
        }
    }
}

impl<T: ReliableOrderedConnectionToTarget> Clone for NetworkEndpoint<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone()
        }
    }
}

impl<T: ReliableOrderedConnectionToTarget> Deref for NetworkEndpoint<T> {
    type Target = NetworkEndpointInner<T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Ensures that the symmetric conversation ID exists between both endpoints when starting
pub struct PreActionSync<'a, T: ReliableOrderedConnectionToTarget + 'static> {
    future: Pin<Box<dyn Future<Output=Result<Subscription<'a, T>, anyhow::Error>> + Send + 'a>>
}

impl<'a, T: ReliableOrderedConnectionToTarget + 'static> PreActionSync<'a, T> {
    fn new(conn: &'a NetworkEndpoint<T>) -> Self {
        Self { future: Box::pin(preaction_sync(conn)) }
    }
}

impl<'a, T: ReliableOrderedConnectionToTarget + 'static> Future for PreActionSync<'a, T> {
    type Output = Result<Subscription<'a, T>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn preaction_sync<T: ReliableOrderedConnectionToTarget + 'static>(ptr: &NetworkEndpoint<T>) -> Result<Subscription<'_, T>, anyhow::Error> {
    log::info!("[Preaction] on {:?}", ptr.relative_node_type);
    let mut recv_lock = ptr.pre_action_channel.rx.lock().await;
    //let _post_lock = ptr.post_action_channel.rx.lock().await;
    match ptr.relative_node_type {
        RelativeNodeType::Receiver => {

            log::info!("[PreAction] RD1");
            // generate the subscription to ensure local can begin receiving packet
            let next_id: SymmetricConvID = (1 + ptr.id_generator.fetch_add(1, Ordering::Relaxed)).into();
            let subscription = ptr.subscribe_inner(next_id);
            ptr.post_action_channel.setup_channel(next_id).await;

            log::info!("[PreAction] RD2 sending {:?}", next_id);
            ptr.conn.send_serialized(Packet::PreActionVerify { expected_id: subscription.id }).await?;
            log::info!("[PreAction] RD3");
            let recvd_id = recv_lock.recv().await.ok_or_else(|| anyhow::Error::msg("rx dead"))?;
            if recvd_id != next_id {
                log::error!("Invalid sync ID received. {:?} != {:?}", recvd_id, next_id);
            }
            log::info!("[PreAction] RD4");


            Ok(subscription)
        }

        RelativeNodeType::Initiator => {

            log::info!("[PreAction] LD1");
            let next_id = recv_lock.recv().await.ok_or_else(|| anyhow::Error::msg("rx dead"))?;
            log::info!("[PreAction] LD2");
            let subscription = ptr.subscribe_inner(next_id);
            ptr.post_action_channel.setup_channel(next_id).await;
            log::info!("[PreAction] LD3");
            ptr.conn.send_serialized(Packet::PreActionVerify { expected_id: next_id }).await?;
            log::info!("[PreAction] LD4");
            // we can safely return, knowing the adjacent node will still have the conv open to receive messages
            Ok(subscription)
        }
    }
}

pub(crate) struct PostActionSync<'a> {
    future: Pin<Box<dyn Future<Output=Result<(), anyhow::Error>> + Send + 'a>>
}

impl<'a> PostActionSync<'a> {
    fn new<T: ReliableOrderedConnectionToTarget + 'static>(conn: &'a NetworkEndpoint<T>, id_to_close: SymmetricConvID) -> Self {
        Self { future: Box::pin(postaction_sync(conn, id_to_close)) }
    }
}

impl<'a> Future for PostActionSync<'a> {
    type Output = Result<(), anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn postaction_sync<T: ReliableOrderedConnectionToTarget + 'static>(ptr: &NetworkEndpoint<T>, close_id: SymmetricConvID) -> Result<(), anyhow::Error> {
    log::info!("[Postaction] on {:?}", ptr.relative_node_type);
    // ensure no other local requests plague the process
    //let _out_lock = ptr.pre_action_channel.rx.lock().await;
    //let mut recv_lock = ptr.post_action_channel.rx.lock().await;
    match ptr.relative_node_type {
        RelativeNodeType::Receiver => {
            log::info!("[PostAction] R0");
            ptr.conn.send_serialized(Packet::PostActionVerify { close_id }).await?;
            log::info!("[PostAction] R1");
            ptr.post_action_channel.recv(close_id).await?;
            log::info!("[PostAction] R2");

            Ok(())
        }

        RelativeNodeType::Initiator => {
            log::info!("[PostAction] L0");
            ptr.post_action_channel.recv(close_id).await?;
            log::info!("[PostAction] L1");
            ptr.conn.send_serialized(Packet::PostActionVerify { close_id }).await?;
            log::info!("[PostAction] L2");

            Ok(())
        }
    }
}