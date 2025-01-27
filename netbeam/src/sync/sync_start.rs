//! # Network Synchronization Start
//!
//! Implements synchronization primitives for coordinating the start of operations
//! between network nodes, with support for payload exchange during synchronization.
//!
//! ## Features
//!
//! - **Operation Synchronization**:
//!   - Two-way synchronization
//!   - Payload exchange support
//!   - Timing coordination
//!   - Node type awareness
//!
//! - **Payload Management**:
//!   - Type-safe payload exchange
//!   - Serialization support
//!   - Error handling
//!   - Timing tracking
//!
//! - **Future Integration**:
//!   - Async/await support
//!   - Future composition
//!   - Error propagation
//!   - Cancellation handling
//!
//! ## Important Notes
//!
//! - Ensures both nodes start operations simultaneously
//! - Handles network latency compensation
//! - Provides reliable payload delivery
//! - Supports timeout configuration
//!
//! ## Related Components
//!
//! - [`subscription`]: Stream subscription management
//! - [`ReliableOrderedStreamToTarget`]: Reliable streaming
//! - [`TimeTracker`]: Operation timing
//! - [`MultiplexedConnKey`]: Connection identification

use crate::multiplex::MultiplexedConnKey;
use crate::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use crate::sync::subscription::Subscribable;
use crate::sync::RelativeNodeType;
use crate::time_tracker::TimeTracker;
use futures::Future;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// synchronizes the beginning of an operation between two nodes. Includes attaching an optional payload for transmission of information between two endpoints during the transmission-sync phase
pub struct NetSyncStart<'a, R> {
    future: Pin<Box<dyn Future<Output = Result<R, anyhow::Error>> + Send + 'a>>,
}

impl<'a, R: 'a> NetSyncStart<'a, R> {
    pub fn new<
        S: Subscribable<ID = K, UnderlyingConn = Conn>,
        K: MultiplexedConnKey + 'a,
        Conn: ReliableOrderedStreamToTarget + 'static,
        F: Future<Output = R> + Send + 'a,
        Fx: FnOnce(P) -> F + Send + 'a,
        P: Serialize + DeserializeOwned + Send + Sync + 'a,
    >(
        conn: &'a S,
        relative_node_type: RelativeNodeType,
        future: Fx,
        payload: P,
    ) -> Self {
        Self {
            future: Box::pin(synchronize(conn, relative_node_type, future, payload)),
        }
    }

    /// Unlike `new`, this function will simply return the payload to the adjacent node synchronisticly with the adjacent node (i.e., both nodes receive each other's payloads at about the same time)
    pub fn exchange_payload<
        S: Subscribable<ID = K, UnderlyingConn = Conn>,
        K: MultiplexedConnKey + 'a,
        Conn: ReliableOrderedStreamToTarget + 'static,
    >(
        conn: &'a S,
        relative_node_type: RelativeNodeType,
        payload: R,
    ) -> Self
    where
        R: Serialize + DeserializeOwned + Send + Sync,
    {
        Self {
            future: Box::pin(synchronize(
                conn,
                relative_node_type,
                futures::future::ready,
                payload,
            )),
        }
    }

    /// This returned future will resolve once both sides terminate synchronisticly
    pub fn new_sync_only<
        S: Subscribable<ID = K, UnderlyingConn = Conn>,
        K: MultiplexedConnKey + 'a,
        Conn: ReliableOrderedStreamToTarget + 'static,
    >(
        conn: &'a S,
        relative_node_type: RelativeNodeType,
    ) -> NetSyncStart<'a, ()> {
        NetSyncStart::exchange_payload(conn, relative_node_type, ())
    }
}

impl<R> Future for NetSyncStart<'_, R> {
    type Output = Result<R, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[derive(Serialize, Deserialize)]
enum SyncPacket<P: Send + Sync> {
    Syn(P),
    SynAck(P),
    Ack(i64),
}

impl<P: Send + Sync> SyncPacket<P> {
    fn is_syn(&self) -> bool {
        matches!(self, Self::Syn(..))
    }

    fn is_syn_ack(&self) -> bool {
        matches!(self, Self::SynAck(..))
    }

    fn is_ack(&self) -> bool {
        matches!(self, Self::Ack(..))
    }
}

impl<P: Send + Sync> SyncPacket<P> {
    fn payload(self) -> Result<P, anyhow::Error> {
        match self {
            Self::Syn(payload) | Self::SynAck(payload) => Ok(payload),
            _ => Err(anyhow::Error::msg("Payload not attached")),
        }
    }

    fn timestamp(self) -> Result<i64, anyhow::Error> {
        match self {
            Self::Ack(ts) => Ok(ts),
            _ => Err(anyhow::Error::msg("Payload not attached (sync time)")),
        }
    }
}

async fn synchronize<
    S: Subscribable<ID = K, UnderlyingConn = Conn>,
    K: MultiplexedConnKey,
    Conn: ReliableOrderedStreamToTarget + 'static,
    F,
    Fx,
    P: Serialize + DeserializeOwned + Send + Sync,
    R,
>(
    conn: &S,
    relative_node_type: RelativeNodeType,
    future: Fx,
    payload: P,
) -> Result<R, anyhow::Error>
where
    F: Future<Output = R>,
    F: Send,
    Fx: FnOnce(P) -> F,
    Fx: Send,
{
    let conn = &(conn.initiate_subscription().await?);
    let tt = TimeTracker::new();

    match relative_node_type {
        RelativeNodeType::Receiver => {
            log::trace!(target: "citadel", "[Sync] Receiver sending SYN ...");
            let now = tt.get_global_time_ns();
            conn.send_serialized::<SyncPacket<P>>(SyncPacket::Syn(payload))
                .await?;
            log::trace!(target: "citadel", "[Sync] Receiver awaiting SYN_ACK ...");
            let payload_recv = conn
                .recv_until_serialized::<SyncPacket<P>, _>(|p| p.is_syn_ack())
                .await?
                .payload()?;
            let rtt = tt.get_global_time_ns() - now;
            let sync_time = tt.get_global_time_ns() + rtt;
            log::trace!(target: "citadel", "[Sync] Receiver sending ACK...");
            conn.send_serialized::<SyncPacket<P>>(SyncPacket::<P>::Ack(sync_time))
                .await?;

            citadel_io::tokio::time::sleep(Duration::from_nanos(rtt as _)).await;
            log::trace!(target: "citadel", "[Sync] Executing provided subroutine for receiver ...");
            Ok((future)(payload_recv).await)
        }

        RelativeNodeType::Initiator => {
            log::trace!(target: "citadel", "[Sync] Initiator awaiting SYN ...");
            let payload_recv = conn
                .recv_until_serialized::<SyncPacket<P>, _>(|p| p.is_syn())
                .await?
                .payload()?;
            log::trace!(target: "citadel", "[Sync] Initiator sending SYN_ACK ...");
            conn.send_serialized::<SyncPacket<P>>(SyncPacket::SynAck(payload))
                .await?;
            log::trace!(target: "citadel", "[Sync] Initiator awaiting ACK ...");
            let sync_time = conn
                .recv_until_serialized::<SyncPacket<P>, _>(|p| p.is_ack())
                .await?
                .timestamp()?;
            let now = tt.get_global_time_ns();

            if sync_time > now {
                let delta = i64::abs(sync_time - tt.get_global_time_ns());
                citadel_io::tokio::time::sleep(Duration::from_nanos(delta as _)).await;
            }

            log::trace!(target: "citadel", "[Sync] Executing provided subroutine for initiator ...");

            Ok((future)(payload_recv).await)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::test_utils::create_streams;
    use crate::time_tracker::TimeTracker;
    use citadel_io::tokio;
    use futures::{FutureExt, StreamExt};

    #[tokio::test]
    async fn run_parallel_many() {
        citadel_logging::setup_log();

        let (server, client) = &create_streams().await;
        let (tx, rx) = futures::channel::mpsc::unbounded();
        const COUNT: usize = 1000;

        for _ in 0..COUNT {
            let (server, client) = (server.clone(), client.clone());
            let tx = tx.clone();

            let server = async move {
                let res = server
                    .clone()
                    .sync_execute(dummy_function, 100)
                    .await
                    .unwrap();
                log::trace!(target: "citadel", "Server res: {:?}", res);
                res
            };

            let client = async move {
                let res = client
                    .clone()
                    .sync_execute(dummy_function, 99)
                    .await
                    .unwrap();
                log::trace!(target: "citadel", "Client res: {:?}", res);
                res
            };

            let (server, client) = (
                citadel_io::tokio::task::spawn(server),
                citadel_io::tokio::task::spawn(client),
            );

            let joined = futures::future::join(server, client).then(|(res0, res1)| async move {
                let (res0, res1) = (res0.unwrap(), res1.unwrap());
                log::trace!(target: "citadel", "res0: {}\nres1: {}\nDelta: {}", res0, res1, res1 - res0);
                tx.unbounded_send(()).unwrap();
            });

            citadel_io::tokio::task::spawn(joined);
        }

        rx.take(COUNT).collect::<()>().await;
    }

    #[tokio::test]
    async fn run_getter() {
        citadel_logging::setup_log();

        let (server, client) = create_streams().await;

        let server = async move {
            let res = server.sync_exchange_payload(100).await.unwrap();
            log::trace!(target: "citadel", "Server res: {:?}", res);
            res
        };

        let client = async move {
            let res = client.sync_exchange_payload(99).await.unwrap();
            log::trace!(target: "citadel", "Client res: {:?}", res);
            res
        };

        let server = citadel_io::tokio::spawn(server);
        let client = citadel_io::tokio::spawn(client);
        let (res0, res1) = citadel_io::tokio::join!(server, client);
        res0.unwrap();
        res1.unwrap();
    }

    async fn dummy_function(_payload: u64) -> i64 {
        TimeTracker::new().get_global_time_ns()
    }
}
