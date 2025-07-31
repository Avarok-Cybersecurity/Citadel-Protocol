/*!
 * # Bidirectional Channel
 *
 * A bidirectional channel implementation that enables two-way communication between
 * network endpoints. This serves as the base abstraction for other channel types
 * in the netbeam framework.
 *
 * ## Features
 * - Two-way communication with send and receive halves
 * - Support for reliable ordered streaming
 * - Graceful channel shutdown with halt verification
 * - Async/await support with Future and Stream implementations
 * - Thread-safe operation
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::channel::bi_channel::Channel;
 * use netbeam::sync::subscription::Subscribable;
 * use anyhow::Result;
 *
 * async fn example<S: Subscribable + 'static>(connection: &S) -> Result<()> {
 *     // Create a new channel
 *     let channel = Channel::create(connection).await?;
 *
 *     // Split into send and receive halves
 *     let (sender, mut receiver) = channel.split();
 *
 *     // Send data (replace with your data type)
 *     sender.send_item("hello".to_string()).await?;
 *
 *     // Receive data
 *     if let Some(data) = receiver.recv().await {
 *         if let Ok(msg) = data {
 *             println!("Received: {:?}", msg);
 *         }
 *     }
 *     Ok(())
 * }
 * ```
 *
 * ## Related Components
 * - `callback_channel.rs`: Channel with callback support
 * - `tracked_callback_channel.rs`: Channel with request tracking
 *
 * ## Important Notes
 * - Channels implement graceful shutdown
 * - Send and receive halves can be used independently
 * - Supports reliable ordered streaming
 * - Thread-safe with atomic operations
 */

use crate::reliable_conn::ReliableOrderedStreamToTargetExt;
use crate::sync::primitives::NetObject;
use crate::sync::subscription::Subscribable;
use crate::sync::subscription::SubscriptionBiStream;
use crate::ScopedFutureResult;
use futures::{Future, Stream, StreamExt, TryFutureExt};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use sync_wrapper::SyncWrapper;

/// Inner channel type for a given subscribable type `S`.
pub(crate) type InnerChannel<S> = <S as Subscribable>::SubscriptionType;

/// Enum representing different types of packets that can be sent over the channel.
#[derive(Serialize, Deserialize, Debug)]
enum ChannelPacket<T> {
    /// A packet containing a value of type `T`.
    Packet(T),
    /// A halt signal indicating that no more packets will be sent.
    Halt,
    /// A verified halt signal indicating that the halt signal has been received.
    HaltVerified,
}

/// A bidirectional channel that enables two-way communication between network endpoints.
pub struct Channel<T: NetObject, S: Subscribable + 'static> {
    /// The receive half of the channel.
    recv: ChannelRecvHalf<T, S>,
    /// The send half of the channel.
    send: ChannelSendHalf<T, S>,
}

/// The receive half of a bidirectional channel.
pub struct ChannelRecvHalf<T: NetObject, S: Subscribable + 'static> {
    /// The receiver stream for the channel.
    receiver: ChannelRecvHalfReceiver<T>,
    /// A flag indicating whether the receive half has been halted.
    recv_halt: Arc<AtomicBool>,
    /// The inner channel for the receive half.
    tx: Option<Arc<InnerChannel<S>>>,
}

/// Type alias for a receiver stream.
type ChannelRecvHalfReceiver<T> =
    SyncWrapper<Pin<Box<dyn Stream<Item = Result<ChannelPacket<T>, anyhow::Error>> + Send>>>;

/// The send half of a bidirectional channel.
pub struct ChannelSendHalf<T: NetObject, S: Subscribable + 'static> {
    /// A flag indicating whether the receive half has been halted.
    recv_halt: Arc<AtomicBool>,
    /// The inner channel for the send half.
    tx: Option<Arc<InnerChannel<S>>>,
    /// A phantom data marker for the type `T`.
    _pd: PhantomData<T>,
}

impl<T: NetObject, S: Subscribable + 'static> ChannelSendHalf<T, S> {
    /// Sends an item over the channel.
    pub async fn send_item(&self, t: T) -> Result<(), anyhow::Error> {
        if self.recv_halt.load(Ordering::Relaxed) {
            Err(anyhow::Error::msg(
                "Receiving end not receiving any new values",
            ))
        } else {
            Ok(self
                .get_chan()
                .send_serialized(ChannelPacket::Packet(t))
                .await?)
        }
    }

    /// Gets a reference to the inner channel.
    fn get_chan(&self) -> &InnerChannel<S> {
        self.tx.as_ref().unwrap()
    }
}

impl<T: NetObject, S: Subscribable + 'static> ChannelRecvHalf<T, S> {
    /// Receives an item from the channel.
    pub async fn recv(&mut self) -> Option<Result<T, anyhow::Error>> {
        let packet = Pin::new(&mut self.receiver).get_pin_mut().next().await?;
        Some(self.process_packet(packet))
    }

    /// Processes a packet received from the channel.
    fn process_packet(
        &mut self,
        packet: Result<ChannelPacket<T>, anyhow::Error>,
    ) -> Result<T, anyhow::Error> {
        match packet? {
            ChannelPacket::Packet(res) => Ok(res),

            _ => {
                self.recv_halt.store(true, Ordering::Relaxed);
                Err(anyhow::Error::msg("Halt received"))
            }
        }
    }
}

impl<T: NetObject, S: Subscribable + 'static> Channel<T, S> {
    /// Creates a new channel.
    pub fn create(conn: &S) -> ChannelLoader<'_, T, S> {
        ChannelLoader {
            inner: Box::pin(
                conn.initiate_subscription()
                    .and_then(|r| futures::future::ok(Channel::new_internal(r.into()))),
            ),
        }
    }

    /// Sends an item over the channel.
    pub async fn send_item(&self, t: T) -> Result<(), anyhow::Error> {
        self.send.send_item(t).await
    }

    /// Receives an item from the channel.
    pub async fn recv(&mut self) -> Option<Result<T, anyhow::Error>> {
        self.recv.recv().await
    }

    /// Creates a new internal channel.
    fn new_internal(chan: InnerChannel<S>) -> Self {
        let chan = Arc::new(chan);
        let chan_stream = chan.clone();

        let recv_halt = Arc::new(AtomicBool::new(false));
        let recv_halt_inner_receiver = recv_halt.clone();

        let stream = async_stream::try_stream! {
            loop {
                if recv_halt_inner_receiver.load(Ordering::Relaxed) {
                    Err(anyhow::Error::msg("Adjacent node no longer sending values"))?
                } else {
                    let ret = chan_stream.recv_serialized::<ChannelPacket<T>>().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
                    yield ret;
                }
            }
        };

        Self {
            recv: ChannelRecvHalf {
                receiver: SyncWrapper::new(Box::pin(stream)),
                recv_halt: recv_halt.clone(),
                tx: Some(chan.clone()),
            },

            send: ChannelSendHalf {
                recv_halt,
                tx: Some(chan),
                _pd: Default::default(),
            },
        }
    }

    /// Splits the channel into send and receive halves.
    pub fn split(self) -> (ChannelSendHalf<T, S>, ChannelRecvHalf<T, S>) {
        (self.send, self.recv)
    }
}

impl<T: NetObject + Unpin, S: Subscribable + 'static> Stream for Channel<T, S> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().recv).poll_next(cx)
    }
}

impl<T: NetObject, S: Subscribable + 'static> Stream for ChannelRecvHalf<T, S> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            receiver,
            recv_halt,
            ..
        } = &mut *self;

        if recv_halt.load(Ordering::Relaxed) {
            return Poll::Ready(None);
        }

        match futures::ready!(Pin::new(receiver).get_pin_mut().poll_next(cx)) {
            None => Poll::Ready(None),
            Some(Ok(res)) => match self.process_packet(Ok(res)) {
                Ok(res) => Poll::Ready(Some(res)),
                _ => Poll::Ready(None),
            },
            Some(Err(_)) => Poll::Ready(None),
        }
    }
}

impl<T: NetObject, S: Subscribable + 'static> Drop for ChannelRecvHalf<T, S> {
    fn drop(&mut self) {
        let chan = self.tx.take().unwrap();
        let recv_halt = self.recv_halt.clone();

        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                log::trace!(target: "citadel", "[Drop] on {:?} | recv_halt: {}", chan.node_type(), recv_halt.load(Ordering::Relaxed));
                // if we haven't yet received a halt signal, send signal to parallel side
                if !recv_halt.load(Ordering::Relaxed) {
                    chan.send_serialized(ChannelPacket::<T>::Halt).await?;
                    // now, toggle to prevent further packets from being sent outbound locally
                    recv_halt.store(true, Ordering::Relaxed);
                } else {
                    return chan.send_serialized(ChannelPacket::<T>::HaltVerified).await;
                }

                // wait for halt verified packet
                loop {
                    let packet = chan.recv_serialized::<ChannelPacket<T>>().await?;
                    log::trace!(target: "citadel", "[Drop RECV] on {:?} recv {:?}", chan.node_type(), &packet);

                    if let ChannelPacket::<T>::HaltVerified = packet {
                        break
                    }
                }

                log::trace!(target: "citadel", "[Drop] Recv halt-verified on {:?}", chan.node_type());
                Ok(()) as std::io::Result<()>
            });
        }
    }
}

/// A loader for a channel.
pub struct ChannelLoader<'a, T: NetObject, S: Subscribable + 'static> {
    inner: ScopedFutureResult<'a, Channel<T, S>>,
}

impl<T: NetObject, S: Subscribable + 'static> Future for ChannelLoader<'_, T, S> {
    type Output = Result<Channel<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::test_utils::create_streams;
    use citadel_io::tokio;
    use futures::StreamExt;

    #[tokio::test]
    async fn bi_channel() {
        citadel_logging::setup_log();
        let (server, client) = create_streams().await;

        let server = citadel_io::tokio::spawn(async move {
            let mut channel = server.bi_channel::<u32>().await.unwrap();

            for x in 0..1000 {
                channel.send_item(x).await.unwrap();
                log::trace!(target: "citadel", "[S] Send {x:?}")
            }

            for x in 0..1000 {
                assert_eq!(x, channel.next().await.unwrap());
                log::trace!(target: "citadel", "[S] Recv {x:?}")
            }
        });

        let client = citadel_io::tokio::spawn(async move {
            let mut channel = client.bi_channel::<u32>().await.unwrap();

            for x in 0..1000 {
                channel.send_item(x).await.unwrap();
                log::trace!(target: "citadel", "[C] Send {x:?}")
            }

            for x in 0..1000 {
                assert_eq!(x, channel.next().await.unwrap());
                log::trace!(target: "citadel", "[C] Send {x:?}")
            }
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }
}
