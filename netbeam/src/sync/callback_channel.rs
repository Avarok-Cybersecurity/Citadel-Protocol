/*!
 * # Callback Channel
 *
 * A specialized channel implementation that enables asynchronous request-response patterns
 * with optional callback support.
 *
 * ## Features
 * - Asynchronous message passing with response callbacks
 * - Support for fire-and-forget operations (no callback required)
 * - Built on top of Tokio's MPSC channels
 * - Implements Stream trait for receiver side
 * - Thread-safe and Clone-able design
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::callback_channel::CallbackChannel;
 *
 * async fn example() {
 *     // Create a new channel with buffer size 10
 *     let (channel, receiver) = CallbackChannel::<String, bool>::new(10);
 *
 *     // Send with callback
 *     if let Ok(result) = channel.send("hello".to_string()).await {
 *         println!("Got response: {}", result);
 *     }
 *
 *     // Send without callback
 *     let _ = channel.send_no_callback("world".to_string()).await;
 * }
 * ```
 *
 * ## Related Components
 * - `tracked_callback_channel.rs`: Enhanced version with tracking capabilities
 * - `bi_channel.rs`: Bidirectional channel implementation
 *
 * ## Important Notes
 * - Channel operations are fallible and return Result types
 * - Callbacks are optional via send_no_callback
 * - Implements Stream trait for easy integration with async streams
 */

use citadel_io::tokio::sync::mpsc::{Receiver, Sender};
use futures::Stream;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A specialized channel implementation that enables asynchronous request-response patterns
/// with optional callback support.
#[derive(Clone)]
pub struct CallbackChannel<T, R> {
    /// Inner implementation details of the callback channel.
    inner: CallbackChannelInner<T, R>,
}

/// Enum representing possible errors that can occur during callback channel operations.
pub enum CallbackError<T> {
    /// Error occurred while sending a message.
    SendError(T),
    /// Error occurred while receiving a message.
    RecvError,
    /// Internal error occurred during channel operations.
    InternalError(&'static str),
}

impl<T> Debug for CallbackError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(_) => {
                write!(f, "Callback Error: Unable to Send")
            }

            Self::RecvError => {
                write!(f, "Callback Error: Unable to receive")
            }

            Self::InternalError(err) => {
                write!(f, "Callback Error: {err}")
            }
        }
    }
}

/// Inner implementation details of the callback channel.
#[derive(Clone)]
struct CallbackChannelInner<T, R> {
    /// Sender for the callback channel.
    to_channel: Sender<CallbackChannelPayload<T, R>>,
}

/// Type alias for the payload of the callback channel.
pub type CallbackChannelPayload<T, R> = (T, Option<citadel_io::tokio::sync::oneshot::Sender<R>>);

impl<T, R> CallbackChannel<T, R> {
    /// Creates a new callback channel with the specified buffer size.
    ///
    /// Returns a tuple containing the sender and receiver of the channel.
    pub fn new(buffer: usize) -> (Self, CallbackReceiver<T, R>) {
        let (to_channel, from_channel) = citadel_io::tokio::sync::mpsc::channel(buffer);
        (
            Self {
                inner: CallbackChannelInner { to_channel },
            },
            CallbackReceiver {
                inner: from_channel,
            },
        )
    }

    /// Sends a message through the channel with an optional callback.
    ///
    /// Returns a result containing the response from the receiver, or an error if the send operation fails.
    pub async fn send(&self, payload: T) -> Result<R, CallbackError<T>> {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        self.inner
            .to_channel
            .send((payload, Some(tx)))
            .await
            .map_err(|err| CallbackError::SendError(err.0 .0))?;
        rx.await.map_err(|_| CallbackError::RecvError)
    }

    /// Sends a message through the channel without a callback.
    ///
    /// Returns a result indicating whether the send operation was successful, or an error if it fails.
    pub async fn send_no_callback(&self, payload: T) -> Result<(), CallbackError<T>> {
        self.inner
            .to_channel
            .send((payload, None))
            .await
            .map_err(|err| CallbackError::SendError(err.0 .0))
    }
}

/// Receiver for the callback channel.
pub struct CallbackReceiver<T, R> {
    /// Inner implementation details of the receiver.
    inner: Receiver<CallbackChannelPayload<T, R>>,
}

impl<T, R> Stream for CallbackReceiver<T, R> {
    type Item = CallbackChannelPayload<T, R>;

    /// Polls the receiver for the next message.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::callback_channel::CallbackChannel;
    use citadel_io::tokio;
    use futures::StreamExt;

    #[tokio::test]
    async fn main() {
        citadel_logging::setup_log();
        let (tx, mut rx) = CallbackChannel::<u32, u64>::new(10);

        const COUNT: u32 = 100000;

        let server = async move {
            while let Some((payload, resp)) = rx.next().await {
                resp.unwrap().send((payload + 1) as u64).unwrap();

                if payload == COUNT {
                    return;
                }
            }
        };

        let client = async move {
            for x in 0..=COUNT {
                assert_eq!(tx.send(x).await.unwrap(), (x + 1) as u64);
            }
        };

        let server = citadel_io::tokio::spawn(server);
        let client = citadel_io::tokio::spawn(client);

        let (_, _) = citadel_io::tokio::join!(server, client);
    }
}
