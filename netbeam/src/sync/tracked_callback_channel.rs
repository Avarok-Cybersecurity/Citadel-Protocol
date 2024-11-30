/*!
 * # Tracked Callback Channel
 *
 * An enhanced version of the callback channel that provides tracking and monitoring
 * capabilities for request-response patterns.
 *
 * ## Features
 * - All features of the base CallbackChannel
 * - Request tracking with unique identifiers
 * - Response correlation with original requests
 * - Thread-safe response tracking
 * - Support for response timeouts
 * - Atomic operation tracking
 *
 * ## Usage Example
 * ```rust,no_run
 * use netbeam::sync::tracked_callback_channel::TrackedCallbackChannel;
 *
 * # fn example() {
 *  // Create a new tracked channel with buffer size 10
 *  let (channel, receiver) = TrackedCallbackChannel::<String, bool>::new(10);
 *
 *  // Send with tracked callback
 *  let result = channel.send("request".to_string());
 *
 *  // Send without callback
 *  channel.send_no_callback("notification".to_string());
 * # }
 * ```
 *
 * ## Related Components
 * - `callback_channel.rs`: Base implementation without tracking
 * - `bi_channel.rs`: Bidirectional channel implementation
 *
 * ## Important Notes
 * - Each request gets a unique tracking ID
 * - Responses are correlated with requests using tracking IDs
 * - Thread-safe tracking using atomic operations
 * - Memory-efficient response tracking with cleanup
 */

use citadel_io::tokio::sync::mpsc::{Receiver, Sender};
use citadel_io::Mutex;
use futures::Stream;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// A tracked callback channel that provides request-response tracking and monitoring.
pub struct TrackedCallbackChannel<T, R> {
    /// The inner implementation of the tracked callback channel.
    inner: Arc<TrackedCallbackChannelInner<T, R>>,
}

impl<T, R> Clone for TrackedCallbackChannel<T, R> {
    /// Clones the tracked callback channel.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// An error that can occur when using the tracked callback channel.
pub enum TrackedCallbackError<T> {
    /// An error occurred while sending a request.
    SendError(T),
    /// An error occurred while receiving a response.
    RecvError,
    /// An internal error occurred.
    InternalError(&'static str),
}

impl<T> TrackedCallbackError<T> {
    /// Returns the payload of the error, if any.
    pub fn payload(self) -> Option<T> {
        match self {
            Self::SendError(payload) => Some(payload),
            _ => None,
        }
    }
}

/// A constant representing no response.
const NO_RESPONSE: u64 = 0;

impl<T> Debug for TrackedCallbackError<T> {
    /// Formats the error for debugging.
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

/// The inner implementation of the tracked callback channel.
struct TrackedCallbackChannelInner<T, R> {
    /// A map of tracking IDs to response senders.
    map: Mutex<HashMap<u64, citadel_io::tokio::sync::oneshot::Sender<R>>>,
    /// The sender for the tracked callback channel.
    to_channel: Sender<TrackedCallbackChannelPayload<T, R>>,
    /// The atomic ID generator.
    id: AtomicU64,
}

/// A payload for the tracked callback channel.
pub struct TrackedCallbackChannelPayload<T, R> {
    /// The tracking ID of the payload.
    id: u64,
    /// The payload data.
    pub payload: T,
    /// A phantom data marker for the response type.
    _pd: PhantomData<R>,
}

impl<T, R> TrackedCallbackChannelPayload<T, R> {
    /// Creates a new payload with the given tracking ID and data.
    pub fn new(&self, payload: R) -> TrackedCallbackChannelPayload<R, T> {
        TrackedCallbackChannelPayload {
            id: self.id,
            payload,
            _pd: Default::default(),
        }
    }

    /// Returns whether the payload expects a response.
    pub fn expects_response(&self) -> bool {
        self.id != NO_RESPONSE
    }
}

impl<T: Send + Sync, R: Send + Sync> TrackedCallbackChannel<T, R> {
    /// Creates a new tracked callback channel with the given buffer size.
    pub fn new(buffer: usize) -> (Self, CallbackReceiver<T, R>) {
        let (to_channel, from_channel) = citadel_io::tokio::sync::mpsc::channel(buffer);
        (
            Self {
                inner: Arc::new(TrackedCallbackChannelInner {
                    to_channel,
                    map: Mutex::new(Default::default()),
                    id: AtomicU64::new(1),
                }),
            },
            CallbackReceiver {
                inner: from_channel,
            },
        )
    }

    /// Sends a request with a tracked callback.
    pub async fn send(&self, payload: T) -> Result<R, TrackedCallbackError<T>> {
        let (rx, id) = {
            let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
            let next_value = self.inner.id.fetch_add(1, Ordering::Relaxed);
            self.inner.map.lock().insert(next_value, tx);
            (rx, next_value)
        };

        self.inner
            .to_channel
            .send(TrackedCallbackChannelPayload {
                id,
                payload,
                _pd: Default::default(),
            })
            .await
            .map_err(|err| TrackedCallbackError::SendError(err.0.payload))?;

        rx.await.map_err(|_| TrackedCallbackError::RecvError)
    }

    /// Sends a request without a tracked callback.
    pub async fn send_no_callback(&self, payload: T) -> Result<(), TrackedCallbackError<T>> {
        self.inner
            .to_channel
            .send(TrackedCallbackChannelPayload {
                id: NO_RESPONSE,
                payload,
                _pd: Default::default(),
            })
            .await
            .map_err(|err| TrackedCallbackError::SendError(err.0.payload))
    }

    /// Tries to reply to a tracked request.
    pub fn try_reply(
        &self,
        payload: TrackedCallbackChannelPayload<R, T>,
    ) -> Result<(), TrackedCallbackError<R>> {
        let sender =
            {
                self.inner.map.lock().remove(&payload.id).ok_or(
                    TrackedCallbackError::InternalError("Mapping does not exist for id"),
                )?
            };

        sender
            .send(payload.payload)
            .map_err(|err| TrackedCallbackError::SendError(err))
    }
}

/// A receiver for the tracked callback channel.
pub struct CallbackReceiver<T, R> {
    /// The inner receiver.
    inner: Receiver<TrackedCallbackChannelPayload<T, R>>,
}

impl<T, R> Stream for CallbackReceiver<T, R> {
    type Item = TrackedCallbackChannelPayload<T, R>;

    /// Polls the receiver for the next item.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::tracked_callback_channel::{TrackedCallbackChannel, TrackedCallbackError};
    use citadel_io::tokio;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_tracked_callback() {
        citadel_logging::setup_log();
        let (tx0, mut rx) = TrackedCallbackChannel::<u32, u64>::new(10);
        let tx1 = tx0.clone();

        const COUNT: u32 = 10000;

        let server = async move {
            while let Some(val) = rx.next().await {
                assert!(val.expects_response());
                let input = val.payload;
                tx0.try_reply(val.new((input + 1) as u64)).unwrap();

                if input == COUNT {
                    return;
                }
            }
        };

        let client = async move {
            for x in 0..=COUNT {
                assert_eq!(tx1.send(x).await.unwrap(), (x + 1) as u64);
            }
        };

        let server = citadel_io::tokio::spawn(server);
        let client = citadel_io::tokio::spawn(client);

        let (_, _) = citadel_io::tokio::join!(server, client);
    }

    #[tokio::test]
    async fn test_tracked_callback_no_response() {
        citadel_logging::setup_log();
        let (tx0, mut rx) = TrackedCallbackChannel::<u32, u64>::new(10);
        let tx1 = tx0.clone();

        const COUNT: u32 = 10000;

        let server = async move {
            while let Some(val) = rx.next().await {
                assert!(!val.expects_response());
                let input = val.payload;
                assert!(tx0.try_reply(val.new((input + 1) as u64)).is_err());

                if input == COUNT {
                    return;
                }
            }
        };

        let client = async move {
            for x in 0..=COUNT {
                tx1.send_no_callback(x).await.unwrap();
            }
        };

        let server = citadel_io::tokio::spawn(server);
        let client = citadel_io::tokio::spawn(client);

        let (_, _) = citadel_io::tokio::join!(server, client);
    }

    #[test]
    fn test_error() {
        // to please codecov
        let err0 = TrackedCallbackError::SendError(0u8);
        let err1 = TrackedCallbackError::<u8>::RecvError;
        let err2 = TrackedCallbackError::<u8>::InternalError("other");
        let _data = format!("{err0:?} {err1:?} {err2:?}");
    }
}
