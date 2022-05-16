use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::{Sender, Receiver};
use std::fmt::{Debug, Formatter};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct TrackedCallbackChannel<T, R> {
    inner: Arc<TrackedCallbackChannelInner<T, R>>
}

pub enum TrackedCallbackError<T> {
    SendError(T),
    RecvError,
    InternalError(&'static str)
}

const NO_RESPONSE: u64 = 0;

impl<T> Debug for TrackedCallbackError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(_) => {
                write!(f, "Callback Error: Unable to Send")
            }

            Self::RecvError => {
                write!(f, "Callback Error: Unable to receive")
            }

            Self::InternalError(err) => {
                write!(f, "Callback Error: {}", err)
            }
        }
    }
}

struct TrackedCallbackChannelInner<T, R> {
    map: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<R>>>,
    to_channel: Sender<TrackedCallbackChannelPayload<T, R>>,
    id: AtomicU64
}

pub struct TrackedCallbackChannelPayload<T, R> {
    id: u64,
    pub payload: T,
    _pd: PhantomData<R>
}

impl<T, R> TrackedCallbackChannelPayload<T, R> {
    pub fn new(&self, payload: R) -> TrackedCallbackChannelPayload<R, T> {
        TrackedCallbackChannelPayload { id: self.id, payload, _pd: Default::default() }
    }

    pub fn expects_response(&self) -> bool {
        self.id != NO_RESPONSE
    }
}

impl<T: Send + Sync, R: Send + Sync> TrackedCallbackChannel<T, R> {
    pub fn new(buffer: usize) -> (Self, CallbackReceiver<T, R>) {
        let (to_channel, from_channel) = tokio::sync::mpsc::channel(buffer);
        (Self { inner: Arc::new(TrackedCallbackChannelInner { to_channel, map: Mutex::new(Default::default()), id: AtomicU64::new(1) }) }, CallbackReceiver { inner: from_channel })
    }

    pub async fn send(&self, payload: T) -> Result<R, TrackedCallbackError<T>> {
        let (rx, id) = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let next_value = self.inner.id.fetch_add(1, Ordering::Relaxed);
            self.inner.map.lock().insert(next_value, tx);
            (rx, next_value)
        };

        self.inner.to_channel.send(TrackedCallbackChannelPayload { id, payload, _pd: Default::default() }).await.map_err(|err| TrackedCallbackError::SendError(err.0.payload))?;

        Ok(rx.await.map_err(|_| TrackedCallbackError::RecvError)?)
    }

    pub async fn send_no_callback(&self, payload: T) -> Result<(), TrackedCallbackError<T>> {
        self.inner.to_channel.send(TrackedCallbackChannelPayload { id: NO_RESPONSE, payload, _pd: Default::default() }).await.map_err(|err| TrackedCallbackError::SendError(err.0.payload))
    }

    pub async fn reply(&self, payload: TrackedCallbackChannelPayload<R, T>) -> Result<(), TrackedCallbackError<R>> {
        let sender = {
            self.inner.map.lock().remove(&payload.id).ok_or(TrackedCallbackError::InternalError("Mapping does not exist for id"))?
        };

        sender.send(payload.payload).map_err(|err| TrackedCallbackError::SendError(err))
    }
}

pub struct CallbackReceiver<T, R> {
    inner: Receiver<TrackedCallbackChannelPayload<T, R>>
}

impl<T, R> Stream for CallbackReceiver<T, R> {
    type Item = TrackedCallbackChannelPayload<T, R>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use crate::sync::tracked_callback_channel::TrackedCallbackChannel;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn main() {
        setup_log();
        let (tx0, mut rx) = TrackedCallbackChannel::<u32, u64>::new(10);
        let tx1 = tx0.clone();

        const COUNT: u32 = 100000;

        let server = async move {
            while let Some(val) = rx.next().await {
                let input = val.payload;
                tx0.reply(val.new((input + 1) as u64)).await.unwrap();

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

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);

        let (_, _) = tokio::join!(server, client);
    }
}