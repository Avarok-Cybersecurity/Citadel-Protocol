use tokio::sync::mpsc::{Sender, Receiver};
use std::fmt::{Debug, Formatter};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct CallbackChannel<T, R> {
    inner: CallbackChannelInner<T, R>
}

pub enum CallbackError<T> {
    SendError(T),
    RecvError,
    InternalError(&'static str)
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
                write!(f, "Callback Error: {}", err)
            }
        }
    }
}

#[derive(Clone)]
struct CallbackChannelInner<T, R> {
    to_channel: Sender<CallbackChannelPayload<T, R>>
}

pub type CallbackChannelPayload<T, R> = (T, Option<tokio::sync::oneshot::Sender<R>>);

impl<T, R> CallbackChannel<T, R> {
    pub fn new(buffer: usize) -> (Self, CallbackReceiver<T, R>) {
        let (to_channel, from_channel) = tokio::sync::mpsc::channel(buffer);
        (Self { inner: CallbackChannelInner { to_channel } }, CallbackReceiver { inner: from_channel })
    }

    pub async fn send(&self, payload: T) -> Result<R, CallbackError<T>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner.to_channel.send((payload, Some(tx))).await.map_err(|err| CallbackError::SendError(err.0.0))?;
        Ok(rx.await.map_err(|_| CallbackError::RecvError)?)
    }

    pub async fn send_no_callback(&self, payload: T) -> Result<(), CallbackError<T>> {
        self.inner.to_channel.send((payload, None)).await.map_err(|err| CallbackError::SendError(err.0.0))
    }
}

pub struct CallbackReceiver<T, R> {
    inner: Receiver<CallbackChannelPayload<T, R>>
}

impl<T, R> Stream for CallbackReceiver<T, R> {
    type Item = CallbackChannelPayload<T, R>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::callback_channel::CallbackChannel;
    use futures::StreamExt;

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

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);

        let (_, _) = tokio::join!(server, client);
    }
}