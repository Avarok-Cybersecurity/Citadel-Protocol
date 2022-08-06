use crate::error::NetworkError;
use crate::proto::hdp_node::{NodeResult, Ticket};
use futures::{Future, Stream};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct KernelAsyncCallbackHandler {
    pub inner: Arc<Mutex<KernelAsyncCallbackHandlerInner>>,
}

#[derive(Default)]
pub struct KernelAsyncCallbackHandlerInner {
    map: HashMap<Ticket, CallbackNotifier>,
}

pub(crate) enum CallbackNotifier {
    Future(tokio::sync::oneshot::Sender<NodeResult>),
    Stream(tokio::sync::mpsc::UnboundedSender<NodeResult>),
}

impl CallbackNotifier {
    fn send(self, item: NodeResult) -> Result<(), NodeResult> {
        match self {
            Self::Future(tx) => tx.send(item),
            Self::Stream(tx) => tx.send(item).map_err(|err| err.0),
        }
    }
}

impl KernelAsyncCallbackHandler {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Default::default())),
        }
    }

    pub fn register_future(
        &self,
        ticket: Ticket,
    ) -> Result<tokio::sync::oneshot::Receiver<NodeResult>, NetworkError> {
        let mut this = self.inner.lock();
        let (tx, rx) = tokio::sync::oneshot::channel();
        this.insert(ticket, CallbackNotifier::Future(tx))?;
        Ok(rx)
    }

    pub fn register_stream(
        &self,
        ticket: Ticket,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let mut this = self.inner.lock();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        this.insert(ticket, CallbackNotifier::Stream(tx))?;
        Ok(KernelStreamSubscription {
            inner: rx,
            ptr: self.clone(),
            ticket,
        })
    }

    #[allow(unused_results)]
    pub fn remove_listener(&self, ticket: Ticket) {
        let mut this = self.inner.lock();
        this.map.remove(&ticket);
    }

    // If a notification occurred, returns None. Else, returns the result
    fn maybe_notify(&self, result: NodeResult) -> Option<NodeResult> {
        match result.ticket() {
            Some(ref ticket) => {
                let mut this = self.inner.lock();
                if let Some(prev) = this.map.get(ticket) {
                    match prev {
                        CallbackNotifier::Future(_) => {
                            let prev = this.map.remove(ticket).unwrap();
                            // it's possible the future listening dropped
                            match prev.send(result) {
                                Ok(_) => None,
                                Err(err) => Some(err),
                            }
                        }

                        CallbackNotifier::Stream(tx) => match tx.send(result) {
                            Ok(_) => None,
                            Err(err) => Some(err.0),
                        },
                    }
                } else {
                    Some(result)
                }
            }

            None => Some(result),
        }
    }

    pub async fn on_message_received<F: Future<Output = Result<(), NetworkError>>>(
        &self,
        result: NodeResult,
        default: impl FnOnce(NodeResult) -> F,
    ) -> Result<(), NetworkError> {
        match self.maybe_notify(result) {
            None => Ok(()),

            Some(result) => default(result).await,
        }
    }
}

impl KernelAsyncCallbackHandlerInner {
    fn insert(&mut self, ticket: Ticket, notifier: CallbackNotifier) -> Result<(), NetworkError> {
        if let Some(_) = self.map.insert(ticket, notifier) {
            Err(NetworkError::InternalError("Overwrote previous notifier"))
        } else {
            Ok(())
        }
    }
}

impl Clone for KernelAsyncCallbackHandler {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct KernelStreamSubscription {
    inner: tokio::sync::mpsc::UnboundedReceiver<NodeResult>,
    ptr: KernelAsyncCallbackHandler,
    ticket: Ticket,
}

impl Stream for KernelStreamSubscription {
    type Item = NodeResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

impl Drop for KernelStreamSubscription {
    fn drop(&mut self) {
        self.ptr.remove_listener(self.ticket)
    }
}
