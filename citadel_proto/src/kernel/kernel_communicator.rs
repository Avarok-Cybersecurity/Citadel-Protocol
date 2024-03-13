use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::remote::Ticket;
use citadel_io::Mutex;
use futures::{Future, Stream};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Default)]
pub struct KernelAsyncCallbackHandler {
    pub inner: Arc<Mutex<KernelAsyncCallbackHandlerInner>>,
}

#[derive(Default)]
pub struct KernelAsyncCallbackHandlerInner {
    map: HashMap<CallbackKey, CallbackNotifier>,
}

pub(crate) enum CallbackNotifier {
    Future(tokio::sync::oneshot::Sender<NodeResult>),
    Stream(tokio::sync::mpsc::UnboundedSender<NodeResult>),
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct CallbackKey {
    pub ticket: Ticket,
    pub implicated_cid: Option<u64>,
}

fn search_for_value(
    map: &mut HashMap<CallbackKey, CallbackNotifier>,
    callback_key_received: &CallbackKey,
) -> Option<CallbackNotifier> {
    let mut found = None;
    for key in map.keys() {
        let ticket = key.ticket;
        let cid_opt = key.implicated_cid;

        // If we locally expect a cid, then, we require the same cid to be present in the received callback_key
        // If we locally do not expect a cid, then, we don't need to check the cid
        if let Some(cid_expected) = cid_opt {
            if let Some(cid_received) = callback_key_received.implicated_cid {
                if ticket == key.ticket && cid_expected == cid_received {
                    found = Some(*key);
                    break;
                } else {
                    // Incorrect match
                    continue;
                }
            } else {
                // We expect a cid, but, the received does not have one
                continue;
            }
        } else {
            // We do not expect a CID. Therefore, we don't need to check the CID received
            if ticket == key.ticket {
                found = Some(*key);
                break;
            } else {
                // Incorrect match
                continue;
            }
        }
    }

    let found = found?;
    map.remove(&found)
}

impl CallbackKey {
    pub fn new(ticket: Ticket, implicated_cid: u64) -> Self {
        Self {
            ticket,
            implicated_cid: Some(implicated_cid),
        }
    }

    pub fn ticket_only(ticket: Ticket) -> Self {
        Self {
            ticket,
            implicated_cid: None,
        }
    }
}

impl CallbackNotifier {
    #[allow(clippy::result_large_err)]
    fn send(self, item: NodeResult) -> Result<(), NodeResult> {
        match self {
            Self::Future(tx) => tx.send(item),
            Self::Stream(tx) => tx.send(item).map_err(|err| err.0),
        }
    }
}

impl KernelAsyncCallbackHandler {
    pub fn register_future(
        &self,
        callback_key: CallbackKey,
    ) -> Result<tokio::sync::oneshot::Receiver<NodeResult>, NetworkError> {
        let mut this = self.inner.lock();
        let (tx, rx) = tokio::sync::oneshot::channel();
        this.insert(callback_key, CallbackNotifier::Future(tx))?;
        Ok(rx)
    }

    pub fn register_stream(
        &self,
        callback_key: CallbackKey,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let mut this = self.inner.lock();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        this.insert(callback_key, CallbackNotifier::Stream(tx))?;
        Ok(KernelStreamSubscription {
            inner: rx,
            ptr: self.clone(),
            callback_key,
        })
    }

    #[allow(unused_results)]
    pub fn remove_listener(&self, callback_key: CallbackKey) {
        let mut this = self.inner.lock();
        this.map.remove(&callback_key);
    }

    // If a notification occurred, returns None. Else, returns the result
    fn maybe_notify(&self, result: NodeResult) -> Option<NodeResult> {
        match result.callback_key() {
            Some(ref received_callback_key) => {
                let mut this = self.inner.lock();
                if let Some(prev) = search_for_value(&mut this.map, received_callback_key) {
                    match prev {
                        CallbackNotifier::Future(_) => {
                            let prev = this.map.remove(received_callback_key).unwrap();
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
    fn insert(
        &mut self,
        callback_key: CallbackKey,
        notifier: CallbackNotifier,
    ) -> Result<(), NetworkError> {
        if self.map.insert(callback_key, notifier).is_some() {
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
    callback_key: CallbackKey,
}

impl Stream for KernelStreamSubscription {
    type Item = NodeResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

impl Drop for KernelStreamSubscription {
    fn drop(&mut self) {
        self.ptr.remove_listener(self.callback_key)
    }
}
