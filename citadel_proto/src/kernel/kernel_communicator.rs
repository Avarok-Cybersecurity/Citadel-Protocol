//! Kernel Communication Handler
//!
//! This module implements the communication layer between kernel components,
//! managing message passing, callbacks, and event handling within the Citadel Protocol.
//!
//! # Features
//!
//! - Asynchronous message handling
//! - Event callback management
//! - Channel-based communication
//! - Error propagation
//! - Resource cleanup
//!
//! # Important Notes
//!
//! - Uses Tokio channels for communication
//! - Maintains thread safety for callbacks
//! - Handles resource cleanup on drop
//! - Supports both sync and async callbacks
//! - Manages message ordering guarantees
//!
//! # Related Components
//!
//! - `kernel_executor.rs`: Task execution
//! - `kernel_trait.rs`: Core interfaces
//! - `mod.rs`: Module coordination
//! - `error.rs`: Error handling

use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::Mutex;
use citadel_io::{error, ErrorCode};
use futures::{Future, Stream};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Default)]
pub struct KernelAsyncCallbackHandler<R: Ratchet> {
    pub inner: Arc<Mutex<KernelAsyncCallbackHandlerInner<R>>>,
}

#[derive(Default)]
pub struct KernelAsyncCallbackHandlerInner<R: Ratchet> {
    pub(crate) map: HashMap<CallbackKey, CallbackNotifier<R>>,
}

#[allow(dead_code)]
pub(crate) struct CallbackNotifier<R: Ratchet> {
    tx: citadel_io::tokio::sync::mpsc::UnboundedSender<NodeResult<R>>,
    key: CallbackKey,
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct CallbackKey {
    pub ticket: Ticket,
    pub session_cid: Option<u64>,
}

/// The listener a result with `received` is delivered to: the one registered for its ticket and
/// CID, or else the one registered for its ticket alone. A listener registered with a CID never
/// receives a result without one. Two lookups, whatever the number of outstanding listeners.
fn listener_for<'a, R: Ratchet>(
    map: &'a mut HashMap<CallbackKey, CallbackNotifier<R>>,
    received: &CallbackKey,
) -> Option<&'a mut CallbackNotifier<R>> {
    let ticket_only = CallbackKey::ticket_only(received.ticket);
    if received.session_cid.is_some() && map.contains_key(received) {
        return map.get_mut(received);
    }
    map.get_mut(&ticket_only)
}

impl CallbackKey {
    pub fn new(ticket: Ticket, session_cid: u64) -> Self {
        Self {
            ticket,
            session_cid: Some(session_cid),
        }
    }

    pub fn ticket_only(ticket: Ticket) -> Self {
        Self {
            ticket,
            session_cid: None,
        }
    }
}

impl<R: Ratchet> KernelAsyncCallbackHandler<R> {
    pub fn register_stream(
        &self,
        callback_key: CallbackKey,
    ) -> Result<KernelStreamSubscription<R>, NetworkError> {
        let mut this = self.inner.lock();
        let (tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        this.insert(
            callback_key,
            CallbackNotifier {
                tx,
                key: callback_key,
            },
        )?;
        Ok(KernelStreamSubscription {
            inner: rx,
            ptr: self.clone(),
            callback_key,
        })
    }

    #[allow(unused_results)]
    pub fn remove_listener(&self, callback_key: CallbackKey) {
        let mut this = self.inner.lock();
        log::trace!(target: "citadel", "Removing listener {callback_key:?}");
        this.map.remove(&callback_key);
    }

    // If a notification occurred, returns None. Else, returns the result
    fn maybe_notify(&self, result: NodeResult<R>) -> Option<NodeResult<R>> {
        match result.callback_key() {
            Some(ref received_callback_key) => {
                let mut this = self.inner.lock();
                if let Some(prev) = listener_for(&mut this.map, received_callback_key) {
                    match prev.tx.send(result) {
                        Ok(_) => None,
                        Err(err) => Some(err.0),
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
        result: NodeResult<R>,
        default: impl FnOnce(NodeResult<R>) -> F,
    ) -> Result<(), NetworkError> {
        match self.maybe_notify(result) {
            None => Ok(()),
            Some(result) => default(result).await,
        }
    }
}

impl<R: Ratchet> KernelAsyncCallbackHandlerInner<R> {
    fn insert(
        &mut self,
        callback_key: CallbackKey,
        notifier: CallbackNotifier<R>,
    ) -> Result<(), NetworkError> {
        // A second listener for a key is refused, and the first keeps receiving.
        match self.map.entry(callback_key) {
            Entry::Occupied(_) => Err(error!(ErrorCode::KernelNotifierOverwritten)),
            Entry::Vacant(slot) => {
                let _ = slot.insert(notifier);
                Ok(())
            }
        }
    }
}

impl<R: Ratchet> Clone for KernelAsyncCallbackHandler<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[allow(dead_code)]
pub struct KernelStreamSubscription<R: Ratchet> {
    inner: citadel_io::tokio::sync::mpsc::UnboundedReceiver<NodeResult<R>>,
    ptr: KernelAsyncCallbackHandler<R>,
    callback_key: CallbackKey,
}

impl<R: Ratchet> KernelStreamSubscription<R> {
    pub fn callback_key(&self) -> &CallbackKey {
        &self.callback_key
    }
}

impl<R: Ratchet> Drop for KernelStreamSubscription<R> {
    fn drop(&mut self) {
        self.ptr.remove_listener(self.callback_key)
    }
}

impl<R: Ratchet> Stream for KernelStreamSubscription<R> {
    type Item = NodeResult<R>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_recv(cx)
    }
}

#[cfg(test)]
#[path = "kernel_communicator_tests.rs"]
mod tests;
