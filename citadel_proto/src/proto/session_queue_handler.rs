//! # Session Queue Handler
//!
//! This module implements a queue-based task scheduling system for Citadel Protocol sessions.
//! It manages timed operations, periodic checks, and session-specific tasks using a delay queue.
//!
//! ## Features
//!
//! - **Task Scheduling**: Manages scheduled tasks with customizable timeouts
//! - **Reserved System Processes**: Dedicated slots for critical system operations
//! - **One-shot Tasks**: Support for single-execution future tasks
//! - **State Management**: Integration with session state container
//! - **Async Stream Interface**: Implements Stream and Future traits
//!
//! ## Task Types
//!
//! - **Reserved Tasks** (indices 0-9): System-level operations like keep-alive checks
//! - **Ordinary Tasks** (indices 10+): Session-specific operations like group timeouts
//! - **One-shot Tasks**: Single-execution tasks with custom timeouts
//!
//! ## Important Notes
//!
//! - Reserved indices below 10 are preserved for system operations
//! - Task execution is managed through a DelayQueue system
//! - Supports both blocking and non-blocking task execution
//!
//! ## Related Components
//!
//! - [`SessionState`]: Session state management
//! - [`StateContainer`]: Session state storage
//! - [`NetworkError`]: Error handling
//!
use crate::error::NetworkError;
use crate::proto::packet_processor::includes::Duration;
use crate::proto::session::SessionState;
use citadel_io::tokio::sync::broadcast::Sender;
use citadel_io::tokio::time::error::Error;
use citadel_io::tokio_util::time::{delay_queue, DelayQueue};
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::inner_arg::ExpectedInnerTargetMut;
use crate::proto::state_container::{StateContainer, StateContainerInner};
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use std::sync::atomic::{AtomicUsize, Ordering};

/// any index below 10 are reserved for the session. Inbound GROUP timeouts will begin at 10 or high
pub const QUEUE_WORKER_RESERVED_INDEX: usize = 10;
pub const RESERVED_CID_IDX: u64 = 0;

pub const PROVISIONAL_CHECKER: usize = 0;
pub const DRILL_REKEY_WORKER: usize = 1;
pub const KEEP_ALIVE_CHECKER: usize = 2;
pub const FIREWALL_KEEP_ALIVE: usize = 3;

pub trait QueueFunction<R: Ratchet>:
    Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult + Send + 'static
{
}

impl<
        R: Ratchet,
        T: Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult
            + Send
            + 'static,
    > QueueFunction<R> for T
{
}

#[allow(clippy::type_complexity)]
pub struct SessionQueueWorker<R: Ratchet> {
    entries: HashMap<QueueWorkerTicket, (Box<dyn QueueFunction<R>>, delay_queue::Key, Duration)>,
    expirations: DelayQueue<QueueWorkerTicket>,
    state_container: Option<StateContainer<R>>,
    sess_shutdown: Sender<()>,
    waker: Option<Waker>,
    rx: UnboundedReceiver<ChannelInner<R>>,
    // keeps track of how many items have been added
    rolling_idx: usize,
}

#[derive(Clone)]
pub struct SessionQueueWorkerHandle<R: Ratchet> {
    tx: UnboundedSender<ChannelInner<R>>,
    rolling_idx: Arc<AtomicUsize>,
}

type ChannelInner<R> = (
    Option<QueueWorkerTicket>,
    Duration,
    Box<dyn QueueFunction<R>>,
);

impl<R: Ratchet> SessionQueueWorkerHandle<R> {
    /// Inserts a reserved system process. We now spawn this as a task to prevent deadlocking
    pub fn insert_reserved(
        &self,
        key: Option<QueueWorkerTicket>,
        timeout: Duration,
        on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult
            + Send
            + 'static,
    ) {
        let _ = self.tx.send((key, timeout, Box::new(on_timeout)));
    }

    /// A convenient way to check on a task once sometime in the future
    #[allow(dead_code)]
    pub fn insert_oneshot(
        &self,
        call_in: Duration,
        on_call: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) + Send + 'static,
    ) {
        self.insert_reserved(None, call_in, move |sess| {
            (on_call)(sess);
            QueueWorkerResult::Complete
        });
    }

    /// factors-in the offset
    pub fn insert_ordinary(
        &self,
        idx: usize,
        target_cid: u64,
        timeout: Duration,
        on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult
            + Send
            + 'static,
    ) {
        self.insert_reserved(
            Some(QueueWorkerTicket::Periodic(
                idx + QUEUE_WORKER_RESERVED_INDEX + self.rolling_idx.fetch_add(1, Ordering::SeqCst),
                target_cid,
            )),
            timeout,
            on_timeout,
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueueWorkerTicket {
    Oneshot(usize, u64),
    Periodic(usize, u64),
}

pub enum QueueWorkerResult {
    Complete,
    Incomplete,
    EndSession,
    AdjustPeriodicity(Duration),
}

impl<R: Ratchet> SessionQueueWorker<R> {
    pub fn new(sess_shutdown: Sender<()>) -> (Self, SessionQueueWorkerHandle<R>) {
        let (tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        let handle = SessionQueueWorkerHandle {
            tx,
            rolling_idx: Arc::new(Default::default()),
        };
        (
            Self {
                rx,
                waker: None,
                sess_shutdown,
                rolling_idx: 0,
                entries: HashMap::new(),
                expirations: DelayQueue::new(),
                state_container: None,
            },
            handle,
        )
    }

    /// MUST be called when a session's timer subroutine begins!
    pub fn load_state_container(&mut self, state_container: StateContainer<R>) {
        self.state_container = Some(state_container);
    }

    /// Inserts a reserved system process. We now spawn this as a task to prevent deadlocking
    #[allow(unused_results)]
    pub fn insert_reserved(
        &mut self,
        key_orig: Option<QueueWorkerTicket>,
        timeout: Duration,
        on_timeout: Box<dyn QueueFunction<R>>,
    ) {
        // the zero in the default unwrap ensures that the key is going to be unique
        let key_new = key_orig.unwrap_or(QueueWorkerTicket::Oneshot(
            self.rolling_idx + QUEUE_WORKER_RESERVED_INDEX + 1,
            RESERVED_CID_IDX,
        ));
        let delay = self.expirations.insert(key_new, timeout);

        if let Some(key) = self.entries.insert(key_new, (on_timeout, delay, timeout)) {
            log::warn!(target: "citadel", "Overwrote a session key: {:?} || Original: {key_orig:?}", key.1);
        }

        self.rolling_idx += 1;
    }

    pub fn insert_reserved_fn(
        &mut self,
        key: Option<QueueWorkerTicket>,
        timeout: Duration,
        on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult
            + Send
            + 'static,
    ) {
        self.insert_reserved(key, timeout, Box::new(on_timeout))
    }

    fn register_waker(&mut self, waker: &Waker) {
        self.waker = Some(waker.clone());
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }

    #[allow(unused_results)]
    fn poll_purge(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.register_waker(cx.waker());

        let SessionQueueWorker {
            expirations,
            state_container,
            entries,
            ..
        } = &mut *self;

        let mut state_container = inner_mut_state!(state_container.as_ref().unwrap());
        if state_container.state.get() != SessionState::Disconnected {
            while let Some(res) = futures::ready!(expirations.poll_expired(cx)) {
                let entry: QueueWorkerTicket = res.into_inner();
                //log::trace!(target: "citadel", "POLL_EXPIRED: {:?}", &entry);
                match entry {
                    QueueWorkerTicket::Oneshot(_, _) => {
                        // already removed from expiration; now, just remove from hashmap
                        let (fx, _, _) = entries.remove(&entry).unwrap();
                        if let QueueWorkerResult::EndSession = (fx)(&mut state_container) {
                            return Poll::Ready(Err(Error::shutdown()));
                        }
                    }

                    QueueWorkerTicket::Periodic(_, _) => {
                        let (fx, _key, duration) = entries.get(&entry).unwrap();

                        let next_key = match fx(&mut state_container) {
                            QueueWorkerResult::Complete => {
                                // nothing to do here since already removed entry
                                //this.expirations.remove(&key2);
                                entries.remove(&entry);
                                // the below line was to fix a bug where the queue wouldn't be polled if ANY
                                // task returned Complete
                                drop(state_container);
                                self.wake();
                                return Poll::Pending;
                            }

                            QueueWorkerResult::EndSession => {
                                return Poll::Ready(Err(Error::shutdown()));
                            }

                            QueueWorkerResult::AdjustPeriodicity(new_period) => {
                                expirations.insert(entry, new_period)
                            }
                            _ => {
                                // if incomplete, and is periodic, reset it
                                let duration = *duration;
                                expirations.insert(entry, duration)
                                // since we re-inserted the item, we need to schedule it to be awaken again
                            }
                        };

                        let (_fx, key, _duration) = entries.get_mut(&entry).unwrap();
                        *key = next_key;
                    }
                }
            }

            Poll::Pending
        } else {
            Poll::Ready(Err(Error::shutdown()))
        }
    }
}

impl<R: Ratchet> Stream for SessionQueueWorker<R> {
    // DelayQueue seems much more specific, where a user may care that it
    // has reached capacity, so return those errors instead of panicking.
    type Item = ();

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        while let Poll::Ready(Some((key, timeout, on_timeout))) =
            self.as_mut().get_mut().rx.poll_recv(cx)
        {
            // register any inbound tasks
            self.as_mut()
                .get_mut()
                .insert_reserved(key, timeout, on_timeout);
        }

        match futures::ready!(self.poll_purge(cx)) {
            Ok(_) => Poll::Pending,
            Err(_) => Poll::Ready(None),
        }
    }
}

impl<R: Ratchet> futures::Future for SessionQueueWorker<R> {
    type Output = Result<(), NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.as_mut().poll_next(cx)) {
            Some(_) => Poll::Pending,
            None => {
                if let Err(_err) = self.sess_shutdown.send(()) {
                    //log::error!(target: "citadel", "Unable to shutdown session: {:?}", err);
                }

                Poll::Ready(Err(NetworkError::InternalError(
                    "Queue handler signalled shutdown",
                )))
            }
        }
    }
}
