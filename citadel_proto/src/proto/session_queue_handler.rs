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
use citadel_io::time::{delay_queue, DelayQueue};
use citadel_io::tokio::sync::broadcast::Sender;
use citadel_io::{error, ErrorCode};
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::inner_arg::ExpectedInnerTargetMut;
use crate::proto::state_container::{StateContainer, StateContainerInner};
use citadel_crypt::ratchets::Ratchet;
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

/// A queued task asked for the session to end; the worker stops.
struct QueueShutdown;

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

    /// Schedules `on_timeout` under a key no other entry has: the index comes from this
    /// handle's own counter alone, never from a group id, so an inbound and an outbound group
    /// with the same peer cannot share a key, and no wire value enters the arithmetic.
    pub fn insert_ordinary(
        &self,
        target_cid: u64,
        timeout: Duration,
        on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner<R>>) -> QueueWorkerResult
            + Send
            + 'static,
    ) {
        self.insert_reserved(
            Some(QueueWorkerTicket::Periodic(
                // Relaxed is sufficient: this counter only mints a unique periodic-ticket index; it
                // guards no other memory and needs no happens-before ordering, so SeqCst's full
                // fence is unnecessary (and costlier on weak-memory archs like aarch64).
                QUEUE_WORKER_RESERVED_INDEX
                    .wrapping_add(self.rolling_idx.fetch_add(1, Ordering::Relaxed)),
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
            self.rolling_idx
                .wrapping_add(QUEUE_WORKER_RESERVED_INDEX + 1),
            RESERVED_CID_IDX,
        ));
        let delay = self.expirations.insert(key_new, timeout);

        if let Some((_, replaced_delay, _)) =
            self.entries.insert(key_new, (on_timeout, delay, timeout))
        {
            // Every key in `entries` has its live delay: left in the queue, the replaced one
            // would fire for an entry that no longer matches it.
            let _ = self.expirations.remove(&replaced_delay);
            log::warn!(target: "citadel", "Replaced the queue entry {key_new:?}");
        }

        self.rolling_idx = self.rolling_idx.wrapping_add(1);
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
    fn poll_purge(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QueueShutdown>> {
        self.register_waker(cx.waker());

        let SessionQueueWorker {
            expirations,
            state_container,
            entries,
            ..
        } = &mut *self;

        let mut state_container = inner_mut_state!(state_container.as_ref().unwrap());
        if state_container.state.get() != SessionState::Disconnecting {
            while let Some(res) = futures::ready!(expirations.poll_expired(cx)) {
                let entry: QueueWorkerTicket = res.into_inner();
                //log::trace!(target: "citadel", "POLL_EXPIRED: {:?}", &entry);
                match entry {
                    QueueWorkerTicket::Oneshot(_, _) => {
                        // already removed from expiration; now, just remove from hashmap
                        let Some((fx, _, _)) = entries.remove(&entry) else {
                            log::warn!(target: "citadel", "The queue entry {entry:?} expired with no function");
                            continue;
                        };
                        if let QueueWorkerResult::EndSession = (fx)(&mut state_container) {
                            return Poll::Ready(Err(QueueShutdown));
                        }
                    }

                    QueueWorkerTicket::Periodic(_, _) => {
                        let Some((fx, _key, duration)) = entries.get(&entry) else {
                            log::warn!(target: "citadel", "The queue entry {entry:?} expired with no function");
                            continue;
                        };

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
                                return Poll::Ready(Err(QueueShutdown));
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

                        if let Some((_fx, key, _duration)) = entries.get_mut(&entry) {
                            *key = next_key;
                        }
                    }
                }
            }

            Poll::Pending
        } else {
            // The session is ending: a normal end, not a failure.
            Poll::Ready(Ok(()))
        }
    }

    fn register_inbound(mut self: Pin<&mut Self>, cx: &mut Context<'_>) {
        while let Poll::Ready(Some((key, timeout, on_timeout))) =
            self.as_mut().get_mut().rx.poll_recv(cx)
        {
            self.as_mut()
                .get_mut()
                .insert_reserved(key, timeout, on_timeout);
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
        self.as_mut().register_inbound(cx);
        let _ = futures::ready!(self.poll_purge(cx));
        Poll::Ready(None)
    }
}

impl<R: Ratchet> futures::Future for SessionQueueWorker<R> {
    type Output = Result<(), NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.as_mut().register_inbound(cx);
        let ended = futures::ready!(self.as_mut().poll_purge(cx));
        // Fails only when nothing listens, which means the session is already gone.
        let _ = self.sess_shutdown.send(());
        Poll::Ready(ended.map_err(|_| error!(ErrorCode::QueueHandlerShutdown)))
    }
}
