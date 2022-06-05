use futures::Stream;
use std::task::{Poll, Context, Waker};
use std::pin::Pin;
use tokio_util::time::{delay_queue, DelayQueue};
use tokio::time::error::Error;
use std::collections::HashMap;
use crate::hdp::hdp_session::SessionState;
use crate::hdp::hdp_packet_processor::includes::Duration;
use crate::error::NetworkError;
use tokio::sync::broadcast::Sender;

use crate::hdp::state_container::{StateContainerInner, StateContainer};
use crate::inner_arg::ExpectedInnerTargetMut;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};

/// any index below 10 are reserved for the session. Inbound GROUP timeouts will begin at 10 or high
pub const QUEUE_WORKER_RESERVED_INDEX: usize = 10;
pub const RESERVED_CID_IDX: u64 = 0;

pub const PROVISIONAL_CHECKER: usize = 0;
pub const DRILL_REKEY_WORKER: usize = 1;
pub const KEEP_ALIVE_CHECKER: usize = 2;
pub const FIREWALL_KEEP_ALIVE: usize = 3;

pub trait QueueFunction: Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) -> QueueWorkerResult + Send + 'static {}
pub trait QueueOneshotFunction: Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) + Send + 'static {}

impl<T: Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) -> QueueWorkerResult + Send + 'static> QueueFunction for T {}
impl<T: Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) + Send + 'static> QueueOneshotFunction for T {}

pub struct SessionQueueWorker {
    entries: HashMap<QueueWorkerTicket, (Box<dyn QueueFunction>, delay_queue::Key, Duration)>,
    expirations: DelayQueue<QueueWorkerTicket>,
    state_container: Option<StateContainer>,
    sess_shutdown: Sender<()>,
    waker: Option<Waker>,
    rx: UnboundedReceiver<ChannelInner>,
    // keeps track of how many items have been added
    rolling_idx: usize
}

#[derive(Clone)]
pub struct SessionQueueWorkerHandle {
    tx: UnboundedSender<ChannelInner>
}

type ChannelInner = (Option<QueueWorkerTicket>, Duration, Box<dyn QueueFunction>);

impl SessionQueueWorkerHandle {
    /// Inserts a reserved system process. We now spawn this as a task to prevent deadlocking
    pub fn insert_reserved(&self, key: Option<QueueWorkerTicket>, timeout: Duration, on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) -> QueueWorkerResult + Send + 'static) {
        let _ = self.tx.send((key, timeout, Box::new(on_timeout)));
    }

    /// A conveniant way to check on a task once sometime in the future
    #[allow(dead_code)]
    pub fn insert_oneshot(&self, call_in: Duration, on_call: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) + Send + 'static) {
        self.insert_reserved(None, call_in, move |sess| {
            (on_call)(sess);
            QueueWorkerResult::Complete
        });
    }

    /// factors-in the offset
    pub fn insert_ordinary(&self, idx: usize, target_cid: u64, timeout: Duration, on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) -> QueueWorkerResult + Send + 'static) {
        self.insert_reserved(Some(QueueWorkerTicket::Periodic(idx + QUEUE_WORKER_RESERVED_INDEX, target_cid)), timeout, on_timeout)
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

impl SessionQueueWorker {

    pub fn new(sess_shutdown: Sender<()>) -> (Self, SessionQueueWorkerHandle) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = SessionQueueWorkerHandle { tx };
        (Self { rx, waker: None, sess_shutdown, rolling_idx: 0, entries: HashMap::new(), expirations: DelayQueue::new(), state_container: None }, handle)
    }

    /// MUST be called when a session's timer subroutine begins!
    pub fn load_state_container(&mut self, state_container: StateContainer) {
        self.state_container = Some(state_container.clone());
    }

    /// Inserts a reserved system process. We now spawn this as a task to prevent deadlocking
    #[allow(unused_results)]
    pub fn insert_reserved(&mut self, key: Option<QueueWorkerTicket>, timeout: Duration, on_timeout: Box<dyn QueueFunction>) {
        // the zero in the default unwrap ensures that the key is going to be unique
        let key = key.unwrap_or(QueueWorkerTicket::Oneshot(self.rolling_idx + QUEUE_WORKER_RESERVED_INDEX + 1, RESERVED_CID_IDX));
        let delay = self.expirations
            .insert(key, timeout);

        if let Some(key) = self.entries.insert(key, (on_timeout, delay, timeout)) {
            log::error!("Overwrote a session key: {:?}", key.1);
        }

        self.rolling_idx += 1;
    }

    pub fn insert_reserved_fn(&mut self, key: Option<QueueWorkerTicket>, timeout: Duration, on_timeout: impl Fn(&mut dyn ExpectedInnerTargetMut<StateContainerInner>) -> QueueWorkerResult + Send + 'static) {
        self.insert_reserved(key, timeout, Box::new(on_timeout))
    }

    // Single-thread note: re-entrancy is okay since we can hold multiple borrow at once, but not multiple borrow_muts
    fn register_waker(&mut self, waker: &futures::task::Waker) {
        self.waker = Some(waker.clone());
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }

    #[allow(unused_results)]
    fn poll_purge(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        //log::info!("poll_purge");
        self.register_waker(cx.waker());

        let SessionQueueWorker {
            expirations,
            state_container,
            entries,
            ..
        } = &mut *self;

            let mut state_container = inner_mut_state!(state_container.as_ref().unwrap());
            if state_container.state.load(Ordering::Relaxed) != SessionState::Disconnected {
                while let Some(res) = futures::ready!(expirations.poll_expired(cx)) {
                    let entry: QueueWorkerTicket = res.into_inner();
                    //log::info!("POLL_EXPIRED: {:?}", &entry);
                    match entry {
                        QueueWorkerTicket::Oneshot(_, _) => {
                            // already removed from expiration; now, just remove from hashmap
                            let (fx, _, _) = entries.remove(&entry).unwrap();
                            match (fx)(&mut state_container) {
                                QueueWorkerResult::EndSession => {
                                    return Poll::Ready(Err(Error::shutdown()));
                                }

                                _ => {}
                            }
                        }

                        QueueWorkerTicket::Periodic(_, _) => {
                            let (fx, _key, duration) = entries.get(&entry).unwrap();

                            let next_key = match (fx)(&mut state_container) {
                                QueueWorkerResult::Complete => {
                                    // nothing to do here since already removed entry
                                    //this.expirations.remove(&key2);
                                    entries.remove(&entry);
                                    // the below line was to fix a bug where the queue wouldn't be polled if ANY
                                    // task returned Complete
                                    std::mem::drop(state_container);
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
                                    let duration = duration.clone();
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

impl Stream for SessionQueueWorker {
    // DelayQueue seems much more specific, where a user may care that it
    // has reached capacity, so return those errors instead of panicking.
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.as_mut().get_mut().rx.poll_recv(cx) {
                Poll::Ready(Some((key, timeout, on_timeout))) => {
                    // register any inbound tasks
                    self.as_mut().get_mut().insert_reserved(key, timeout, on_timeout);
                }

                _ => {
                    break;
                }
            }
        }

        match futures::ready!(self.poll_purge(cx)) {
            Ok(_) => {
                Poll::Pending
            }

            Err(_) => {
                Poll::Ready(None)
            }
        }
    }
}

impl futures::Future for SessionQueueWorker {
    type Output = Result<(), NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.as_mut().poll_next(cx)) {
            Some(_) => Poll::Pending,
            None => {
                if let Err(_err) = self.sess_shutdown.send(()) {
                    //log::error!("Unable to shutdown session: {:?}", err);
                }

                Poll::Ready(Err(NetworkError::InternalError("Queue handler signalled shutdown")))
            }
        }
    }
}