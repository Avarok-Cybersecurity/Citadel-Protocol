use futures::Stream;
use std::task::{Poll, Context};
use std::pin::Pin;
use tokio::time::{delay_queue, DelayQueue, Error};
use std::collections::HashMap;
use crate::hdp::hdp_session::{HdpSession, HdpSessionInner, SessionState, WeakHdpSessionBorrow};
use crate::hdp::hdp_packet_processor::includes::Duration;
use std::hash::{Hasher, BuildHasher};
use byteorder::{BigEndian, ByteOrder};
use crate::inner_arg::InnerParameterMut;
use crate::macros::{SessionBorrow, ContextRequirements};
use crate::error::NetworkError;
use futures::task::AtomicWaker;
use crate::hdp::outbound_sender::Sender;

/// any index below 10 are reserved for the session. Inbound GROUP timeouts will begin at 10 or high
pub const QUEUE_WORKER_RESERVED_INDEX: usize = 10;
pub const RESERVED_CID_IDX: u64 = 0;

pub const PROVISIONAL_CHECKER: usize = 0;
pub const DRILL_REKEY_WORKER: usize = 1;
pub const KEEP_ALIVE_CHECKER: usize = 2;
pub const FIREWALL_KEEP_ALIVE: usize = 3;

//define_outer_struct_wrapper!(SessionQueueWorker, SessionQueueWorkerInner);
#[derive(Clone)]
#[cfg(feature = "multi-threaded")]
pub struct SessionQueueWorker {
    inner: std::sync::Arc<parking_lot::Mutex<SessionQueueWorkerInner>>,
    waker: std::sync::Arc<AtomicWaker>
}

pub trait QueueFunction: Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) -> QueueWorkerResult + ContextRequirements {}
pub trait QueueOneshotFunction: Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) + ContextRequirements {}

impl<T: Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) -> QueueWorkerResult + ContextRequirements> QueueFunction for T {}
impl<T: Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) + ContextRequirements> QueueOneshotFunction for T {}

#[derive(Clone)]
#[cfg(not(feature = "multi-threaded"))]
pub struct SessionQueueWorker {
    inner: std::rc::Rc<std::cell::RefCell<SessionQueueWorkerInner>>,
    waker: std::rc::Rc<AtomicWaker>
}

#[cfg(feature = "multi-threaded")]
macro_rules! unlock {
    ($item:expr) => {
        $item.inner.lock()
    };
}

#[cfg(not(feature = "multi-threaded"))]
macro_rules! unlock {
    ($item:expr) => {
        $item.inner.borrow_mut()
    };
}

pub struct SessionQueueWorkerInner {
    entries: HashMap<QueueWorkerTicket, (Box<dyn QueueFunction>, delay_queue::Key, Duration), NoHash>,
    expirations: DelayQueue<QueueWorkerTicket>,
    session: Option<WeakHdpSessionBorrow>,
    sess_shutdown: Sender<()>,
    // keeps track of how many items have been added
    rolling_idx: usize
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueueWorkerTicket {
    Oneshot(usize, u64),
    Periodic(usize, u64)
}

pub enum QueueWorkerResult {
    Complete,
    Incomplete,
    EndSession,
    AdjustPeriodicity(Duration)
}

impl SessionQueueWorker {
    #[cfg(feature = "multi-threaded")]
    pub fn new(sess_shutdown: Sender<()>) -> Self {
        let waker = std::sync::Arc::new(AtomicWaker::new());
        //Self::from(SessionQueueWorkerInner { rolling_idx: 0, entries: HashMap::with_hasher(NoHash(0)), expirations: DelayQueue::new(), waker: Arc::new(AtomicWaker::new()), session: None })
        Self { waker, inner: std::sync::Arc::new(parking_lot::Mutex::new(SessionQueueWorkerInner { sess_shutdown, rolling_idx: 0, entries: HashMap::with_hasher(NoHash(0)), expirations: DelayQueue::new(), session: None })) }
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn new(sess_shutdown: Sender<()>) -> Self {
        let waker = std::rc::Rc::new(AtomicWaker::new());
        //Self::from(SessionQueueWorkerInner { rolling_idx: 0, entries: HashMap::with_hasher(NoHash(0)), expirations: DelayQueue::new(), waker: Arc::new(AtomicWaker::new()), session: None })
        Self { waker, inner: std::rc::Rc::new(std::cell::RefCell::new(SessionQueueWorkerInner { sess_shutdown, rolling_idx: 0, entries: HashMap::with_hasher(NoHash(0)), expirations: DelayQueue::new(), session: None })) }
    }

    pub fn signal_shutdown(&self) {
        let mut this = unlock!(self);
        if let Err(_) = this.sess_shutdown.try_send(()) {
            log::warn!("Unable to signal shutdown through SessionQueueHandler")
        }
    }

    /// MUST be called when a session's timer subroutine begins!
    pub fn load_session(&self, session: &HdpSession) {
        let mut this = unlock!(self);
        this.session = Some(session.as_weak());
    }

    #[allow(dead_code)]
    pub fn remove_entry(&self, key: QueueWorkerTicket) {
        let mut this = unlock!(self);
        if let Some((_, key, _)) = this.entries.remove(&key) {
            let _ = this.expirations.remove(&key);
        }
    }

    /// Inserts a reserved system process. We now spawn this as a task to prevent deadlocking
    #[allow(unused_results)]
    pub fn insert_reserved(&self, key: Option<QueueWorkerTicket>, timeout: Duration, on_timeout: impl Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) -> QueueWorkerResult + ContextRequirements) {
            //tokio::task::yield_now().await;
            let mut this = unlock!(self);
            // the zero in the default unwrap ensures that the key is going to be unique
            let key = key.unwrap_or(QueueWorkerTicket::Oneshot(this.rolling_idx + QUEUE_WORKER_RESERVED_INDEX + 1, RESERVED_CID_IDX));
            let delay = this.expirations
                .insert(key, timeout);

            if let Some(key) = this.entries.insert(key, (Box::new(on_timeout), delay, timeout)) {
                log::error!("Overwrote a session key: {:?}", key.1);
            }

            this.rolling_idx += 1;

            std::mem::drop(this);
            // may not be registered yet
            self.waker.wake();

    }

    /// A conveniant way to check on a task once sometime in the future
    pub fn insert_oneshot(&self, call_in: Duration, on_call: impl Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) + ContextRequirements) {
        self.insert_reserved(None, call_in, move |sess| {
            (on_call)(sess);
            QueueWorkerResult::Complete
        });
    }

    /// factors-in the offset
    pub fn insert_ordinary(&self, idx: usize, target_cid: u64, timeout: Duration, on_timeout: impl Fn(&mut InnerParameterMut<SessionBorrow, HdpSessionInner>) -> QueueWorkerResult + ContextRequirements) {
        self.insert_reserved(Some(QueueWorkerTicket::Periodic(idx + QUEUE_WORKER_RESERVED_INDEX, target_cid)), timeout, on_timeout)
    }

    #[allow(unused_results)]
    fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        //log::info!("poll_purge");
        self.waker.register(cx.waker());

        let mut this = unlock!(self);

        if let Some(sess) = HdpSession::upgrade_weak(this.session.as_ref().unwrap()) {
            let mut sess = inner_mut!(sess);
            if sess.state != SessionState::Disconnected {
                while let Some(res) = futures::ready!(this.expirations.poll_expired(cx)) {
                    let entry: QueueWorkerTicket = res?.into_inner();
                    //log::info!("POLL_EXPIRED: {:?}", &entry);
                    match entry {
                        QueueWorkerTicket::Oneshot(_, _) => {
                            // already removed from expiration; now, just remove from hashmap
                            let (fx, _, _) = this.entries.remove(&entry).unwrap();
                            match (fx)(&mut wrap_inner_mut!(sess)) {
                                QueueWorkerResult::EndSession => {
                                    return Poll::Ready(Err(Error::shutdown()))
                                }

                                _ => {}
                            }
                        }

                        QueueWorkerTicket::Periodic(_, _) => {
                            let (fx, _key, duration) = this.entries.get(&entry).unwrap();

                            let next_key = match (fx)(&mut wrap_inner_mut!(sess)) {
                                QueueWorkerResult::Complete => {
                                    // nothing to do here since already removed entry
                                    //this.expirations.remove(&key2);
                                    this.entries.remove(&entry);
                                    // the below line was to fix a bug where the queue wouldn't be polled if ANY
                                    // task returned Complete
                                    std::mem::drop(this);
                                    self.waker.wake();
                                    return Poll::Pending;
                                }

                                QueueWorkerResult::EndSession => {
                                    return Poll::Ready(Err(Error::shutdown()))
                                }

                                QueueWorkerResult::AdjustPeriodicity(new_period) => {
                                    this.expirations.insert(entry, new_period)
                                }
                                _ => {
                                    // if incomplete, and is periodic, reset it
                                    let duration = duration.clone();
                                    this.expirations.insert(entry, duration)
                                    // since we re-inserted the item, we need to schedule it to be awaken again
                                }
                            };
                            let (_fx, key, _duration) = this.entries.get_mut(&entry).unwrap();
                            *key = next_key;
                        }
                    }
                }

                Poll::Pending
            } else {
                Poll::Ready(Err(Error::shutdown()))
            }
        } else {
            log::warn!("HdpSession dropped");
            Poll::Ready(Err(Error::shutdown()))
        }
    }
}

impl Stream for SessionQueueWorker {
    // DelayQueue seems much more specific, where a user may care that it
    // has reached capacity, so return those errors instead of panicking.
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
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
                if let Err(_err) = unlock!(self.as_mut()).sess_shutdown.try_send(()) {
                    //log::error!("Unable to shutdown session: {:?}", err);
                }
                Poll::Ready(Err(NetworkError::InternalError("Queue handler signalled shutdown")))
            }
        }
    }
}

/// TODO: check soundness
struct NoHash(u64);

impl Hasher for NoHash {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = BigEndian::read_u64(bytes);
    }
}

impl BuildHasher for NoHash {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        NoHash(0)
    }
}

