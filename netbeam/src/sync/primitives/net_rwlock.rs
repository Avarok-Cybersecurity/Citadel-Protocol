/*!
 * # Network Read-Write Lock
 *
 * A distributed read-write lock implementation that provides synchronized access to
 * shared state across network endpoints. Similar to std::sync::RwLock, but operates
 * over a network connection with support for multiple readers and exclusive writers.
 *
 * ## Features
 * - Distributed read-write locking
 * - Multiple concurrent readers
 * - Exclusive writer access
 * - Network-aware locking mechanism
 * - Automatic lock release on drop
 * - State synchronization between nodes
 * - Lock type upgrades and downgrades
 * - Background state management
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::primitives::net_rwlock::NetRwLock;
 * use netbeam::sync::subscription::Subscribable;
 * use anyhow::Result;
 *
 * async fn example<S: Subscribable + 'static>(connection: &S) -> Result<()> {
 *     // Create a network-aware RwLock
 *     let rwlock = NetRwLock::create(connection, Some(0)).await?;
 *
 *     // Acquire read lock
 *     let read_guard = rwlock.read().await?;
 *     println!("Read value: {}", *read_guard);
 *     drop(read_guard);
 *
 *     // Acquire write lock
 *     let mut write_guard = rwlock.write().await?;
 *     *write_guard = 42;
 *
 *     Ok(())
 * }
 * ```
 *
 * ## Important Notes
 * - Lock acquisition is asynchronous
 * - Multiple readers can access simultaneously
 * - Writers have exclusive access
 * - State is synchronized on write release
 * - Uses multiplexed connections
 * - Background handlers manage state
 *
 * ## Related Components
 * - `net_mutex.rs`: Network-aware mutex
 * - `subscription.rs`: Subscription system for network events
 */

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use citadel_io::tokio::sync::mpsc::{Receiver, Sender};
use citadel_io::tokio::sync::{Mutex, OwnedMutexGuard};

use crate::reliable_conn::ReliableOrderedStreamToTargetExt;
use crate::sync::primitives::net_mutex::{sync_establish_init, InnerChannel};
use crate::sync::primitives::NetObject;
use crate::sync::subscription::Subscribable;
use crate::sync::subscription::SubscriptionBiStream;
use crate::sync::RelativeNodeType;
use crate::time_tracker::TimeTracker;
use crate::ScopedFutureResult;
use serde::{Deserialize, Serialize};

type InnerState<T> = (T, Sender<()>);
type OwnedLocalReadLock<T> = Arc<OwnedMutexGuard<InnerState<T>>>;
type OwnedLocalWriteLock<T> = OwnedMutexGuard<InnerState<T>>;

/// A distributed read-write lock implementation that provides synchronized access to
/// shared state across network endpoints.
pub struct NetRwLock<T: NetObject, S: Subscribable + 'static> {
    // Used to hold a lock when either local or remote is engaged. We use a Mutex here over an RwLock because
    // if local tries to read, then we get a mutex guard with an Arc wrapped around it to allow clonable read access.
    // if local tries to write, then the mutex guard is given-as is
    shared: Arc<Mutex<InnerState<T>>>,
    channel: Arc<InnerChannel<S>>,
    stop_tx: Option<citadel_io::tokio::sync::oneshot::Sender<()>>,
    // Used to cheaply clone read locks locally. There is no equivalent WriteLock version, since only one can exist
    local_active_read_lock: Arc<citadel_io::RwLock<Option<OwnedLocalReadLock<T>>>>,
    active_to_bg_signalled: Sender<()>,
}

impl<T: NetObject, S: Subscribable + 'static> NetRwLock<T, S> {
    /// Returns the node type of the underlying channel.
    pub fn node_type(&self) -> RelativeNodeType {
        self.channel.node_type()
    }

    /// Creates a new network rwlock with the given initial value.
    pub async fn new_internal(
        channel: InnerChannel<S>,
        initial_value: T,
    ) -> Result<Self, anyhow::Error> {
        // create a channel to listen here for incoming messages and alter the local state as needed
        let (stop_tx, stop_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (active_to_bg_tx, active_to_bg_rx) = citadel_io::tokio::sync::mpsc::channel(1);

        let this = Self {
            shared: Arc::new(Mutex::new((initial_value, active_to_bg_tx.clone()))),
            channel: Arc::new(channel),
            stop_tx: Some(stop_tx),
            local_active_read_lock: Arc::new(citadel_io::RwLock::new(None)),
            active_to_bg_signalled: active_to_bg_tx,
        };

        let shared_state = this.shared.clone();
        let local_read_lock = this.local_active_read_lock.clone();
        let channel = this.channel.clone();

        citadel_io::tokio::task::spawn(async move {
            if let Err(err) = passive_background_handler::<S, T>(
                channel,
                shared_state,
                stop_rx,
                active_to_bg_rx,
                local_read_lock,
            )
            .await
            {
                log::error!(target: "citadel", "[NetRwLock] Err: {:?}", err.to_string());
            }

            log::trace!(target: "citadel", "[NetRwLock] Passive background handler ending")
        });

        Ok(this)
    }

    /// Creates a new network rwlock loader with the given connection and initial value.
    pub fn create(conn: &S, t: Option<T>) -> NetRwLockLoader<T, S> {
        NetRwLockLoader {
            future: Box::pin(sync_establish_init(conn, t, Self::new_internal)),
        }
    }

    /// Acquires a read lock on the network rwlock.
    pub fn read(&self) -> RwLockReadAcquirer<T, S> {
        RwLockReadAcquirer {
            future: Box::pin(acquire_read(self)),
        }
    }

    /// Acquires a write lock on the network rwlock.
    pub fn write(&self) -> RwLockWriteAcquirer<T, S> {
        RwLockWriteAcquirer {
            future: Box::pin(acquire_write(self)),
        }
    }

    /// Returns the number of active local reads.
    pub fn active_local_reads(&self) -> usize {
        self.local_active_read_lock
            .read()
            .as_ref()
            .map(|r| Arc::strong_count(r) - 1)
            .unwrap_or(0)
    }
}

impl<T: NetObject, S: Subscribable + 'static> Drop for NetRwLock<T, S> {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "DROPPING {:?} NetRwLock", self.channel.node_type());
        let conn = self.channel.clone();
        let stop_tx = self.stop_tx.take().unwrap();
        let _ = stop_tx.send(());

        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            rt.spawn(async move { conn.send_serialized(UpdatePacket::Halt).await });
        }
    }
}

/// A network rwlock loader that creates a new network rwlock with the given connection and initial value.
pub struct NetRwLockLoader<'a, T: NetObject, S: Subscribable + 'static> {
    future: ScopedFutureResult<'a, NetRwLock<T, S>>,
}

impl<T: NetObject, S: Subscribable + 'static> Future for NetRwLockLoader<'_, T, S> {
    type Output = Result<NetRwLock<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// A read acquirer that acquires a read lock on the network rwlock.
pub struct RwLockReadAcquirer<'a, T: NetObject + 'static, S: Subscribable + 'static> {
    pub(crate) future: ScopedFutureResult<'a, NetRwLockReadGuard<T, S>>,
}

/// A read guard that provides read access to the network rwlock.
pub struct NetRwLockReadGuard<T: NetObject + 'static, S: Subscribable + 'static> {
    inner: Option<LocalLockHolder<T>>,
    conn: Arc<InnerChannel<S>>,
    shared_store: Arc<citadel_io::RwLock<Option<OwnedLocalReadLock<T>>>>,
}

impl<T: NetObject, S: Subscribable + 'static> Future for RwLockReadAcquirer<'_, T, S> {
    type Output = Result<NetRwLockReadGuard<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Acquires a read lock on the network rwlock.
pub(super) async fn acquire_read<T: NetObject + 'static, S: Subscribable + 'static>(
    rwlock: &NetRwLock<T, S>,
) -> Result<NetRwLockReadGuard<T, S>, anyhow::Error> {
    log::trace!(target: "citadel", "Running acquire_read for {:?}", rwlock.channel.node_type());
    {
        let pre_loaded = rwlock.local_active_read_lock.read();
        log::trace!(target: "citadel", "Running acquire_read for {:?} | pre_loaded ? {}", rwlock.channel.node_type(), pre_loaded.is_some());
        // if there is more than one strong reference, we can return early
        if pre_loaded
            .as_ref()
            .map(|r| Arc::strong_count(r) > 1)
            .unwrap_or(false)
        {
            return Ok(NetRwLockReadGuard {
                inner: Some(LocalLockHolder::Read(pre_loaded.clone(), false)),
                conn: rwlock.channel.clone(),
                shared_store: rwlock.local_active_read_lock.clone(),
            });
        }
    }

    // no read locks exist currently. Acquire a local shared read lock
    acquire_lock(LockType::Read, rwlock, |inner| NetRwLockReadGuard {
        inner: Some(inner),
        conn: rwlock.channel.clone(),
        shared_store: rwlock.local_active_read_lock.clone(),
    })
    .await
}

impl<T: NetObject, S: Subscribable> Deref for NetRwLockReadGuard<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap().deref()
    }
}

impl<T: NetObject, S: Subscribable + 'static> Drop for NetRwLockReadGuard<T, S> {
    fn drop(&mut self) {
        let this = self.inner.take().unwrap();
        // if there are two left, then this is the final rwlock active for the user. The other one is the lock stored inside the rwlock
        if this.arc_strong_count().unwrap() == 2 {
            log::trace!(target: "citadel", "CALLING read drop code on {:?}", self.conn.node_type());
            // immediately remove the shared store to prevent further acquires
            *self.shared_store.write() = None; // 1 arc left (this)

            if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
                let future = NetRwLockEitherGuardDropCode::new::<T, S>(self.conn.clone(), this);
                rt.spawn(future);
            }
        }
    }
}

/// A write acquirer that acquires a write lock on the network rwlock.
pub struct RwLockWriteAcquirer<'a, T: NetObject + 'static, S: Subscribable + 'static> {
    pub(crate) future: ScopedFutureResult<'a, NetRwLockWriteGuard<T, S>>,
}

/// A write guard that provides write access to the network rwlock.
pub struct NetRwLockWriteGuard<T: NetObject + 'static, S: Subscribable + 'static> {
    inner: Option<LocalLockHolder<T>>,
    conn: Arc<InnerChannel<S>>,
}

impl<T: NetObject, S: Subscribable> Future for RwLockWriteAcquirer<'_, T, S> {
    type Output = Result<NetRwLockWriteGuard<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Acquires a write lock on the network rwlock.
pub(super) async fn acquire_write<T: NetObject + 'static, S: Subscribable + 'static>(
    rwlock: &NetRwLock<T, S>,
) -> Result<NetRwLockWriteGuard<T, S>, anyhow::Error> {
    acquire_lock(LockType::Write, rwlock, |inner| NetRwLockWriteGuard {
        inner: Some(inner),
        conn: rwlock.channel.clone(),
    })
    .await
}

impl<T: NetObject, S: Subscribable> Deref for NetRwLockWriteGuard<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<T: NetObject, S: Subscribable> DerefMut for NetRwLockWriteGuard<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.as_mut().unwrap().assert_write_mut().0
    }
}

impl<T: NetObject + 'static, S: Subscribable + 'static> Drop for NetRwLockWriteGuard<T, S> {
    fn drop(&mut self) {
        let this = self.inner.take().unwrap();
        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            let future = NetRwLockEitherGuardDropCode::new::<T, S>(self.conn.clone(), this);
            rt.spawn(future);
        }
    }
}

/// A drop code that releases the lock with the adjacent endpoint, updating the value too for the adjacent node if a write lock was dropped.
pub(super) struct NetRwLockEitherGuardDropCode {
    future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>>,
}

impl NetRwLockEitherGuardDropCode {
    pub(super) fn new<T: NetObject + 'static, S: Subscribable + 'static>(
        conn: Arc<InnerChannel<S>>,
        guard: LocalLockHolder<T>,
    ) -> Self {
        Self {
            future: Box::pin(net_rwlock_guard_drop_code::<T, S>(conn, guard)),
        }
    }
}

impl Future for NetRwLockEitherGuardDropCode {
    type Output = Result<(), anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Releases the lock with the adjacent endpoint, updating the value too for the adjacent node if a write lock was dropped.
async fn net_rwlock_guard_drop_code<T: NetObject, S: Subscribable + 'static>(
    conn: Arc<InnerChannel<S>>,
    lock: LocalLockHolder<T>,
) -> Result<(), anyhow::Error> {
    log::trace!(target: "citadel", "[NetRwLock] Drop code initialized for {:?}...", conn.node_type());
    match &lock {
        LocalLockHolder::Read(..) => {
            conn.send_serialized(UpdatePacket::ReleasedRead).await?;
        }

        LocalLockHolder::Write(_guard, ..) => {
            conn.send_serialized(UpdatePacket::ReleasedWrite(bincode::serialize(
                &lock.deref(),
            )?))
            .await?;
        }
    }

    let mut adjacent_trying_to_acquire = None;

    loop {
        let packet = conn.recv_serialized::<UpdatePacket>().await?;
        log::trace!(target: "citadel", "[NetRwLock] [Drop Code] RECV {:?} on {:?}", &packet, conn.node_type());

        match packet {
            UpdatePacket::ReleasedWrite(_new_value) => {
                //unreachable!("Adjacent signalled a release of the write lock, yet, local has not yet dropped read/write")
            }

            UpdatePacket::ReleasedRead => {
                if let LocalLockHolder::Read(..) = &lock {
                    log::trace!(target: "citadel", "Yield:: Releasing Read lock");
                    conn.send_serialized(UpdatePacket::ReleasedVerified(LockType::Read))
                        .await?;
                }
            }

            UpdatePacket::ReleasedVerified(_lock_type) => {
                log::trace!(target: "citadel", "[NetRwLock] [Drop Code] Release has been verified for {:?}. Adjacent node updated; will drop local lock", conn.node_type());

                if let Some(_lock_type) = adjacent_trying_to_acquire {
                    log::trace!(target: "citadel", "[NetRwLock] [Drop Code] Will not yet drop though, since remote requested lock access since dropping ...");
                    // all we have to do is hold the lock here. The underlying lock uses a mutex, so we are safe from parallel/concurrent local calls until after the yield is complete
                    log::trace!(target: "citadel", "[KTX] {:?} yield_lock", conn.node_type());
                    return yield_lock::<S, T>(&conn, lock).await.map(|_| ());
                }

                return Ok(());
            }

            UpdatePacket::TryAcquire(_, lock_type) => {
                adjacent_trying_to_acquire = Some(lock_type);
                // once the release is confirmed, we will yield the lock back to remote
                // However, if we are trying to drop a read locally, and they are trying to acquire a read, we can yield a read
                // no need to yield a lock either since local will need to ask again
            }

            UpdatePacket::Halt => return Err(anyhow::Error::msg("Halted from background")),

            UpdatePacket::LockAcquired(_) => {
                // this is received after sending the Released packet. We do nothing here
            }
        }
    }
}

/// A lock type that represents either a read or write lock.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
enum LockType {
    Read,
    Write,
}

/// A local lock holder that represents either a read or write lock.
pub(super) enum LocalLockHolder<T> {
    Write(Option<OwnedLocalWriteLock<T>>, bool),
    Read(Option<OwnedLocalReadLock<T>>, bool),
}

impl<T> Deref for LocalLockHolder<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Write(val, _) => &val.as_ref().unwrap().0,
            Self::Read(val, _) => &val.as_ref().unwrap().0,
        }
    }
}

impl<T> LocalLockHolder<T> {
    /// Returns whether the lock holder is from the background.
    fn is_from_background(&self) -> bool {
        match self {
            Self::Write(_, from_bg) | Self::Read(_, from_bg) => *from_bg,
        }
    }

    /// Returns the lock type of the lock holder.
    fn lock_type(&self) -> LockType {
        match self {
            Self::Write(..) => LockType::Write,
            Self::Read(..) => LockType::Read,
        }
    }

    /// Returns the sender of the lock holder.
    fn free_lock_and_get_sender(&mut self) -> Sender<()> {
        match self {
            Self::Read(r, _) => r.take().unwrap().1.clone(),
            Self::Write(w, _) => w.take().unwrap().1.clone(),
        }
    }

    /// Asserts that the lock holder is a write lock and returns a mutable reference to the write lock.
    fn assert_write_mut(&mut self) -> &mut OwnedLocalWriteLock<T> {
        match self {
            Self::Write(val, ..) => val.as_mut().unwrap(),
            _ => {
                panic!("Asserted write lock, but was a read lock");
            }
        }
    }

    /// Asserts that the lock holder is a read lock and returns a reference to the read lock.
    fn assert_read(&self) -> &OwnedLocalReadLock<T> {
        match self {
            Self::Read(val, ..) => val.as_ref().unwrap(),
            _ => {
                panic!("Asserted write lock, but was a read lock");
            }
        }
    }

    /// Upgrades the lock holder to a write lock.
    fn assert_read_and_upgrade(&mut self) {
        match self {
            Self::Read(val, from_bg) => {
                let val = val.take().unwrap();
                log::trace!(target: "citadel", "Arc count: {}", Arc::strong_count(&val));
                let upgraded = Arc::try_unwrap(val).map_err(|_| ()).unwrap();
                let new = LocalLockHolder::Write(Some(upgraded), *from_bg);
                *from_bg = true; // set to true to disable destructor from executing normally
                *self = new
            }

            Self::Write(..) => {
                panic!("Asserted read, but was write")
            }
        }
    }

    /// Downgrades the lock holder to a read lock.
    fn assert_write_and_downgrade(&mut self) {
        match self {
            Self::Write(val, from_bg) => {
                let new = LocalLockHolder::Read(val.take().map(Arc::new), *from_bg);
                *from_bg = true; // stop destructor from being called
                *self = new;
            }

            Self::Read(..) => {
                panic!("Asserted write, but was read")
            }
        }
    }

    /// Returns the strong count of the lock holder.
    fn arc_strong_count(&self) -> Option<usize> {
        match self {
            Self::Read(val, ..) => Some(Arc::strong_count(val.as_ref().unwrap())),
            Self::Write(..) => None,
        }
    }
}

impl<T> Drop for LocalLockHolder<T> {
    // The lock holder's only duty is to wake the background task. If there are more readers, the background will immediately go back to sleep
    fn drop(&mut self) {
        // if this is a lock holder from the BG, we aren't interested in sending an alert
        if !self.is_from_background() {
            let sender = self.free_lock_and_get_sender(); // frees the lock
            if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = sender.send(()).await; // alert the bg
                });
            }
        }
    }
}

/// Yields the lock to the adjacent endpoint.
async fn yield_lock<S: Subscribable + 'static, T: NetObject>(
    channel: &Arc<InnerChannel<S>>,
    mut lock: LocalLockHolder<T>,
) -> Result<LocalLockHolder<T>, anyhow::Error> {
    match &lock {
        LocalLockHolder::Read(..) => {
            channel.send_serialized(UpdatePacket::ReleasedRead).await?;
        }

        LocalLockHolder::Write(val, _) => {
            channel
                .send_serialized(UpdatePacket::ReleasedWrite(
                    bincode::serialize(&val.as_ref().unwrap().0).unwrap(),
                ))
                .await?;
        }
    }

    loop {
        let next_packet = channel.recv_serialized().await?;
        log::trace!(target: "citadel", "Yield::RECV | {:?} received {:?}", channel.node_type(), &next_packet);
        match next_packet {
            UpdatePacket::ReleasedWrite(new_value) => match &mut lock {
                LocalLockHolder::Write(val, _) => {
                    log::trace!(target: "citadel", "Yield:: Releasing Write lock");
                    val.as_mut().unwrap().0 = bincode::deserialize(&new_value)?;
                    channel
                        .send_serialized(UpdatePacket::ReleasedVerified(LockType::Write))
                        .await?;
                    return Ok(lock);
                }

                _ => {
                    log::warn!(target: "citadel", "{:?} | Invalid read/write packet. Expected a write, but local has a read", channel.node_type())
                }
            },

            UpdatePacket::ReleasedRead => match &lock {
                LocalLockHolder::Read(..) => {
                    log::trace!(target: "citadel", "Yield:: Releasing Read lock");
                    channel
                        .send_serialized(UpdatePacket::ReleasedVerified(LockType::Read))
                        .await?;
                    return Ok(lock);
                }

                _ => {
                    log::warn!(target: "citadel", "Invalid read/write packet. Expected a read, but local has a write")
                }
            },

            UpdatePacket::Halt => return Err(anyhow::Error::msg("Halted from background")),

            UpdatePacket::LockAcquired(_) => {
                // this is received after sending the Released packet. We do nothing here
            }

            p => {
                log::warn!(target: "citadel", "Received invalid packet type in inner_loop! {:?}", p)
            }
        }
    }
}

/// A passive background handler that manages the state of the network rwlock.
async fn passive_background_handler<S: Subscribable + 'static, T: NetObject>(
    channel: Arc<InnerChannel<S>>,
    shared_state: Arc<Mutex<InnerState<T>>>,
    stop_rx: citadel_io::tokio::sync::oneshot::Receiver<()>,
    mut active_to_background_rx: Receiver<()>,
    read_lock_local: Arc<citadel_io::RwLock<Option<OwnedLocalReadLock<T>>>>,
) -> Result<(), anyhow::Error> {
    let background_task = async move {
        'outer_loop: loop {
            // since this the background handler for the rwlock handler, we need to make one exception here compared to the flow of the normal mutex background handler.
            // Since it is possible for the adjacent node to hold a read lock while this node ALSO has a read lock, we need to check before polling the lock
            match shared_state.clone().try_lock_owned() {
                Ok(lock) => {
                    // here, any local requests will be blocked until an external packet gets received OR local signals background to stop;
                    let packet = citadel_io::tokio::select! {
                        res0 = channel.recv_serialized::<UpdatePacket>() => res0?,
                        res1 = active_to_background_rx.recv() => {
                            // in the case local tries ot make an outgoing request, we will stop listening in the background
                            res1.ok_or_else(|| anyhow::Error::msg("The active_to_background_tx died"))?;
                            continue 'outer_loop;
                        }
                    };

                    match packet {
                        UpdatePacket::TryAcquire(_, lock_type) => {
                            let lock_holder = match lock_type {
                                LockType::Read => {
                                    // load inside local map to allow instant local read access
                                    let lock = Some(Arc::new(lock));
                                    read_lock_local.write().clone_from(&lock);
                                    LocalLockHolder::Read(lock, true)
                                }

                                LockType::Write => LocalLockHolder::Write(Some(lock), true),
                            };

                            // we hold the lock locally, preventing local from sending any packets outbound from the active channel since the adjacent node is actively seeking to
                            // establish a lock
                            // we set "true" to the local lock holder to imply that the drop code won't alert the background (b/c we already are in BG)
                            log::trace!(target: "citadel", "[KTG] {:?} yield_lock", channel.node_type());
                            let lock_holder = yield_lock::<S, T>(&channel, lock_holder).await?; // return on error

                            // we must also manually free the read lock IF needs be
                            if lock_type == LockType::Read
                                && lock_holder.arc_strong_count().unwrap() == 2
                            {
                                // this implies local did NOT try to get a read lock from the read lock already present here. We can clear local;
                                *read_lock_local.write() = None;
                                std::mem::drop(lock_holder); // now, there are zero locks local
                            }
                        }

                        UpdatePacket::ReleasedRead
                        | UpdatePacket::ReleasedWrite(..)
                        | UpdatePacket::ReleasedVerified(..)
                        | UpdatePacket::LockAcquired(..) => {
                            log::warn!(target: "citadel", "RELEASED/RELEASED_VERIFIED/LOCK_ACQUIRED should only be received in the yield_lock subroutine.");
                        }

                        UpdatePacket::Halt => {
                            return Err(anyhow::Error::msg("Halted from background"))
                        }
                    }
                }

                Err(_) => {
                    // wait until the lock drops
                    active_to_background_rx
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::Error::msg("The active_to_background_tx died"))?;
                }
            }
        }
    };

    citadel_io::tokio::select! {
        res0 = background_task => res0,
        _res1 = stop_rx => Ok(())
    }
}

/// Acquires a lock on the network rwlock.
async fn acquire_lock<T: NetObject, S: Subscribable + 'static, R, F>(
    lock_type: LockType,
    rwlock: &NetRwLock<T, S>,
    fx: F,
) -> Result<R, anyhow::Error>
where
    F: Fn(LocalLockHolder<T>) -> R,
{
    log::trace!(target: "citadel", "Attempting to acquire lock for {:?}", rwlock.channel.node_type());
    // first, ensure background isn't already awaiting for a packet
    rwlock.active_to_bg_signalled.send(()).await?;
    let lock = rwlock.shared.clone().lock_owned().await;

    let mut owned_local_lock = match lock_type {
        LockType::Read => LocalLockHolder::Read(Some(Arc::new(lock)), false),
        LockType::Write => LocalLockHolder::Write(Some(lock), false),
    };

    log::trace!(target: "citadel", "{:?} acquired local lock", rwlock.channel.node_type());

    let conn = &rwlock.channel;

    let local_request_time = TimeTracker::new().get_global_time_ns();
    conn.send_serialized(UpdatePacket::TryAcquire(local_request_time, lock_type))
        .await
        .map_err(|err| anyhow::Error::msg(err.to_string()))?;

    loop {
        let packet = conn.recv_serialized().await?;
        log::trace!(target: "citadel", "{:?}/active-channel || obtained packet {:?}", rwlock.channel.node_type(), &packet);

        // the adjacent side will return one of two packets. In the first case, we wait until it drops the adjacent lock, in which case,
        // we get a Released packet. The side that gets this will automatically be allowed to acquire the mutex lock
        match packet {
            UpdatePacket::ReleasedWrite(new_data) => {
                let new_data = bincode::deserialize::<T>(&new_data)?;
                match &mut owned_local_lock {
                    LocalLockHolder::Write(lock, ..) => {
                        lock.as_mut().unwrap().0 = new_data;
                    }

                    LocalLockHolder::Read(lock_orig, _) => {
                        let mut lock = Arc::try_unwrap(lock_orig.take().unwrap())
                            .map_err(|_err| anyhow::Error::msg("Unable to unwrap Arc"))?;
                        lock.0 = new_data;
                        *lock_orig = Some(Arc::new(lock));
                    }
                }

                // now, send a LockAcquired packet
                conn.send_serialized(UpdatePacket::ReleasedVerified(lock_type))
                    .await?;
                conn.send_serialized(UpdatePacket::LockAcquired(lock_type))
                    .await?;

                if owned_local_lock.lock_type() == LockType::Read {
                    *rwlock.local_active_read_lock.write() =
                        Some(owned_local_lock.assert_read().clone())
                }

                return Ok((fx)(owned_local_lock));
            }

            UpdatePacket::ReleasedRead => {
                // now, send a LockAcquired packet
                conn.send_serialized(UpdatePacket::ReleasedVerified(lock_type))
                    .await?;
                conn.send_serialized(UpdatePacket::LockAcquired(lock_type))
                    .await?;

                if owned_local_lock.lock_type() == LockType::Read {
                    *rwlock.local_active_read_lock.write() =
                        Some(owned_local_lock.assert_read().clone())
                }

                return Ok((fx)(owned_local_lock));
            }

            UpdatePacket::LockAcquired(_lock_type) => {
                // in this case, the other side deemed that it should have the lock. We need to wait
            }

            UpdatePacket::TryAcquire(remote_request_time, lock_type) => {
                log::trace!(target: "citadel", "[local: {:?}] BOTH trying to acquire! Local: {:?} | Remote: {:?}", conn.node_type(), owned_local_lock.lock_type(), lock_type);
                // in this case both are trying to acquire, give to the node that requested first, OR, if it was given preference in case of the next conflict

                if lock_type == LockType::Read && owned_local_lock.lock_type() == LockType::Read {
                    // both win
                    log::trace!(target: "citadel", "BOTH acquiring reads. Both win");
                    // we tell the adjacent side that it won, while returning from here
                    // we don't yield here for the other side. Instead, the drop code must account for it (TODO)
                    conn.send_serialized(UpdatePacket::ReleasedRead).await?;

                    if owned_local_lock.lock_type() == LockType::Read {
                        *rwlock.local_active_read_lock.write() =
                            Some(owned_local_lock.assert_read().clone())
                    }

                    return Ok(fx(owned_local_lock));
                }

                let local_wins = if remote_request_time == local_request_time {
                    rwlock.node_type() == RelativeNodeType::Initiator
                } else {
                    remote_request_time > local_request_time
                };

                if local_wins {
                    // we requested before the remote node; tell the remote node we took the value
                    conn.send_serialized(UpdatePacket::LockAcquired(lock_type))
                        .await?;

                    if owned_local_lock.lock_type() == LockType::Read {
                        *rwlock.local_active_read_lock.write() =
                            Some(owned_local_lock.assert_read().clone())
                    }

                    return Ok((fx)(owned_local_lock));
                } else {
                    // transform only if local wins
                    if owned_local_lock.lock_type() != lock_type {
                        log::trace!(target: "citadel", "Remote is trying to acquire lock type not equal to local type. Must transform. Local {:?}, Remote {:?}", owned_local_lock.lock_type(), lock_type);
                        // if remote wants a write, all we need to do is clear the local read store and yield the lock to prevent local from reading
                        if lock_type == LockType::Write {
                            // this will prevent local from acquiring any reads
                            *rwlock.local_active_read_lock.write() = None;
                            owned_local_lock.assert_read_and_upgrade();
                        }

                        // if remote wants a read, and considering local holds a write, we need to downgrade the lock and yield
                        if lock_type == LockType::Read {
                            // just yield ahead
                            owned_local_lock.assert_write_and_downgrade();
                            log::trace!(target: "citadel", "Asserted local is write and downgraded");
                        }
                    }

                    log::trace!(target: "citadel", "[KTZZ] {:?} yield_lock", conn.node_type());
                    owned_local_lock = yield_lock::<S, T>(conn, owned_local_lock).await?;
                    // the next time a conflict happens, the local node will win unconditionally since its time is lesser than the next possible adjacent request time
                    // transform only if local wins
                    if owned_local_lock.lock_type() != lock_type {
                        log::trace!(target: "citadel", "[undo] Remote is trying to acquire lock type not equal to local type. Must transform");
                        // if remote wants a write, all we need to do is clear the local read store and yield the lock to prevent local from reading
                        if lock_type == LockType::Write {
                            // this will prevent local from acquiring any reads
                            owned_local_lock.assert_write_and_downgrade();
                            *rwlock.local_active_read_lock.write() =
                                Some(owned_local_lock.assert_read().clone()); // now, there are two in existence
                            assert_eq!(owned_local_lock.arc_strong_count().unwrap(), 2);
                        }

                        // if remote wants a read, and considering local holds a write, we need to downgrade the lock and yield
                        if lock_type == LockType::Read {
                            // just yield ahead
                            owned_local_lock.assert_read_and_upgrade();
                            *rwlock.local_active_read_lock.write() = None;
                            log::trace!(target: "citadel", "Asserted local is write and downgraded");
                        }
                    }
                }
            }

            UpdatePacket::Halt => {
                // the adjacent node dropped their NetRwLock. The program is done
                return Err(anyhow::Error::msg("The adjacent node dropped the Mutex"));
            }

            UpdatePacket::ReleasedVerified(..) => {
                log::warn!(target: "citadel", "RELEASED_VERIFIED should only be received by the drop_lock subroutine")
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
enum UpdatePacket {
    TryAcquire(i64, LockType),
    ReleasedWrite(Vec<u8>),
    ReleasedRead,
    LockAcquired(LockType),
    Halt,
    ReleasedVerified(LockType),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::sync::test_utils::create_streams;
    use citadel_io::tokio;

    #[tokio::test]
    async fn many_writes() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;

        const COUNT: u64 = 1000;

        let init_value = 1000u64;
        let final_value = 1001u64;
        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server_ref = Arc::new(AtomicU64::new(init_value));
        let client_ref = server_ref.clone();

        let server = citadel_io::tokio::spawn(async move {
            let rwlock = &server_stream.rwlock(Some(init_value)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on server");
            client_done_rx.await.unwrap();
            let guard = rwlock.write().await.unwrap();
            assert_eq!(*guard, final_value);
            log::trace!(target: "citadel", "Server ASSERT_EQ valid");
            std::mem::drop(guard);

            for idx in 1..COUNT {
                log::trace!(target: "citadel", "Server obtaining lock {}", idx);
                let mut lock = rwlock.write().await.unwrap();
                log::trace!(target: "citadel", "****Server obtained lock {} w/val {:?}", idx, &*lock);
                assert_eq!(idx + init_value, *lock);

                *lock += 1;
                server_ref.store(*lock, Ordering::SeqCst);
            }

            server_done_tx.send(()).unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let rwlock = &client_stream.rwlock::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on client");
            let mut guard = rwlock.write().await.unwrap();
            log::trace!(target: "citadel", "Client has successfully established a rwlock write lock");
            *guard = 1001;
            client_ref.store(*guard, Ordering::SeqCst);
            std::mem::drop(guard);
            client_done_tx.send(()).unwrap();

            for _ in 1..COUNT {
                let val = rwlock.write().await.unwrap();
                let loaded = client_ref.load(Ordering::SeqCst);
                if *val != loaded {
                    log::error!(target: "citadel", "Mutex value {} != loaded value {}", *val, loaded);
                    std::process::exit(-1);
                }
            }

            server_done_rx.await.unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }

    #[tokio::test]
    async fn many_reads() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;

        const COUNT: u64 = 1000;

        let init_value = 1000u64;
        let final_value = 1001u64;
        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx0, server_done_rx0) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (client_done_tx2, client_done_rx2) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server_ref = Arc::new(AtomicU64::new(init_value));
        let client_ref = server_ref.clone();

        let server = citadel_io::tokio::spawn(async move {
            let rwlock = &server_stream.rwlock(Some(init_value)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on server");
            client_done_rx.await.unwrap();
            let guard = rwlock.write().await.unwrap();
            assert_eq!(*guard, final_value);
            log::trace!(target: "citadel", "Server ASSERT_EQ valid");
            std::mem::drop(guard);
            server_done_tx0.send(()).unwrap();

            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Server obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                log::trace!(target: "citadel", "****Server obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            server_done_tx.send(()).unwrap();
            assert_eq!(rwlock.active_local_reads(), COUNT as _);
            log::trace!(target: "citadel", "**Server has acquired {} reads", COUNT);
            client_done_rx2.await.unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let rwlock = &client_stream.rwlock::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on client");
            let mut guard = rwlock.write().await.unwrap();
            log::trace!(target: "citadel", "Client has successfully established a rwlock write lock");
            *guard = 1001;
            client_ref.store(*guard, Ordering::SeqCst);
            std::mem::drop(guard);
            client_done_tx.send(()).unwrap();
            server_done_rx0.await.unwrap();
            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Client obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                log::trace!(target: "citadel", "****Client obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            log::trace!(target: "citadel", "**Client has acquired {} reads", COUNT);
            server_done_rx.await.unwrap();
            assert_eq!(rwlock.active_local_reads(), COUNT as _);
            std::mem::drop(reads);
            client_done_tx2.send(()).unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }

    #[citadel_io::tokio::test]
    async fn many_reads_no_initial_write() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;

        const COUNT: u64 = 1000;

        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server = citadel_io::tokio::spawn(async move {
            let rwlock = &server_stream.rwlock::<u64>(Some(1000)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on server");

            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Server obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                log::trace!(target: "citadel", "****Server obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            client_done_rx.await.unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let rwlock = &client_stream.rwlock::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on client");
            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Client obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                log::trace!(target: "citadel", "****Client obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            log::trace!(target: "citadel", "**Client has acquired {} reads", COUNT);

            std::mem::drop(reads);
            client_done_tx.send(()).unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }

    #[citadel_io::tokio::test]
    async fn many_reads_end_with_write() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;

        const COUNT: u64 = 1000;

        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let init_value = 1000u64;
        let final_value = 1001u64;

        let server_ref = Arc::new(AtomicU64::new(init_value));
        let client_ref = server_ref.clone();

        let server = citadel_io::tokio::spawn(async move {
            let rwlock = &server_stream.rwlock::<u64>(Some(1000)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on server");

            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Server obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                log::trace!(target: "citadel", "****Server obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            std::mem::drop(reads);

            client_done_rx.await.unwrap();
            let guard = rwlock.write().await.unwrap();
            assert_eq!(*guard, final_value);
            log::trace!(target: "citadel", "Server ASSERT_EQ valid");
            std::mem::drop(guard);
            server_done_tx.send(()).unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let rwlock = &client_stream.rwlock::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on client");
            let mut reads = Vec::new();

            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Client obtaining lock {}", idx);
                let lock = rwlock.read().await.unwrap();
                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                log::trace!(target: "citadel", "****Client obtained read lock {} w/val {:?}", idx, &*lock);
                reads.push(lock);
            }

            log::trace!(target: "citadel", "**Client has acquired {} reads", COUNT);

            std::mem::drop(reads);

            let mut guard = rwlock.write().await.unwrap();
            log::trace!(target: "citadel", "Client has successfully established a rwlock write lock");
            *guard = 1001;
            client_ref.store(*guard, Ordering::SeqCst);
            std::mem::drop(guard);
            client_done_tx.send(()).unwrap();
            server_done_rx.await.unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }

    #[citadel_io::tokio::test]
    async fn many_interweaved() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;

        const COUNT: u64 = 1000;

        let (init_tx, init_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (init2_tx, init2_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server_ref = Arc::new(AtomicU64::new(0));
        let client_ref = server_ref.clone();

        let server = citadel_io::tokio::spawn(async move {
            let rwlock = &server_stream.rwlock::<u64>(Some(0)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on server");
            init_tx.send(()).unwrap();
            init2_rx.await.unwrap();

            let mut do_read = false;
            for idx in 0..COUNT {
                log::trace!(target: "citadel", "Server obtaining lock {}", idx);
                if do_read {
                    let lock = rwlock.read().await.unwrap();
                    //citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    log::trace!(target: "citadel", "****Server obtained read lock {} w/val {:?}", idx, &*lock);
                    do_read = false;
                    assert_eq!(server_ref.load(Ordering::Relaxed), *lock);
                } else {
                    let mut lock = rwlock.write().await.unwrap();
                    //citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    log::trace!(target: "citadel", "****Server obtained write lock {} w/val {:?}", idx, &*lock);
                    do_read = true;
                    *lock = idx;
                    server_ref.store(*lock, Ordering::Relaxed);
                }
            }

            client_done_rx.await.unwrap();
            server_done_tx.send(()).unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let rwlock = &client_stream.rwlock::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing rwlock on client");
            init_rx.await.unwrap();
            init2_tx.send(()).unwrap();

            let mut do_read = false;

            for idx in 0..COUNT {
                if do_read {
                    let lock = rwlock.read().await.unwrap();
                    //citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    log::trace!(target: "citadel", "****Server obtained read lock {} w/val {:?}", idx, &*lock);
                    do_read = false;
                    assert_eq!(client_ref.load(Ordering::Relaxed), *lock);
                } else {
                    let mut lock = rwlock.write().await.unwrap();
                    //citadel_io::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    log::trace!(target: "citadel", "****Server obtained write lock {} w/val {:?}", idx, &*lock);
                    do_read = true;
                    *lock = idx;
                    client_ref.store(*lock, Ordering::Relaxed);
                }
            }

            client_done_tx.send(()).unwrap();
            server_done_rx.await.unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        r0.unwrap();
        r1.unwrap();
    }
}
