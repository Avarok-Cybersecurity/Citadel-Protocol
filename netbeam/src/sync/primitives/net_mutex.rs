/*!
 * # Network Mutex
 *
 * A distributed mutex implementation that provides synchronized access to shared
 * state across network endpoints. Similar to std::sync::Mutex, but operates over
 * a network connection.
 *
 * ## Features
 * - Distributed mutual exclusion
 * - Network-aware locking mechanism
 * - Automatic lock release on drop
 * - State synchronization between nodes
 * - Deadlock prevention with timeouts
 * - Support for passive background handlers
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::primitives::net_mutex::NetMutex;
 * use netbeam::sync::subscription::Subscribable;
 * use anyhow::Result;
 *
 * async fn example<S: Subscribable + 'static>(connection: &S) -> Result<()> {
 *     // Create a network-aware mutex
 *     let mutex = NetMutex::create(connection, Some(0)).await?;
 *
 *     // Acquire the lock
 *     let mut guard = mutex.lock().await?;
 *
 *     // Modify the protected data
 *     *guard = 42;
 *
 *     Ok(())
 * }
 * ```
 *
 * ## Important Notes
 * - Lock acquisition is asynchronous
 * - State is synchronized on lock release
 * - Implements deadlock prevention
 * - Uses multiplexed connections
 * - Background handlers manage state
 *
 * ## Related Components
 * - `net_rwlock.rs`: Network-aware read-write lock
 * - `subscription.rs`: Subscription system for network events
 */

use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::ScopedFutureResult;
use citadel_io::tokio::sync::mpsc::{Receiver, Sender};
use citadel_io::tokio::sync::{Mutex, OwnedMutexGuard};
use futures::Future;
use serde::{Deserialize, Serialize};

use crate::reliable_conn::ReliableOrderedStreamToTargetExt;
use crate::sync::primitives::NetObject;
use crate::sync::subscription::Subscribable;
use crate::sync::subscription::SubscriptionBiStream;
use crate::sync::RelativeNodeType;
use crate::time_tracker::TimeTracker;

pub(crate) type InnerChannel<S> = <S as Subscribable>::SubscriptionType;

type InnerState<T> = (T, Sender<()>);
type OwnedLocalLock<T> = OwnedMutexGuard<InnerState<T>>;

pub struct NetMutex<T: NetObject, S: Subscribable + 'static> {
    app: Arc<InnerChannel<S>>,
    // contains the background_to_active_rx
    shared_state: Arc<Mutex<InnerState<T>>>,
    stop_tx: Option<citadel_io::tokio::sync::oneshot::Sender<()>>,
    bg_stop_signaller: Sender<()>,
}

struct LocalLockHolder<T>(Option<OwnedLocalLock<T>>, bool);

impl<T> Deref for LocalLockHolder<T> {
    type Target = OwnedLocalLock<T>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<T> DerefMut for LocalLockHolder<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

impl<T> Drop for LocalLockHolder<T> {
    fn drop(&mut self) {
        // if this is a lock holder from the BG, we aren't interested in sending an alert
        if !self.1 {
            let this = self.0.take().unwrap();
            let sender = this.1.clone();
            std::mem::drop(this); // free the lock
            if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = sender.send(()).await; // alert the bg
                });
            }
        }
    }
}

impl<S: Subscribable + 'static, T: NetObject> NetMutex<T, S> {
    async fn new_internal(conn: InnerChannel<S>, t: T) -> Result<Self, anyhow::Error> {
        // create a channel to listen here for incoming messages and alter the local state as needed
        let (stop_tx, stop_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (active_to_bg_tx, active_to_bg_rx) = citadel_io::tokio::sync::mpsc::channel::<()>(1);

        let this = Self {
            app: Arc::new(conn),
            shared_state: Arc::new(Mutex::new((t, active_to_bg_tx.clone()))),
            stop_tx: Some(stop_tx),
            bg_stop_signaller: active_to_bg_tx,
        };

        let shared_state = this.shared_state.clone();
        let channel = this.app.clone();

        citadel_io::tokio::task::spawn(async move {
            if let Err(err) =
                passive_background_handler::<S, T>(channel, shared_state, stop_rx, active_to_bg_rx)
                    .await
            {
                log::warn!(target: "citadel", "[NetMutex Passive Background Handler] Err: {:?}", err.to_string());
            }

            log::trace!(target: "citadel", "[NetMutex] Passive background handler ending")
        });

        Ok(this)
    }

    pub fn create<'a>(app: &'a S, value: Option<T>) -> NetMutexLoader<'a, T, S>
    where
        T: 'a,
    {
        NetMutexLoader::<T, S> {
            future: Box::pin(sync_establish_init(app, value, Self::new_internal)),
        }
    }

    /// Returns a future which resolves once the lock can be established with the network
    pub fn lock(&self) -> NetMutexGuardAcquirer<'_, T, S> {
        NetMutexGuardAcquirer::new(self)
    }

    fn node_type(&self) -> RelativeNodeType {
        self.app.node_type()
    }
}

impl<T: NetObject, S: Subscribable + 'static> Drop for NetMutex<T, S> {
    fn drop(&mut self) {
        let conn = self.app.clone();
        let stop_tx = self.stop_tx.take().unwrap();
        // stop the background task
        let _ = stop_tx.send(());

        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            // Delay the Halt packet to allow the peer time to finish naturally.
            // This prevents race conditions where dropping the mutex immediately
            // sends Halt before the peer has completed its operations (similar
            // to TCP's TIME_WAIT state for graceful connection closure).
            rt.spawn(async move {
                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let _ = conn.send_serialized(UpdatePacket::Halt).await;
            });
        }
    }
}

pub struct NetMutexGuard<T: NetObject + 'static, S: Subscribable + 'static> {
    conn: Arc<InnerChannel<S>>,
    guard: Option<LocalLockHolder<T>>,
}

impl<T: NetObject, S: Subscribable> Deref for NetMutexGuard<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard.as_ref().unwrap().0.as_ref().unwrap().0
    }
}

impl<T: NetObject, S: Subscribable> DerefMut for NetMutexGuard<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard.as_mut().unwrap().0.as_mut().unwrap().0
    }
}

impl<T: NetObject + 'static, S: Subscribable> Drop for NetMutexGuard<T, S> {
    fn drop(&mut self) {
        let guard = self.guard.take().unwrap();
        let app = self.conn.clone();

        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            let future = NetMutexGuardDropCode::new::<T, S>(app, guard);
            rt.spawn(future);
        } else {
            log::warn!(target: "citadel", "Failed to spawn drop code for NetMutexGuard since no runtime was found");
        }

        // if the RT is down, then we are not interested in continuing the program's synchronization
    }
}

pub struct NetMutexLoader<'a, T: NetObject, S: Subscribable + 'static> {
    future: ScopedFutureResult<'a, NetMutex<T, S>>,
}

impl<T: NetObject, S: Subscribable + 'static> Future for NetMutexLoader<'_, T, S> {
    type Output = Result<NetMutex<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[derive(Serialize, Deserialize)]
enum LoaderPacket<T> {
    Syn(Option<T>),
    SynAck,
}

pub(crate) async fn sync_establish_init<T: NetObject, S: Subscribable + 'static, Fx, F, O>(
    app: &S,
    local_value: Option<T>,
    fx: Fx,
) -> Result<O, anyhow::Error>
where
    Fx: FnOnce(InnerChannel<S>, T) -> F,
    F: Future<Output = Result<O, anyhow::Error>>,
{
    let conn = app.initiate_subscription().await?;
    conn.send_serialized(LoaderPacket::Syn(local_value.clone()))
        .await?;
    let packet = conn.recv_serialized::<LoaderPacket<T>>().await?;
    // one side gets the value, while the other already has it
    match packet {
        LoaderPacket::Syn(remote_value) => match (remote_value, local_value) {
            (Some(remote_value), None) => {
                conn.send_serialized(LoaderPacket::<T>::SynAck).await?;
                let _ = conn.recv_serialized::<LoaderPacket<T>>().await?;
                (fx)(conn.into(), remote_value).await
            }

            (None, Some(local_value)) => {
                let _ = conn.recv_serialized::<LoaderPacket<T>>().await?;
                conn.send_serialized(LoaderPacket::<T>::SynAck).await?;
                (fx)(conn.into(), local_value).await
            }

            _ => Err(anyhow::Error::msg(
                "Only one node may set the initial Mutex value",
            )),
        },

        _ => Err(anyhow::Error::msg("Invalid initial NetMutex packet")),
    }
}

/// Releases the lock with the adjacent endpoint, updating the value too for the adjacent node
struct NetMutexGuardDropCode {
    future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>>,
}

impl NetMutexGuardDropCode {
    fn new<T: NetObject + 'static, S: Subscribable + 'static>(
        conn: Arc<InnerChannel<S>>,
        guard: LocalLockHolder<T>,
    ) -> Self {
        Self {
            future: Box::pin(net_mutex_drop_code::<T, S>(conn, guard)),
        }
    }
}

impl Future for NetMutexGuardDropCode {
    type Output = Result<(), anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn net_mutex_drop_code<T: NetObject, S: Subscribable + 'static>(
    conn: Arc<InnerChannel<S>>,
    lock: LocalLockHolder<T>,
) -> Result<(), anyhow::Error> {
    log::trace!(target: "citadel", "[NetMutex] Drop code initialized for {:?}...", conn.node_type());
    conn.send_serialized(UpdatePacket::Released(
        bincode::serialize(&lock.deref().0)?,
        true,
    ))
    .await?;

    let mut adjacent_trying_to_acquire = false;

    loop {
        let packet = conn.recv_serialized::<UpdatePacket>().await?;
        log::trace!(target: "citadel", "[NetMutex] [Drop Code] RECV {:?} on {:?}", &packet, conn.node_type());
        match packet {
            UpdatePacket::ReleasedVerified => {
                log::trace!(target: "citadel", "[NetMutex] [Drop Code] Release has been verified for {:?}. Adjacent node updated; will drop local lock. Adjacent trying to acquire? {adjacent_trying_to_acquire}", conn.node_type());

                if adjacent_trying_to_acquire {
                    // Since we are holding the local lock, even if the local node tries to acquire
                    // the lock again, it will be blocked until the adjacent node releases the lock
                    // and the yield_lock subroutine finishes
                    return yield_lock::<S, T>(&conn, lock, false).await.map(|_| ());
                }

                return Ok(());
            }

            UpdatePacket::TryAcquire(_) => {
                adjacent_trying_to_acquire = true;
                // once the release is confirmed, we will yield the lock back to remote
            }

            _ => {}
        }
    }
}

/// Releases the lock with the adjacent endpoint, updating the value too for the adjacent node
pub struct NetMutexGuardAcquirer<'a, T: NetObject + 'static, S: Subscribable + 'static> {
    future: ScopedFutureResult<'a, NetMutexGuard<T, S>>,
}

#[derive(Serialize, Deserialize, Debug)]
enum UpdatePacket {
    TryAcquire(i64),
    Released(Vec<u8>, bool),
    LockAcquired,
    Halt,
    ReleasedVerified,
}

impl<'a, T: NetObject, S: Subscribable> NetMutexGuardAcquirer<'a, T, S> {
    fn new(mutex: &'a NetMutex<T, S>) -> Self {
        Self {
            future: Box::pin(net_mutex_guard_acquirer(mutex)),
        }
    }
}

impl<T: NetObject + 'static, S: Subscribable + 'static> Future for NetMutexGuardAcquirer<'_, T, S> {
    type Output = Result<NetMutexGuard<T, S>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn net_mutex_guard_acquirer<T: NetObject + 'static, S: Subscribable>(
    mutex: &NetMutex<T, S>,
) -> Result<NetMutexGuard<T, S>, anyhow::Error> {
    // first step is always to acquire the local lock. If local has a NetMutexGuard, then it will hold an owned lock until it drops, ensuring no local process can progress past this point
    // until after the lock is dropped. Further, the lock ensures the drop process is complete and that both nodes have a symmetric value
    log::trace!(target: "citadel", "Attempting to acquire lock for {:?}", mutex.node_type());
    // first, ensure background isn't already awaiting for a packet
    mutex.bg_stop_signaller.send(()).await?;
    let mut owned_local_lock =
        LocalLockHolder(Some(mutex.shared_state.clone().lock_owned().await), false);
    log::trace!(target: "citadel", "{:?} acquired local lock", mutex.node_type());

    let conn = &mutex.app;

    let local_request_time = TimeTracker::new().get_global_time_ns();
    conn.send_serialized(UpdatePacket::TryAcquire(local_request_time))
        .await
        .map_err(|err| anyhow::Error::msg(err.to_string()))?;

    loop {
        let (value, _bg_alerter) = &mut **owned_local_lock.deref_mut();

        let packet = conn.recv_serialized().await?;
        log::trace!(target: "citadel", "{:?}/active-channel || obtained packet {:?}", mutex.node_type(), &packet);

        // the adjacent side will return one of two packets. In the first case, we wait until it drops the adjacent lock, in which case,
        // we get a Released packet. The side that gets this will automatically be allowed to acquire the mutex lock
        match packet {
            UpdatePacket::Released(new_data, _) => {
                let new_data = bincode::deserialize::<T>(&new_data)?;
                *value = new_data;
                // now, send a LockAcquired packet
                conn.send_serialized(UpdatePacket::LockAcquired).await?;
                conn.send_serialized(UpdatePacket::ReleasedVerified).await?;
                return Ok(NetMutexGuard {
                    conn: mutex.app.clone(),
                    guard: Some(owned_local_lock),
                });
            }

            UpdatePacket::LockAcquired => {
                // in this case, the other side deemed that it should have the lock. We need to wait
            }

            UpdatePacket::TryAcquire(remote_request_time) => {
                log::trace!(target: "citadel", "BOTH trying to acquire!");
                // in this case both are trying to acquire, give to the node that requested first, OR, if it was given preference in case of the next conflict
                let local_wins = if remote_request_time == local_request_time {
                    mutex.node_type() == RelativeNodeType::Initiator
                } else {
                    remote_request_time > local_request_time
                };

                log::trace!(target: "citadel", "Local {:?} wins?: {} (remote time ({remote_request_time}) < local time ({local_request_time}))", mutex.node_type(), local_wins);

                return if local_wins {
                    // we requested before the remote node; tell the remote node we took the value
                    conn.send_serialized(UpdatePacket::LockAcquired).await?;
                    Ok(NetMutexGuard {
                        conn: mutex.app.clone(),
                        guard: Some(owned_local_lock),
                    })
                } else {
                    // remote gets the lock. We send the local value first. Then, we must continue looping
                    // yield the lock
                    owned_local_lock = yield_lock::<S, T>(conn, owned_local_lock, false).await?;
                    log::trace!(target: "citadel", "{:?} finished yielding lock to remote, will now return the mutex to local", mutex.node_type());
                    Ok(NetMutexGuard {
                        conn: mutex.app.clone(),
                        guard: Some(owned_local_lock),
                    })
                };
            }

            UpdatePacket::Halt => {
                // the adjacent node dropped their NetMutex. The program is done
                return Err(anyhow::Error::msg("The adjacent node dropped the Mutex"));
            }

            UpdatePacket::ReleasedVerified => {
                // TODO: Figure out why this got called
                log::warn!(target: "citadel", "RELEASED_VERIFIED should only be received by the yield_lock subroutine")
            }
        }
    }
}

async fn yield_lock<S: Subscribable + 'static, T: NetObject>(
    channel: &Arc<InnerChannel<S>>,
    mut lock: LocalLockHolder<T>,
    send_release: bool,
) -> Result<LocalLockHolder<T>, anyhow::Error> {
    if send_release {
        channel
            .send_serialized(UpdatePacket::Released(
                bincode::serialize(&lock.deref().0).unwrap(),
                false,
            ))
            .await?;
    }

    loop {
        let next_packet = channel.recv_serialized().await?;
        log::trace!(target: "citadel", "[YIELD LOCK] {:?} received packet: {:?}", channel.node_type(), &next_packet);
        match next_packet {
            UpdatePacket::Released(new_value, _) => {
                lock.deref_mut().0 = bincode::deserialize(&new_value)?;
                channel.send_serialized(UpdatePacket::LockAcquired).await?;
                channel
                    .send_serialized(UpdatePacket::ReleasedVerified)
                    .await?;
                return Ok(lock);
            }

            UpdatePacket::Halt => {
                // This is what happened: Local called yield_lock, yielding the lock
                // to the adjacent node. Then, we waited for the adjacent node to release
                // the lock. However, the adjacent node did not release the lock, and instead,
                // dropped the mutex without editing the final value. Thus, return the local lock
                // with the current value
                log::warn!(target: "citadel", "Received a HALT from the adjacent background thread. Assuming local value is most recent: {:?}", lock.0);
                return Ok(lock);
            }

            UpdatePacket::ReleasedVerified => {
                // Ignore this packets and continue waiting for the Released packet
                continue;
            }

            UpdatePacket::LockAcquired => {
                // Ignore this packet, we have to wait for the user to release their lock
                continue;
            }

            p => {
                log::warn!(target: "citadel", "Received invalid packet type in inner_loop! {p:?}");
                return Err(anyhow::Error::msg("Received invalid packet type"));
            }
        }
    }
}

/// - background_to_active_tx: only gets sent if the other end is listening
async fn passive_background_handler<S: Subscribable + 'static, T: NetObject>(
    channel: Arc<InnerChannel<S>>,
    shared_state: Arc<Mutex<InnerState<T>>>,
    stop_rx: citadel_io::tokio::sync::oneshot::Receiver<()>,
    mut active_to_background_rx: Receiver<()>,
) -> Result<(), anyhow::Error> {
    let background_task = async move {
        // first, check to see if the other end is listening
        loop {
            match shared_state.clone().try_lock_owned() {
                Ok(lock) => {
                    // here, any local requests will be blocked until an external packet gets received OR local signals background to stop;
                    let packet = citadel_io::tokio::select! {
                        res0 = channel.recv_serialized::<UpdatePacket>() => res0?,
                        res1 = active_to_background_rx.recv() => {
                            // in the case local tries ot make an outgoing request, we will stop listening in the background
                            res1.ok_or_else(|| anyhow::Error::msg("The active_to_background_tx died"))?;
                            continue;
                        }
                    };

                    match packet {
                        UpdatePacket::TryAcquire(_time) => {
                            // we hold the lock locally, preventing local from sending any packets outbound from the active channel since the adjacent node is actively seeking to
                            // establish a lock
                            // we set "true" to the local lock holder to imply that the drop code won't alert the background (b/c we already are in BG)
                            yield_lock::<S, T>(&channel, LocalLockHolder(Some(lock), true), true)
                                .await?;
                            // return on error
                        }

                        UpdatePacket::Released(_, true) => {
                            // In the case that the local node has dropped the mutex, and,
                            // the remote node has released the lock thereafter, this branch
                            // may execute (mostly when latency is very low, e,g., on localhost-testing
                            continue;
                        }

                        UpdatePacket::Released(_, false)
                        | UpdatePacket::ReleasedVerified
                        | UpdatePacket::LockAcquired => {
                            unreachable!("[BG] RELEASED/RELEASED_VERIFIED/LOCK_ACQUIRED should only be received in the yield_lock subroutine.");
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

#[cfg(test)]
mod tests {
    use crate::sync::test_utils::create_streams_with_addrs_and_lag;
    use citadel_io::tokio;
    use rstest::rstest;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[rstest]
    #[case(0, 1000)]
    #[case(5, 50)]
    #[case(50, 10)]
    #[citadel_io::tokio::test]
    async fn test_net_mutex(#[case] lag: usize, #[case] count: u64) {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams_with_addrs_and_lag(lag).await;

        let init_value = 1000u64;
        let final_value = 1001u64;
        let (client_done_tx, client_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

        let server_ref = Arc::new(AtomicU64::new(init_value));
        let client_ref = server_ref.clone();

        let server = citadel_io::tokio::spawn(async move {
            let mutex = &server_stream.mutex(Some(init_value)).await.unwrap();
            log::trace!(target: "citadel", "Success establishing mutex on server");
            client_done_rx.await.unwrap();
            let guard = mutex.lock().await.unwrap();
            assert_eq!(*guard, final_value);
            log::trace!(target: "citadel", "Server ASSERT_EQ valid");
            std::mem::drop(guard);

            for idx in 1..count {
                log::trace!(target: "citadel", "Server obtaining lock {idx}");
                let mut lock = mutex.lock().await.unwrap();
                log::trace!(target: "citadel", "****Server obtained lock {} w/val {:?}", idx, &*lock);
                assert_eq!(idx + init_value, *lock);

                *lock += 1;
                server_ref.store(*lock, Ordering::SeqCst);
            }

            server_done_tx.send(()).unwrap();
        });

        let client = citadel_io::tokio::spawn(async move {
            let mutex = &client_stream.mutex::<u64>(None).await.unwrap();
            log::trace!(target: "citadel", "Success establishing mutex on client");
            let mut guard = mutex.lock().await.unwrap();
            log::trace!(target: "citadel", "Client has successfully established a mutex lock");
            *guard = 1001;
            client_ref.store(*guard, Ordering::SeqCst);
            std::mem::drop(guard);
            client_done_tx.send(()).unwrap();

            for _ in 1..count {
                let val = mutex.lock().await.unwrap();
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
}
