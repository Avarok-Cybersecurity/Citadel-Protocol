use crate::primitives::accessor::{NetworkTransferable, OwnedGuard};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use futures::Future;
use futures::task::Context;
use tokio::macros::support::{Pin, Poll};

pub struct NetRwLock<T: NetworkTransferable> {
    // When the ReadAccessorGuard drop, it only sends a signal to the networking protocol if
    // local_read_locks_open drops to 0. This allows multiple local read to occur without consent
    // of the network
    local_read_locks_open: Arc<AtomicUsize>,
    lock: Arc<RwLock<T>>,
    // multiple local threads may attempt to get R
    access_notifier: parking_lot::Mutex<Receiver<()>>,
    updater_tx: Sender<OwnedGuard<T>>
}

impl<T: NetworkTransferable> NetRwLock<T> {
    pub fn new(inner: T, access_notifier: Receiver<()>, updater_tx: Sender<OwnedGuard<T>>) -> Self {
        Self {
            local_read_locks_open: Arc::new(AtomicUsize::new(0)),
            lock: Arc::new(RwLock::new(inner)),
            access_notifier: parking_lot::Mutex::new(access_notifier),
            updater_tx
        }
    }

    pub async fn read(&self) -> Option<RwLockReadAccessGuard<'_, T>> {
        let lock = self.lock.read().await;

        // If there have been no reads, wait for the network to allow a read
        if self.local_read_locks_open.load(Ordering::SeqCst) == 0 {
            self.await?;
        }

        let guard = RwLockReadAccessGuard {
            lock: Some(OwnedRwLockGuard::read(self.lock.clone(), lock)),
            reads_open: self.local_read_locks_open.clone(),
            notifier: self.updater_tx.clone(),
            _pd: Default::default()
        };

        self.increment_read();

        Some(guard)
    }

    pub async fn write(&self) -> Option<RwLockWriteAccessGuard<'_, T>> {
        let lock = self.lock.write().await;

        self.await?;

        let guard = RwLockWriteAccessGuard {
            lock: Some(OwnedRwLockGuard::write(self.lock.clone(), lock)),
            notifier: self.updater_tx.clone(),
            _pd: Default::default(),
            mutated: false
        };

        Some(guard)
    }

    pub async fn update_value(&self, t: T) {
        *self.lock.write().await = t;
    }

    #[allow(unused_results)]
    fn increment_read(&self) {
        self.local_read_locks_open.fetch_add(1, Ordering::SeqCst);
    }
}

impl<T: NetworkTransferable> Future for &'_ NetRwLock<T> {
    type Output = Option<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.access_notifier.lock().poll_recv(cx)
    }
}

pub enum OwnedRwLockGuard<T: NetworkTransferable> {
    Read(Arc<RwLock<T>>, RwLockReadGuard<'static, T>),
    Write(Arc<RwLock<T>>, RwLockWriteGuard<'static, T>)
}

impl<T: NetworkTransferable> OwnedRwLockGuard<T> {
    pub fn write(ptr: Arc<RwLock<T>>, guard: RwLockWriteGuard<T>) -> Self {
        // we can safely upgrade to the static lifetime because the ptr stays alive as long as
        // the wrapper does
        let lock = unsafe { std::mem::transmute(guard) };
        OwnedRwLockGuard::Write(ptr, lock)
    }

    pub fn read(ptr: Arc<RwLock<T>>, guard: RwLockReadGuard<T>) -> Self {
        // we can safely upgrade to the static lifetime because the ptr stays alive as long as
        // the wrapper does
        let lock = unsafe { std::mem::transmute(guard) };
        OwnedRwLockGuard::Read(ptr, lock)
    }
}

pub struct RwLockReadAccessGuard<'a, T: NetworkTransferable> {
    lock: Option<OwnedRwLockGuard<T>>,
    notifier: Sender<OwnedGuard<T>>,
    reads_open: Arc<AtomicUsize>,
    // to prevent sending between threads as well as being forced a lifetime
    _pd: PhantomData<*const &'a T>
}

impl<T: NetworkTransferable> Deref for RwLockReadAccessGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self.lock.as_ref().unwrap() {
            OwnedRwLockGuard::Read(_, guard) => guard.deref(),
            _ => unreachable!("Write guard does not apply to RwLockReadAccessGuard")
        }
    }
}

impl<T: NetworkTransferable> Drop for RwLockReadAccessGuard<'_, T> {
    fn drop(&mut self) {
        if self.reads_open.fetch_sub(1, Ordering::SeqCst) == 1 {
            // the last read dropped. Tell the network we're done reading
            if let Err(err) = self.notifier.try_send(OwnedGuard::RwLock(self.lock.take().unwrap())) {
                log::error!("RwLockReadAccessGuard send error: {:?}", err.to_string());
            }
        }
    }
}

pub struct RwLockWriteAccessGuard<'a, T: NetworkTransferable> {
    lock: Option<OwnedRwLockGuard<T>>,
    notifier: Sender<OwnedGuard<T>>,
    mutated: bool,
    // to prevent sending between threads as well as being forced a lifetime
    _pd: PhantomData<*mut &'a mut T>
}

impl<T: NetworkTransferable> Deref for RwLockWriteAccessGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self.lock.as_ref().unwrap() {
            OwnedRwLockGuard::Write(_, guard) => guard.deref(),
            _ => unreachable!("Read guard does not apply to RwLockWriteAccessGuard")
        }
    }
}

impl<T: NetworkTransferable> DerefMut for RwLockWriteAccessGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.mutated = true;
        match self.lock.as_mut().unwrap() {
            OwnedRwLockGuard::Write(_, guard) => guard.deref_mut(),
            _ => unreachable!("Read guard does not apply to RwLockWriteAccessGuard")
        }
    }
}

impl<T: NetworkTransferable> Drop for RwLockWriteAccessGuard<'_, T> {
    fn drop(&mut self) {
        if self.mutated {
            if let Err(err) = self.notifier.try_send(OwnedGuard::RwLock(self.lock.take().unwrap())) {
                log::error!("RwLockWriteAccessGuard send error: {:?}", err.to_string());
            }
        }
    }
}