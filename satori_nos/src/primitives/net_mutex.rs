use tokio::sync::{Mutex, OwnedMutexGuard};
use crate::primitives::accessor::{NetworkTransferable, OwnedGuard};
use futures::task::{Poll, Context};
use std::ops::{Deref, DerefMut};
use futures::Future;
use tokio::macros::support::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use std::marker::PhantomData;

pub struct NetMutex<T: NetworkTransferable> {
    lock: Arc<Mutex<T>>,
    // the networking protocol will notify this when the network has locked the status
    access_notifier: parking_lot::Mutex<Receiver<()>>,
    // used when writes occur to the inner value. TODO: send should happen regardless to tell server to release lock. Create enum, send that through instead
    updater_tx: Sender<OwnedGuard<T>>
    // create tx/rx to networking stack
}

impl<T: NetworkTransferable> NetMutex<T> {
    /// Creates a thread-safe and network-safe mutex wrapped around a network-consistent shared state variable
    pub fn new(inner: T, access_notifier: Receiver<()>, updater_tx: Sender<OwnedGuard<T>>) -> Self {
        Self { lock: Arc::new(Mutex::new(inner)), access_notifier: parking_lot::Mutex::new(access_notifier), updater_tx }
    }

    pub async fn access(&self) -> Option<AccessGuard<'_, T>> {
        // ensure only one attempt to access at a time
        let lock = self.lock.clone().lock_owned().await;
        // we need to wait for the network now, and modify the value if necessary
        self.await?;

        // this means the network is permitting access. We can now access the variable
        let guard = AccessGuard {
            lock: Some(lock),
            notifier: self.updater_tx.clone(),
            mutated: false,
            _pd: Default::default()
        };

        Some(guard)
    }

    pub async fn update_value(&self, t: T) {
        *self.lock.lock().await = t;
    }
}

impl<T: NetworkTransferable> Future for &'_ NetMutex<T> {
    type Output = Option<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.access_notifier.lock().poll_recv(cx)
    }
}

pub struct AccessGuard<'a, T: NetworkTransferable> {
    mutated: bool,
    lock: Option<OwnedMutexGuard<T>>,
    notifier: Sender<OwnedGuard<T>>,
    // to prevent sending between threads as well as being forced a lifetime
    _pd: PhantomData<*mut &'a mut T>
}



impl<T: NetworkTransferable> Deref for AccessGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.lock.as_ref().unwrap().deref()
    }
}

impl<T: NetworkTransferable> DerefMut for AccessGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.mutated = true;
        self.lock.as_mut().unwrap().deref_mut()
    }
}


impl<T: NetworkTransferable> Drop for AccessGuard<'_, T> {
    fn drop(&mut self) {
        if self.mutated {
            // we need to alert the networking stack. The mutex will be held until the networking stack drops it,
            // at which point, anybody trying to access the variable again locally will be able to lock it againm
            // BUT, because of the future await, won't be able to get R/W access again
            if let Err(err) = self.notifier.try_send(OwnedGuard::Mutex(self.lock.take().unwrap())) {
                log::error!("AccessGuard send error: {:?}", err.to_string());
            }
        }
    }
}