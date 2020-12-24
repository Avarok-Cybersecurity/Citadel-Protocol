use crate::dapp::primitives::accessor::{NetworkTransferable, Accessor, OwnedGuard};
use std::sync::Arc;
use crate::dapp::primitives::net_mutex::NetMutex;
use crate::dapp::primitives::net_rwlock::NetRwLock;
use tokio::sync::mpsc::{Sender, Receiver};
use std::ops::Deref;
use hyxe_user::re_imports::export::PhantomData;
use std::any::Any;

// Each [NetworkVariable] gets stored inside an application hashmap
#[derive(Clone)]
pub struct NetworkVariableInner {
    inner: Arc<dyn Any + Send + Sync + 'static>
}

pub enum VariableType {
    MutualExclusion,
    ReadWriteLock
}

impl NetworkVariableInner {
    pub fn new<T: NetworkTransferable + 'static>(value: T, var_type: VariableType, notifier_rx: Receiver<()>, updater_tx: Sender<OwnedGuard<T>>) -> Self {
        match var_type {
            VariableType::MutualExclusion => Self { inner: Arc::new(Accessor::Mutex(NetMutex::new(value, notifier_rx, updater_tx))) },
            VariableType::ReadWriteLock => Self { inner: Arc::new(Accessor::RwLock(NetRwLock::new(value, notifier_rx, updater_tx))) }
        }
    }
}

#[derive(Clone)]
pub struct NetworkVariable<T: NetworkTransferable + 'static> {
    ptr: NetworkVariableInner,
    _pd: PhantomData<T>
}

impl<T: NetworkTransferable + 'static> NetworkVariable<T> {
    pub fn new(ptr: NetworkVariableInner) -> Self {
        Self { ptr, _pd: Default::default() }
    }
}

impl<T: NetworkTransferable + 'static> Deref for NetworkVariable<T> {
    type Target = Accessor<T>;

    fn deref(&self) -> &Self::Target {
        self.ptr.inner.downcast_ref().unwrap()
    }
}