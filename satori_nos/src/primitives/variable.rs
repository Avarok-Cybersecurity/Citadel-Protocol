use crate::primitives::accessor::{NetworkTransferable, Accessor, OwnedGuard};
use std::sync::Arc;
use crate::primitives::net_mutex::NetMutex;
use crate::primitives::net_rwlock::NetRwLock;
use tokio::sync::mpsc::{Sender, Receiver};
use std::ops::Deref;
use std::any::Any;
use std::marker::PhantomData;

// Each [NetworkVariable] gets stored inside an application hashmap
#[derive(Clone)]
pub struct NetworkVariableInner {
    inner: Arc<dyn Any + Send + Sync + 'static>
}

#[derive(Copy, Clone)]
pub enum VariableType {
    MutualExclusion,
    ReadWriteLock
}

impl NetworkVariableInner {
    pub fn new<T: NetworkTransferable>(value: T, var_type: VariableType, notifier_rx: Receiver<()>, updater_tx: Sender<OwnedGuard<T>>) -> Self {
        match var_type {
            VariableType::MutualExclusion => Self { inner: Arc::new(Accessor::Mutex(NetMutex::new(value, notifier_rx, updater_tx))) },
            VariableType::ReadWriteLock => Self { inner: Arc::new(Accessor::RwLock(NetRwLock::new(value, notifier_rx, updater_tx))) }
        }
    }

    fn downcast_accessor<T: NetworkTransferable>(&self) -> &Accessor<T> {
        self.inner.downcast_ref::<Accessor<T>>().unwrap()
    }

    pub(crate) async fn update_value<T: NetworkTransferable>(&self, t: Vec<u8>) -> Option<()> {
        let t = T::deserialize_from(t)?;
        match self.downcast_accessor() {
            Accessor::Mutex(val) => {
                val.update_value(t).await
            }

            Accessor::RwLock(val) => {
                val.update_value(t).await
            }
        }

        Some(())
    }
}

#[derive(Clone)]
pub struct NetworkVariable<T: NetworkTransferable> {
    ptr: NetworkVariableInner,
    _pd: PhantomData<T>
}

impl<T: NetworkTransferable> NetworkVariable<T> {
    pub fn new(ptr: NetworkVariableInner) -> Self {
        Self { ptr, _pd: Default::default() }
    }
}

impl<T: NetworkTransferable> Deref for NetworkVariable<T> {
    type Target = Accessor<T>;

    fn deref(&self) -> &Self::Target {
        self.ptr.inner.downcast_ref().unwrap()
    }
}