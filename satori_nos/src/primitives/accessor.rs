use crate::primitives::net_mutex::{NetMutex, AccessGuard};
use std::ops::{Deref, DerefMut};
use crate::primitives::net_rwlock::{NetRwLock, RwLockWriteAccessGuard, RwLockReadAccessGuard, OwnedRwLockGuard};
use tokio::sync::OwnedMutexGuard;
use crate::primitives::error::Error;
use serde::{Serialize, Deserialize};

pub enum Accessor<T: NetworkTransferable> {
    Mutex(NetMutex<T>),
    RwLock(NetRwLock<T>)
}

pub enum WriteAccessGuard<'a, T: NetworkTransferable> {
    Mutex(AccessGuard<'a, T>),
    RwLock(RwLockWriteAccessGuard<'a, T>)
}

pub enum ReadAccessGuard<'a, T: NetworkTransferable> {
    Mutex(AccessGuard<'a, T>),
    RwLock(RwLockReadAccessGuard<'a, T>)
}

impl<T: NetworkTransferable> Accessor<T> {
    pub async fn write(&self) -> Option<WriteAccessGuard<'_, T>> {
        match self {
            Accessor::Mutex(val) => {
                val.access().await.map(WriteAccessGuard::Mutex)
            }

            Accessor::RwLock(val) => {
                val.write().await.map(WriteAccessGuard::RwLock)
            }
        }
    }

    /// Both Mutexes and RwLocks can be accessed through the [ReadAccessGuard]. When this is used,
    /// only Deref is implemented
    pub async fn read(&self) -> Option<ReadAccessGuard<'_, T>> {
        match self {
            Accessor::Mutex(val) => {
                val.access().await.map(ReadAccessGuard::Mutex)
            }

            Accessor::RwLock(val) => {
                val.read().await.map(ReadAccessGuard::RwLock)
            }
        }
    }
}

pub trait NetworkTransferable where for<'a> Self: Serialize + Deserialize<'a> + Sized + Default + Send + Sync + 'static {
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        bincode2::serialize(self)
            .map_err(|err| Error::Default(err.to_string()))
    }

    fn deserialize_from(input: &[u8]) -> Option<Self> {
        bincode2::deserialize(input).ok()
    }

    /// When the application initializes, the default will be used to set a shared state
    fn serialize_default() -> Result<Vec<u8>, Error> {
        <Self as NetworkTransferable>::serialize(&Self::default())
    }
}

impl<T> NetworkTransferable for T
    where for<'a> T: Serialize + Deserialize<'a> + Sized + Default + Send + Sync + 'static{}

impl<T: NetworkTransferable> Deref for ReadAccessGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            ReadAccessGuard::Mutex(guard) => guard.deref(),
            ReadAccessGuard::RwLock(guard) => guard.deref()
        }
    }
}

impl<T: NetworkTransferable> Deref for WriteAccessGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            WriteAccessGuard::Mutex(guard) => guard.deref(),
            WriteAccessGuard::RwLock(guard) => guard.deref()
        }
    }
}

impl<T: NetworkTransferable> DerefMut for WriteAccessGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            WriteAccessGuard::Mutex(guard) => guard.deref_mut(),
            WriteAccessGuard::RwLock(guard) => guard.deref_mut()
        }
    }
}

#[allow(variant_size_differences)]
pub enum OwnedGuard<T: NetworkTransferable> {
    Mutex(OwnedMutexGuard<T>),
    RwLock(OwnedRwLockGuard<T>)
}