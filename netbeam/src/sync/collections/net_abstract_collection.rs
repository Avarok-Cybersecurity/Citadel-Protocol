#![allow(dead_code)]
use std::sync::Arc;
use crate::sync::primitives::NetObject;
use crate::sync::subscription::Subscribable;
use crate::sync::collections::net_abstract_collection::loader::NetVecLoader;
use crate::sync::primitives::net_rwlock::read::NetRwLockReadGuard;
use crate::sync::primitives::net_rwlock::write::NetRwLockWriteGuard;
use tokio::sync::RwLock;
use std::sync::atomic::AtomicU64;
use crate::sync::channel::bi_channel::Channel;
use crate::sync::collections::AbstractCollection;
use std::marker::PhantomData;
use crate::sync::RelativeNodeType;
use crate::sync::primitives::net_mutex::NetMutex;
use crate::sync::primitives::net_rwlock::NetRwLock;

type OwnedGlobalModifyElementLock<T, S> = Arc<NetRwLockReadGuard<T, S>>;
type OwnedGlobalAlterVecLock<T, S> = NetRwLockWriteGuard<T, S>;


pub struct NetAbstractCollection<T: NetObject, K, C: AbstractCollection<K, NetRwLock<T, S>>, S: Subscribable + 'static> {
    /// Adding/removing elements to the vector requires a write lock to global
    ///
    /// The element is a version number. Version number increments each time an insert/delete to the vec is performed
    global: NetMutex<u64, S>,
    /// Once the global lock is obtained, the local lock can then be accessed.
    inner: Arc<RwLock<C>>,
    local_version: Arc<AtomicU64>,
    update_channel: Channel<T, S>,
    _pd: PhantomData<K>
}

enum NetVecAlteration<K, T> {
    Insert(K, T),
    Remove(K),
    Clear
}

impl<T: NetObject, K, C: AbstractCollection<K, NetRwLock<T, S>>, S: Subscribable + 'static> NetAbstractCollection<T, K, C, S> {
    pub fn new(conn: &S) -> NetVecLoader<'_, T, K, C, S> {
        NetVecLoader {
            inner: Box::pin(async move {
                let update_channel = async move {
                    Channel::<T, S>::new(conn).await
                };

                let global_mutex = async move {
                    NetMutex::<u64, S>::new(conn, if conn.node_type() == RelativeNodeType::Initiator { Some(0) } else { None }).await
                };

                // TODO: make this operation concurrent ... will require adding unique ids ontop of symmetric IDs though
                let update_channel = update_channel.await?;
                let global = global_mutex.await?;

                Ok(Self { global, inner: Arc::new(RwLock::new(C::default())), local_version: Arc::new(AtomicU64::new(0)), update_channel, _pd: Default::default() })
            })
        }
    }
}

mod loader {
    use crate::sync::primitives::NetObject;
    use crate::sync::subscription::Subscribable;
    use std::pin::Pin;
    use futures::Future;
    use crate::sync::collections::net_abstract_collection::NetAbstractCollection;
    use std::task::{Context, Poll};
    use crate::sync::collections::AbstractCollection;
    use crate::sync::primitives::net_rwlock::NetRwLock;

    pub struct NetVecLoader<'a, T: NetObject, K, C: AbstractCollection<K, NetRwLock<T, S>>, S: Subscribable + 'static> {
        pub(crate) inner: Pin<Box<dyn Future<Output=Result<NetAbstractCollection<T, K, C, S>, anyhow::Error>> + Send + 'a>>
    }

    impl<T: NetObject, K, C: AbstractCollection<K, NetRwLock<T, S>>, S: Subscribable + 'static> Future for NetVecLoader<'_, T, K, C, S> {
        type Output = Result<NetAbstractCollection<T, K, C, S>, anyhow::Error>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.as_mut().poll(cx)
        }
    }
}

/*
mod locks {
    use crate::sync::primitives::NetObject;
    use crate::sync::subscription::Subscribable;

    pub(crate) struct OwnedVecAlterLock<T: NetObject, S: Subscribable + 'static> {

    }
}*/