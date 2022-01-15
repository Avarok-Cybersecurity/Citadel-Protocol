#![allow(dead_code)]

use std::pin::Pin;
use std::future::Future;
use std::task::{Context, Poll};

pub type StaticSyncFuture<F> = SyncFuture<'static, F>;

pub struct SyncFuture<'a, F> {
    inner: sync_wrapper::SyncWrapper<Pin<Box<dyn Future<Output=F> + Send + 'a>>>
}

pub trait SyncFutureExt<'a>: Future + Send + Sized + 'a {
    fn syncable(self) -> SyncFuture<'a, <Self as Future>::Output> {
        SyncFuture::new(self)
    }
}

impl<'a, F> SyncFuture<'a, F> {
    /// Creates a new [`SyncFuture`], rendering the future Send and Sync
    pub fn new(fut: impl Future<Output=F> + Send + 'a) -> Self {
        Self { inner: sync_wrapper::SyncWrapper::new(Box::pin(fut)) }
    }
}

impl<F> Future for SyncFuture<'_, F> {
    type Output = F;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.get_mut().as_mut().poll(cx)
    }
}