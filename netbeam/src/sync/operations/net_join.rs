use std::pin::Pin;
use std::future::Future;
use crate::reliable_conn::ReliableOrderedStreamToTarget;
use std::task::{Context, Poll};
use crate::sync::operations::net_try_join::NetTryJoin;
use crate::sync::RelativeNodeType;
use futures::{TryFutureExt, FutureExt};
use crate::multiplex::MultiplexedConnKey;
use crate::sync::subscription::Subscribable;

/// Two endpoints produce Ok(T). Returns when both endpoints produce T, or, when the first error occurs
pub struct NetJoin<'a, T> {
    future: Pin<Box<dyn Future<Output=Result<NetJoinResult<T>, anyhow::Error>> + Send + 'a>>,
}

impl<'a, T: Send + 'a> NetJoin<'a, T> {
    pub fn new<S: Subscribable<ID=K, UnderlyingConn=Conn>, K: MultiplexedConnKey + 'a, Conn: ReliableOrderedStreamToTarget + 'static, F: Send + 'a>(conn: &'a S, local_node_type: RelativeNodeType, future: F) -> Self
        where F: Future<Output=T> {
        // we can safely unwrap since we are wrapping the result in an Ok()
        Self { future: Box::pin(NetTryJoin::<T, ()>::new(conn, local_node_type, future.map(Ok)).map_ok(|r| NetJoinResult { value: r.value.map(|r| r.unwrap()) })) }
    }
}

impl<T> Future for NetJoin<'_, T> {
    type Output = Result<NetJoinResult<T>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

pub struct NetJoinResult<T> {
    pub value: Option<T>
}