use std::pin::Pin;
use std::future::Future;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use std::task::{Context, Poll};
use crate::sync::net_try_join::NetTryJoin;
use crate::sync::network_endpoint::NetworkEndpoint;
use crate::sync::RelativeNodeType;
use futures::TryFutureExt;

/// Two endpoints produce Ok(T). Returns when both endpoints produce T, or, when the first error occurs
pub struct NetJoin<'a, T> {
    future: Pin<Box<dyn Future<Output=Result<NetJoinResult<T>, anyhow::Error>> + Send + 'a>>,
}

impl<'a, T: Send + 'a> NetJoin<'a, T> {
    pub fn new<Conn: ReliableOrderedConnectionToTarget + 'static, F: Send + 'a>(conn: &'a NetworkEndpoint<Conn>, local_node_type: RelativeNodeType, future: F) -> Self
        where F: Future<Output=T> {
        // we can safely unwrap since we are wrapping the result is an Ok()
        Self { future: Box::pin(NetTryJoin::<T, ()>::new(conn, local_node_type, async move { Ok(future.await) }).map_ok(|r| NetJoinResult { value: r.value.map(|r| r.unwrap()) })) }
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