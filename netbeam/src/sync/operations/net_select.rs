use crate::multiplex::MultiplexedConnKey;
use crate::reliable_conn::ReliableOrderedStreamToTarget;
use crate::sync::operations::net_select_ok::NetSelectOk;
use crate::sync::subscription::Subscribable;
use crate::sync::RelativeNodeType;
use futures::{FutureExt, TryFutureExt};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Two endpoints race to produce R. The first endpoint to produce R wins. Includes conflict-resolution synchronization
pub struct NetSelect<'a, R> {
    future: Pin<Box<dyn Future<Output = Result<NetSelectResult<R>, anyhow::Error>> + Send + 'a>>,
}

impl<'a, R: Send + 'a> NetSelect<'a, R> {
    pub fn new<
        S: Subscribable<ID = K, UnderlyingConn = Conn>,
        K: MultiplexedConnKey + 'a,
        Conn: ReliableOrderedStreamToTarget + 'static,
        F: Future<Output = R> + Send + 'a,
    >(
        conn: &'a S,
        local_node_type: RelativeNodeType,
        future: F,
    ) -> Self {
        Self {
            future: Box::pin(
                NetSelectOk::new(conn, local_node_type, future.map(Ok))
                    .map_ok(|r| NetSelectResult { value: r.result }),
            ),
        }
    }
}

impl<R> Future for NetSelect<'_, R> {
    type Output = Result<NetSelectResult<R>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

pub struct NetSelectResult<R> {
    pub value: Option<R>,
}
