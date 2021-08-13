use std::pin::Pin;
use std::future::Future;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::sync::net_select_ok::NetSelectOk;
use futures::TryFutureExt;
use std::task::{Context, Poll};
use crate::sync::network_endpoint::NetworkEndpoint;
use crate::sync::RelativeNodeType;

/// Two endpoints race to produce R. The first endpoint to produce R wins. Includes conflict-resolution synchronization
pub struct NetSelect<'a, R> {
    future: Pin<Box<dyn Future<Output=Result<NetSelectResult<R>, anyhow::Error>> + Send + 'a>>,
}

impl<'a, R: Send + 'a> NetSelect<'a, R> {
    pub fn new<Conn: ReliableOrderedConnectionToTarget + 'static, F: Send + 'a>(conn: &'a NetworkEndpoint<Conn>, local_node_type: RelativeNodeType, future: F) -> Self
        where F: Future<Output=R> {
        Self { future: Box::pin(NetSelectOk::new(conn, local_node_type, async move { Ok(future.await) }).map_ok(|r| NetSelectResult { value: r.result })) }
    }
}

impl<R> Future for NetSelect<'_, R> {
    type Output = Result<NetSelectResult<R>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

pub struct NetSelectResult<R> {
    pub value: Option<R>
}