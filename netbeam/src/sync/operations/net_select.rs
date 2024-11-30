/*!
 * # Network Select Operation
 *
 * Implements a network-aware select operation that races futures across two network
 * endpoints. Similar to `futures::select`, but operates over a network connection
 * with built-in conflict resolution.
 *
 * ## Features
 * - Races futures between two network endpoints
 * - First endpoint to complete wins
 * - Built-in conflict resolution
 * - Type-safe with generic result type
 * - Network-aware relative node types
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::operations::net_select::NetSelect;
 * use netbeam::sync::RelativeNodeType;
 * use netbeam::sync::subscription::Subscribable;
 * use anyhow::Result;
 *
 * async fn example<S: Subscribable + 'static>(connection: &S) -> Result<()> {
 *     // Create a select operation
 *     let select = NetSelect::new(
 *         connection,
 *         RelativeNodeType::Initiator,
 *         async { Ok::<_, anyhow::Error>(42) }
 *     );
 *
 *     // Wait for first endpoint to complete
 *     let result = select.await?;
 *     Ok(())
 * }
 * ```
 *
 * ## Important Notes
 * - First endpoint to complete wins
 * - Includes conflict resolution
 * - Uses multiplexed connections
 *
 * ## Related Components
 * - `net_select_ok.rs`: Select operation for fallible futures
 * - `net_join.rs`: Join operation for synchronization
 */

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
