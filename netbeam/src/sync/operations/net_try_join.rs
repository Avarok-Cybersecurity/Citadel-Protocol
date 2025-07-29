/*!
 * # Network Try-Join Operation
 *
 * Implements a network-aware try-join operation that synchronizes fallible futures
 * across two network endpoints. Similar to `futures::try_join`, but operates over
 * a network connection.
 *
 * ## Features
 * - Synchronizes fallible futures between network endpoints
 * - Returns when both endpoints complete successfully
 * - Early termination on first error
 * - Type-safe with generic value and error types
 * - State synchronization between nodes
 * - Network-aware relative node types
 *
 * ## Usage Example
 * ```rust
 * use netbeam::sync::operations::net_try_join::NetTryJoin;
 * use netbeam::sync::RelativeNodeType;
 * use netbeam::sync::subscription::Subscribable;
 * use anyhow::Result;
 *
 * async fn example<S: Subscribable>(connection: &S) -> Result<()> {
 *     // Create a try-join operation
 *     let join = NetTryJoin::new(
 *         connection,
 *         RelativeNodeType::Initiator,
 *         async { Ok::<_, anyhow::Error>(42) }
 *     );
 *
 *     // Wait for both endpoints
 *     let result = join.await?;
 *     println!("Got result: {:?}", result);
 *     Ok(())
 * }
 * ```
 *
 * ## Important Notes
 * - Both endpoints must complete successfully
 * - Handles errors with Result type
 * - State is synchronized between nodes
 * - Uses multiplexed connections
 *
 * ## Related Components
 * - `net_join.rs`: Basic join operation without error handling
 * - `net_select.rs`: Select operation for multiple futures
 */

use crate::multiplex::MultiplexedConnKey;
use crate::reliable_conn::{ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt};
use crate::sync::subscription::{Subscribable, SubscriptionBiStream};
use crate::sync::RelativeNodeType;
use crate::ScopedFutureResult;
use citadel_io::tokio::sync::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Two endpoints produce Ok(T). Returns when both endpoints produce Ok(T), or, when the first error occurs
pub struct NetTryJoin<'a, T, E> {
    future: ScopedFutureResult<'a, NetTryJoinResult<T, E>>,
}

impl<'a, T: Send + 'a, E: Send + 'a> NetTryJoin<'a, T, E> {
    pub fn new<
        S: Subscribable<ID = K, UnderlyingConn = Conn>,
        K: MultiplexedConnKey + 'a,
        Conn: ReliableOrderedStreamToTarget + 'static,
        F: Future<Output = Result<T, E>> + Send + 'a,
    >(
        conn: &'a S,
        local_node_type: RelativeNodeType,
        future: F,
    ) -> NetTryJoin<'a, T, E> {
        Self {
            future: Box::pin(resolve(conn, local_node_type, future)),
        }
    }
}

impl<T, E> Future for NetTryJoin<'_, T, E> {
    type Output = Result<NetTryJoinResult<T, E>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[derive(Debug)]
pub struct NetTryJoinResult<T, E> {
    pub value: Option<Result<T, E>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
enum State {
    Pending,
    ObtainedValidResult,
    Resolved,
    ResolvedBothFail,
    NonPreferredFinished,
    Error,
    // None if not finished, false if errored, true if success
    Pinging(Option<bool>),
}

impl State {
    /// assumes this is called by the receiving node, not the node that creates the state
    fn implies_success(&self) -> bool {
        matches!(self, Self::ObtainedValidResult | Self::Pinging(Some(true)))
    }

    fn implies_failure(&self) -> bool {
        matches!(self, Self::Error | Self::Pinging(Some(false)))
    }
}

async fn resolve<
    S: Subscribable<ID = K, UnderlyingConn = Conn>,
    K: MultiplexedConnKey,
    Conn: ReliableOrderedStreamToTarget + 'static,
    F,
    T,
    E,
>(
    conn: &S,
    local_node_type: RelativeNodeType,
    future: F,
) -> Result<NetTryJoinResult<T, E>, anyhow::Error>
where
    F: Future<Output = Result<T, E>>,
{
    let conn = &(conn.initiate_subscription().await?);
    log::trace!(target: "citadel", "NET_TRY_JOIN started conv={:?} for {:?}", conn.id(), local_node_type);
    let (stopper_tx, stopper_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();

    struct LocalState<T, E> {
        local_state: State,
        ret_value: Option<Result<T, E>>,
    }

    let local_state = LocalState {
        local_state: State::Pending,
        ret_value: None,
    };
    let local_state_ref = &Mutex::new(local_state);

    let has_preference = local_node_type == RelativeNodeType::Initiator;

    // the evaluator finishes before the "completer" if this goes successfully
    let evaluator = async move {
        let _stopper_tx = stopper_tx;

        async fn return_sequence<Conn: ReliableOrderedStreamToTarget, T, E>(
            conn: &Conn,
            new_state: State,
            mut state: MutexGuard<'_, LocalState<T, E>>,
        ) -> Result<Option<Result<T, E>>, anyhow::Error> {
            state.local_state = new_state.clone();
            conn.send_serialized(new_state.clone()).await?;
            Ok(state.ret_value.take())
        }

        loop {
            let received_remote_state = conn.recv_serialized::<State>().await?;
            //log::trace!(target: "citadel", "{:?} RECV'd {:?}", local_node_type, &received_remote_state);
            let mut lock = local_state_ref.lock().await;
            let local_state_info = lock.ret_value.as_ref().map(|r| r.is_ok());
            log::trace!(target: "citadel", "[conv={:?} Node {:?} recv {:?} || Local state: {:?}", conn.id(), local_node_type, received_remote_state, lock.local_state);
            if has_preference {
                // if local has preference, we have the permission to evaluate
                // first, check to make sure local hasn't already obtained a value
                if received_remote_state.implies_failure() || lock.local_state.implies_failure() {
                    // If ANY node fails in a TryJoin, we have a global failure
                    return return_sequence(conn, State::ResolvedBothFail, lock).await;
                }

                // at this point, neither imply failure
                if received_remote_state.implies_success() && lock.local_state.implies_success() {
                    return return_sequence(conn, State::Resolved, lock).await;
                }

                // neither imply failure, AND, neither imply success. This means we need to ping until either one of those conditions becomes true
                conn.send_serialized(State::Pinging(local_state_info))
                    .await?;
            } else {
                // if not, we cannot evaluate UNLESS we are being told that we resolved
                match received_remote_state {
                    State::Resolved => {
                        // remote is telling us we both won
                        lock.local_state = State::Resolved;
                        return Ok(lock.ret_value.take());
                    }

                    State::ResolvedBothFail => {
                        // both nodes failed
                        return Ok(lock.ret_value.take());
                    }

                    _ => {
                        // even in the case of an error, or simply an acknowledgement that the adjacent side succeeded, we need to let remote determine what to do. Just ping
                        //std::mem::drop(lock);
                        conn.send_serialized(State::Pinging(local_state_info))
                            .await?;
                    }
                }
            }
        }
    };

    // racer should never finish first
    let completer = async move {
        // both sides start this function
        let res = future.await;
        let mut local_state = local_state_ref.lock().await;

        let state = res
            .as_ref()
            .map(|_| State::ObtainedValidResult)
            .unwrap_or(State::Error);

        // we don't check the local state because the resolution would terminate this task anyways
        //log::trace!(target: "citadel", "[NetRacer] {:?} Old state: {:?} | New state: {:?}", local_node_type, &local_state.local_state, &state);

        local_state.local_state = state.clone();
        local_state.ret_value = Some(res);

        // now, send a packet to the other side
        conn.send_serialized(state).await?;
        std::mem::drop(local_state);
        //log::trace!(target: "citadel", "[NetRacer] {:?} completer done", local_node_type);

        stopper_rx.await?;
        Err(anyhow::Error::msg("Stopped before the resolver"))
    };

    citadel_io::tokio::select! {
        res0 = evaluator => {
            log::trace!(target: "citadel", "NET_TRY_JOIN ending for {:?} (conv={:?})", local_node_type, conn.id());
            let ret = res0?;
            wrap_return(ret)
        },

        res1 = completer => res1
    }
}

fn wrap_return<T, E>(value: Option<Result<T, E>>) -> Result<NetTryJoinResult<T, E>, anyhow::Error> {
    Ok(NetTryJoinResult { value })
}

#[cfg(test)]
mod tests {
    use crate::sync::network_application::NetworkApplication;
    use crate::sync::test_utils::create_streams;
    use citadel_io::tokio;
    use std::fmt::Debug;
    use std::future::Future;
    use std::time::Duration;

    #[tokio::test]
    async fn racer() {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams().await;
        const COUNT: i32 = 10;
        for idx in 0..COUNT {
            log::trace!(target: "citadel", "[Meta] ERR:ERR ({idx}/{COUNT})");
            inner(
                server_stream.clone(),
                client_stream.clone(),
                dummy_function_err(),
                dummy_function_err(),
                false,
            )
            .await;
        }

        for idx in 0..COUNT {
            log::trace!(target: "citadel", "[Meta] OK:OK ({idx}/{COUNT})");
            inner(
                server_stream.clone(),
                client_stream.clone(),
                dummy_function(),
                dummy_function(),
                true,
            )
            .await;
        }

        for idx in 0..COUNT {
            log::trace!(target: "citadel", "[Meta] ERR:OK ({idx}/{COUNT})");
            inner(
                server_stream.clone(),
                client_stream.clone(),
                dummy_function_err(),
                dummy_function(),
                false,
            )
            .await;
        }

        for idx in 0..COUNT {
            log::trace!(target: "citadel", "[Meta] OK:ERR ({idx}/{COUNT})");
            inner(
                server_stream.clone(),
                client_stream.clone(),
                dummy_function(),
                dummy_function_err(),
                false,
            )
            .await;
        }
    }

    async fn inner<
        R: Send + Debug + 'static,
        F: Future<Output = Result<R, &'static str>> + Send + 'static,
        Y: Future<Output = Result<R, &'static str>> + Send + 'static,
    >(
        conn0: NetworkApplication,
        conn1: NetworkApplication,
        fx_1: F,
        fx_2: Y,
        success: bool,
    ) {
        let server = async move {
            let res = conn0.net_try_join(fx_1).await.unwrap();
            log::trace!(target: "citadel", "Server res: {:?}", res.value);
            res
        };

        let client = async move {
            let res = conn1.net_try_join(fx_2).await.unwrap();
            log::trace!(target: "citadel", "Client res: {res:?}");
            res
        };

        let server = citadel_io::tokio::spawn(server);
        let client = citadel_io::tokio::spawn(client);
        let (res0, res1) = citadel_io::tokio::join!(server, client);

        log::trace!(target: "citadel", "Unwrapping ....");

        let (res0, res1) = (res0.unwrap(), res1.unwrap());

        log::trace!(target: "citadel", "Done unwrapping");
        if success {
            assert!(res0.value.unwrap().is_ok() && res1.value.unwrap().is_ok())
        } else {
            assert!(
                res0.value.map(|r| r.is_err()).unwrap_or(true)
                    || res1.value.map(|r| r.is_err()).unwrap_or(true)
            );
        }

        log::trace!(target: "citadel", "DONE executing")
    }

    async fn dummy_function() -> Result<(), &'static str> {
        citadel_io::tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    async fn dummy_function_err() -> Result<(), &'static str> {
        Err("Error")
    }
}
