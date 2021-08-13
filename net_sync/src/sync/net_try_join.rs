use std::pin::Pin;
use std::future::Future;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use std::task::{Context, Poll};
use tokio::sync::{Mutex, MutexGuard};
use serde::{Serialize, Deserialize};
use crate::sync::network_endpoint::{NetworkEndpoint, PreActionSync};
use crate::sync::RelativeNodeType;

/// Two endpoints produce Ok(T). Returns when both endpoints produce Ok(T), or, when the first error occurs
pub struct NetTryJoin<'a, T, E> {
    future: Pin<Box<dyn Future<Output=Result<NetTryJoinResult<T, E>, anyhow::Error>> + Send + 'a>>,
}

impl<'a, T: Send + 'a, E: Send + 'a> NetTryJoin<'a, T, E> {
    pub fn new<Conn: ReliableOrderedConnectionToTarget + 'static, F: Send + 'a>(conn: &'a NetworkEndpoint<Conn>, local_node_type: RelativeNodeType, future: F) -> NetTryJoin<'a, T, E>
        where F: Future<Output=Result<T, E>> {
        Self { future: Box::pin(resolve(conn.subscribe_internal(), local_node_type, future)) }
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
    pub value: Option<Result<T, E>>
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
    Pinging(Option<bool>)
}

impl State {
    /// assumes this is called by the receiving node, not the node that creates the state
    fn implies_success(&self) -> bool {
        match self {
            Self::ObtainedValidResult => true,
            Self::Pinging(Some(true)) => true,
            _ => false
        }
    }

    fn implies_failure(&self) -> bool {
        match self {
            Self::Error => true,
            Self::Pinging(Some(false)) => true,
            _ => false
        }
    }
}

async fn resolve<Conn: ReliableOrderedConnectionToTarget, F, T, E>(conn: PreActionSync<'_, Conn>, local_node_type: RelativeNodeType, future: F) -> Result<NetTryJoinResult<T, E>, anyhow::Error>
    where F: Future<Output=Result<T, E>> {
    let ref conn = conn.await?;
    log::info!("NET_TRY_JOIN started conv={:?} for {:?}", conn.id, local_node_type);
    let (stopper_tx, stopper_rx) = tokio::sync::oneshot::channel::<()>();

    struct LocalState<T, E> {
        local_state: State,
        ret_value: Option<Result<T, E>>
    }

    let local_state = LocalState { local_state: State::Pending, ret_value: None };
    let ref local_state_ref = Mutex::new(local_state);

    let has_preference = local_node_type == RelativeNodeType::Initiator;

    // the evaluator finishes before the "completer" if this goes successfully
    let evaluator = async move {
        let _stopper_tx = stopper_tx;

        async fn return_sequence<Conn: ReliableOrderedConnectionToTarget, T, E>(conn: &Conn, new_state: State, mut state: MutexGuard<'_, LocalState<T, E>>) -> Result<Option<Result<T, E>>, anyhow::Error> {
            state.local_state = new_state.clone();
            conn.send_serialized(new_state.clone()).await?;
            Ok(state.ret_value.take())
        }

        loop {
            let received_remote_state = conn.recv_serialized::<State>().await?;
            //log::info!("{:?} RECV'd {:?}", local_node_type, &received_remote_state);
            let mut lock = local_state_ref.lock().await;
            let local_state_info = lock.ret_value.as_ref().map(|r| r.is_ok());
            log::info!("[conv={:?} Node {:?} recv {:?} || Local state: {:?}", conn.id, local_node_type, received_remote_state, lock.local_state);
            if has_preference {
                // if local has preference, we have the permission to evaluate
                // first, check to make sure local hasn't already obtained a value
                if received_remote_state.implies_failure() || lock.local_state.implies_failure() {
                    // If ANY node fails in a TryJoin, we have a global failure
                    return return_sequence(conn, State::ResolvedBothFail, lock).await
                }

                // at this point, neither imply failure
                if received_remote_state.implies_success() && lock.local_state.implies_success() {
                    return return_sequence(conn, State::Resolved, lock).await;
                }

                // neither imply failure, AND, neither imply success. This means we need to ping until either one of those conditions becomes true
                conn.send_serialized(State::Pinging(local_state_info)).await?;
            } else {
                // if not, we cannot evaluate UNLESS we are being told that we resolved
                match received_remote_state {
                    State::Resolved => {
                        // remote is telling us we both won
                        lock.local_state = State::Resolved;
                        return Ok(lock.ret_value.take())
                    }

                    State::ResolvedBothFail => {
                        // both nodes failed
                        return Ok(lock.ret_value.take())
                    }

                    _ => {
                        // even in the case of an error, or simply an acknowledgement that the adjacent side succeeded, we need to let remote determine what to do. Just ping
                        //std::mem::drop(lock);
                        conn.send_serialized(State::Pinging(local_state_info)).await?;
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

        let state = res.as_ref().map(|_| State::ObtainedValidResult).unwrap_or(State::Error);

        // we don't check the local state because the resolution would terminate this task anyways
        //log::info!("[NetRacer] {:?} Old state: {:?} | New state: {:?}", local_node_type, &local_state.local_state, &state);

        local_state.local_state = state.clone();
        local_state.ret_value = Some(res);

        // now, send a packet to the other side
        conn.send_serialized(state).await?;
        std::mem::drop(local_state);
        //log::info!("[NetRacer] {:?} completer done", local_node_type);

        stopper_rx.await?;
        Err(anyhow::Error::msg("Stopped before the resolver"))
    };

    tokio::select! {
        res0 = evaluator => {
            log::info!("NET_TRY_JOIN ending for {:?} (conv={:?})", local_node_type, conn.id);
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
    use std::future::Future;
    use crate::reliable_conn::ReliableOrderedConnectionToTarget;
    use std::fmt::Debug;
    use std::time::Duration;
    use crate::sync::network_endpoint::NetworkEndpoint;
    use crate::sync::test_utils::{deadlock_detector, create_streams};

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn racer() {
        setup_log();
        deadlock_detector();

        let (server_stream, client_stream) = create_streams().await;
        const COUNT: i32 = 10;
        for idx in 0..COUNT {
            log::info!("[Meta] ERR:ERR ({}/{})", idx, COUNT);
            inner(server_stream.clone(), client_stream.clone(), dummy_function_err(), dummy_function_err(), false).await;
        }

        for idx in 0..COUNT {
            log::info!("[Meta] OK:OK ({}/{})", idx, COUNT);
            inner(server_stream.clone(), client_stream.clone(), dummy_function(), dummy_function(), true).await;
        }

        
        for idx in 0..COUNT{
            log::info!("[Meta] ERR:OK ({}/{})", idx, COUNT);
            inner(server_stream.clone(), client_stream.clone(), dummy_function_err(), dummy_function(), false).await;
        }


        for idx in 0..COUNT {
            log::info!("[Meta] OK:ERR ({}/{})", idx, COUNT);
            inner(server_stream.clone(), client_stream.clone(), dummy_function(), dummy_function_err(), false).await;
        }
    }


    async fn inner<R: Send + Debug + 'static, Conn0: ReliableOrderedConnectionToTarget + 'static, Conn1: ReliableOrderedConnectionToTarget + 'static, F: Future<Output=Result<R, &'static str>> + Send + 'static, Y: Future<Output=Result<R, &'static str>> + Send + 'static>(conn0: NetworkEndpoint<Conn0>, conn1: NetworkEndpoint<Conn1>, fx_1: F, fx_2: Y, success: bool) {
        let server = async move {
            let res = conn0.net_try_join(fx_1).await.unwrap();
            log::info!("Server res: {:?}", res.value);
            res
        };

        let client = async move {
            let res = conn1.net_try_join(fx_2).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        };

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);

        log::info!("Unwrapping ....");

        let (res0, res1) = (res0.unwrap(), res1.unwrap());

        log::info!("Done unwrapping");
        if success {
            assert!(res0.value.unwrap().is_ok() && res1.value.unwrap().is_ok())
        } else {
            assert!(res0.value.map(|r| r.is_err()).unwrap_or(true) || res1.value.map(|r| r.is_err()).unwrap_or(true));
        }

        log::info!("DONE executing")
    }

    async fn dummy_function() -> Result<(), &'static str> {
        Ok(tokio::time::sleep(Duration::from_millis(50)).await)
    }

    async fn dummy_function_err() -> Result<(), &'static str> {
        Err("Error")
    }
}