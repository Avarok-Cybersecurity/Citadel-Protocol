use crate::udp_traversal::linear::RelativeNodeType;
use serde::{Serialize, Deserialize};
use futures::Future;
use std::pin::Pin;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use std::task::{Context, Poll};
use tokio::sync::{Mutex, MutexGuard};

/// Two endpoints race to produce Ok(R). The first endpoint to produce Ok(R) wins. Includes conflict-resolution synchronization
pub struct NetSelectOk<'a, R> {
    future: Pin<Box<dyn Future<Output=Result<NetSelectOkResult<R>, anyhow::Error>> + 'a>>,
}

impl<'a, R: 'a> NetSelectOk<'a, R> {
    pub fn new<Conn: ReliableOrderedConnectionToTarget + 'a, F: 'a>(conn: Conn, local_node_type: RelativeNodeType, future: F) -> Self
        where F: Future<Output=Result<R, anyhow::Error>> {
        Self { future: Box::pin(resolve(conn, local_node_type, future)) }
    }
}

impl<R> Future for NetSelectOk<'_, R> {
    type Output = Result<NetSelectOkResult<R>, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
enum State {
    Pending,
    ObtainedValidResult,
    ResolvedLocalWon,
    ResolvedPointeeWins,
    ResolvedBothFail,
    NonPreferredFinished,
    Error,
    // None if not finished, false if errored, true if success
    Pinging(Option<bool>)
}

impl State {
    /// assumes this is called by the receiving node, not the node that creates the state
    fn implies_remote_success(&self) -> bool {
        match self {
            Self::ObtainedValidResult => true,
            Self::Pinging(Some(true)) => true,
            _ => false
        }
    }

    fn implies_remote_failure(&self) -> bool {
        match self {
            Self::Error => true,
            Self::Pinging(Some(false)) => true,
            _ => false
        }
    }
}

#[derive(Debug)]
pub struct NetSelectOkResult<R> {
    /// This contains a value for the winning side, while containing no value for the losing side
    pub result: Option<R>,
    /// This is not the same as "winning". Winning just means local had preference and obtained a valid value. Other side succeeding just means their result was Ok(R)
    pub other_side_succeeded: bool,
}

impl<R> NetSelectOkResult<R> {
    /// Returns true if both sides failed
    pub fn global_failure(&self) -> bool {
        self.result.is_none() && !self.other_side_succeeded
    }
}

async fn resolve<Conn: ReliableOrderedConnectionToTarget, F, R>(ref conn: Conn, local_node_type: RelativeNodeType, future: F) -> Result<NetSelectOkResult<R>, anyhow::Error>
    where F: Future<Output=Result<R, anyhow::Error>> {
    let (stopper_tx, stopper_rx) = tokio::sync::oneshot::channel::<()>();

    struct LocalState<R> {
        local_state: State,
        ret_value: Option<Result<R, anyhow::Error>>
    }

    let local_state = LocalState { local_state: State::Pending, ret_value: None };
    let ref local_state_ref = Mutex::new(local_state);

    let has_preference = local_node_type == RelativeNodeType::Initiator;

    // the evaluator finishes before the "completer" if this goes successfully
    let evaluator = async move {
        let _stopper_tx = stopper_tx;

        async fn return_sequence<Conn: ReliableOrderedConnectionToTarget, R>(conn: &Conn, new_state: State, mut state: MutexGuard<'_, LocalState<R>>, adjacent_success: bool) -> Result<(Option<Result<R, anyhow::Error>>, bool), anyhow::Error> {
            state.local_state = new_state.clone();
            conn.send_serialized(new_state.clone()).await?;

            log::info!("INITIATOR RETURNING");
            Ok((state.ret_value.take(), adjacent_success))
        }

        loop {
            let received_remote_state = conn.recv_serialized::<State>().await?;
            log::info!("{:?} RECV'd {:?}", local_node_type, &received_remote_state);
            let mut lock = local_state_ref.lock().await;
            let local_state_info = lock.ret_value.as_ref().map(|r| r.is_ok());
            let adjacent_success = received_remote_state.implies_remote_success();

            if has_preference {
                // if local has preference, we have the permission to evaluate
                // first, check to make sure local hasn't already obtained a value
                match lock.local_state {
                    State::ObtainedValidResult => {
                        // we win unconditionally, even if remote submitted a valid result
                        return return_sequence(conn, State::ResolvedLocalWon, lock, false).await
                    }

                    State::Error => {
                        // if adjacent has a valid result, the adjacent side wins unconditionally
                        if received_remote_state.implies_remote_success() {
                            // adjacent node wins unconditionally
                            return return_sequence(conn, State::ResolvedPointeeWins, lock, adjacent_success).await
                        } else {

                            // if local state is errored, and, remote is errored, then conclude
                            if received_remote_state.implies_remote_failure() {
                                // both nodes failed
                                return return_sequence(conn, State::ResolvedBothFail, lock, false).await
                            } else {
                                // otherwise, keep pinging; we must wait for remote to finish
                                conn.send_serialized(State::Pinging(local_state_info)).await?;
                            }
                        }
                    }

                    _ => {
                        // if remote won, finish unconditionally
                        if received_remote_state.implies_remote_success() {
                            // adjacent node wins unconditionally
                            return return_sequence(conn, State::ResolvedPointeeWins, lock, adjacent_success).await
                        } else {
                            // local state is pending, yet, remote is either errored or not done
                            if received_remote_state.implies_remote_failure() {
                                // remote won't be able to conclude; Ping to wait for local to finish
                                conn.send_serialized(State::Pinging(local_state_info)).await?;
                            } else {
                                // both local and remote are pending
                                conn.send_serialized(State::Pinging(local_state_info)).await?;
                            }
                        }
                    }
                }
            } else {
                // if not, we cannot evaluate UNLESS we are being told that we resolved
                log::info!("RECV REMT: {:?}", received_remote_state);
                match received_remote_state {
                    State::ResolvedPointeeWins => {
                        // remote is telling us WE won
                        lock.local_state = State::ResolvedLocalWon;
                        //conn.send_serialized(State::NonPreferredFinished).await?;

                        return Ok((lock.ret_value.take(), false))
                    }

                    State::ResolvedLocalWon => {
                        // remote is telling us THEY won
                        lock.local_state = State::ResolvedPointeeWins;
                        //conn.send_serialized(State::NonPreferredFinished).await?;

                        return Ok((None, true))
                    }

                    State::ResolvedBothFail => {
                        // both nodes failed
                        log::info!("{:?} returning with both failed", local_node_type);
                        std::mem::drop(lock);
                        //conn.send_serialized(State::NonPreferredFinished).await?;

                        return Ok((None, false))
                    }

                    State::ObtainedValidResult => {
                        // if the opposite side sent this, it means it locally produced a valid result and is thus the winner
                        return Ok((None, true))
                    }

                    _ => {
                        // even in the case of an error, we need to let remote determine what to do. Just ping
                        log::info!("Sending ping");
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
        log::info!("[NetRacer] {:?} Old state: {:?} | New state: {:?}", local_node_type, &local_state.local_state, &state);

        local_state.local_state = state.clone();
        local_state.ret_value = Some(res);

        // now, send a packet to the other side
        conn.send_serialized(state).await?;
        std::mem::drop(local_state);
        log::info!("[NetRacer] {:?} completer done", local_node_type);

        stopper_rx.await?;
        Err(anyhow::Error::msg("Stopped before the resolver"))
    };

    tokio::select! {
        res0 = evaluator => {
            let (ret, remote_success) = res0?;
            let local_state = local_state_ref.lock().await;
            log::info!("returning {:?} local state = {:?}", local_node_type, local_state.local_state);
            Ok(wrap_return(ret, local_state.local_state == State::ResolvedLocalWon, remote_success))
        },

        res1 = completer => res1
    }
}

fn wrap_return<R>(result: Option<Result<R, anyhow::Error>>, did_win: bool, other_side_succeeded: bool) -> NetSelectOkResult<R> {
    NetSelectOkResult { result: if did_win { result.map(|r| r.ok()).flatten() } else { None }, other_side_succeeded }
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};
    use crate::udp_traversal::linear::RelativeNodeType;
    use std::pin::Pin;
    use std::future::Future;
    use std::task::{Context, Poll};
    use crate::sync::ReliableOrderedConnSyncExt;
    use crate::reliable_conn::ReliableOrderedConnectionToTarget;
    use std::sync::Arc;
    use std::fmt::Debug;
    use std::time::Duration;
    use crate::reliable_conn::simulator::NetworkConnSimulator;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    async fn create_streams() -> (Arc<NetworkConnSimulator<'static, TcpStream>>, Arc<NetworkConnSimulator<'static, TcpStream>>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            listener.accept().await.unwrap().0
        };

        let client = async move {
            let addr = rx.await.unwrap();
            TcpStream::connect(addr).await.unwrap()
        };

        let (server_stream, client_stream) = tokio::join!(server, client);
        (Arc::new(server_stream.into()), Arc::new(client_stream.into()))
    }

    #[tokio::test]
    async fn racer() {
        setup_log();


        //inner(server_stream.clone(), client_stream.clone(), dummy_function_err(), dummy_function()).await;
        //flush_clean(&client_stream, &server_stream).await;
        for idx in 0..10 {
            log::info!("[Meta] ERR:ERR ({}/10)", idx);
            let (server_stream, client_stream) = create_streams().await;
            inner(server_stream.clone(), client_stream.clone(), dummy_function_err(), dummy_function_err()).await;
        }


        for idx in 0..10 {
            log::info!("[Meta] OK:OK ({}/10)", idx);
            let (server_stream, client_stream) = create_streams().await;
            inner(server_stream.clone(), client_stream.clone(), dummy_function(), dummy_function()).await;
        }


        for idx in 0..10 {
            log::info!("[Meta] ERR:OK ({}/10)", idx);
            let (server_stream, client_stream) = create_streams().await;
            inner(server_stream.clone(), client_stream.clone(), dummy_function_err(), dummy_function()).await;
        }


        for idx in 0..10 {
            log::info!("[Meta] OK:ERR ({}/10)", idx);
            let (server_stream, client_stream) = create_streams().await;
            inner(server_stream.clone(), client_stream.clone(), dummy_function(), dummy_function_err()).await;
        }
    }


    async fn inner<R: Send + Debug + 'static, Conn0: ReliableOrderedConnectionToTarget + 'static, Conn1: ReliableOrderedConnectionToTarget + 'static, F: Future<Output=Result<R, anyhow::Error>> + 'static, Y: Future<Output=Result<R, anyhow::Error>> + 'static>(conn0: Conn0, conn1: Conn1, fx_1: F, fx_2: Y) {
        let server = AssertSendSafeFuture::new(async move {
            let res = conn0.net_select_ok(RelativeNodeType::Receiver, fx_1).await.unwrap();
            log::info!("Server res: {:?}", res);
            res
        });

        let client = AssertSendSafeFuture::new(async move {
            let res = conn1.net_select_ok(RelativeNodeType::Initiator, fx_2).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        });

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        let (res0, res1) = (res0.unwrap(), res1.unwrap());

        if res0.result.is_some() {
            assert_eq!(res0.other_side_succeeded, false);
            assert!(res1.result.is_none());
            assert!(res1.other_side_succeeded);
        }

        if res1.result.is_some() {
            assert_eq!(res1.other_side_succeeded, false);
            assert!(res0.result.is_none());
            assert!(res0.other_side_succeeded);
        }

        if res0.result.is_none() && res1.result.is_none() {
            assert_eq!(res0.other_side_succeeded, false);
            assert_eq!(res1.other_side_succeeded, false);
            assert!(res0.global_failure());
            assert!(res1.global_failure());
        }

        log::info!("DONE executing")
    }

    async fn dummy_function() -> Result<(), anyhow::Error> {
        Ok(tokio::time::sleep(Duration::from_millis(50)).await)
    }

    async fn dummy_function_err() -> Result<(), anyhow::Error> {
        Err(anyhow::Error::msg("Error!!"))
    }

    struct AssertSendSafeFuture<'a, Out: 'a>(Pin<Box<dyn Future<Output=Out> + 'a>>);

    unsafe impl<'a, Out: 'a> Send for AssertSendSafeFuture<'a, Out> {}

    impl<'a, Out: 'a> AssertSendSafeFuture<'a, Out> {
        /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
        pub fn new(fx: impl Future<Output=Out> + 'a) -> Self {
            Self(Box::pin(fx))
        }
    }

    impl<'a, Out: 'a> Future for AssertSendSafeFuture<'a, Out> {
        type Output = Out;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.as_mut().poll(cx)
        }
    }
}