//! Subject A reaches the server through a [`SeveringProxy`], peer B directly. A's link is
//! severed while the two are linked, so the server holds A's session; then A logs in again.
//! B reports how many times the server told it that A's old session ended.

use citadel_io::tokio::sync::Barrier;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::server_info;
use std::sync::Arc;
use std::time::Duration;

use super::half_open::{
    connect, link_peers, login_after_local_teardown, server_teardown_notices, standard, usernames,
    SeveringProxy, DISPLACED_WITHIN, PASSWORD,
};
use super::{NodeState, ReconnectionTestKernel};

/// How A logs in again once its link is severed.
#[derive(Clone, Copy)]
pub struct Relogin {
    pub force_login: bool,
    pub correct_password: bool,
}

impl Relogin {
    /// Whether this login may displace the session the server holds for A.
    fn displaces(self) -> bool {
        self.correct_password
    }
}

/// Runs the scenario and returns B's count of server teardown notices.
pub async fn run_scenario(relogin: Relogin) -> usize {
    citadel_logging::setup_log();
    let (server, server_addr) = server_info::<StackedRatchet>();
    let proxy = SeveringProxy::start(server_addr).await;
    let (username_a, username_b) = usernames("ho");

    let connected = Arc::new(Barrier::new(2));
    let linked = Arc::new(Barrier::new(2));
    let settled = Arc::new(Barrier::new(2));
    let done = Arc::new(Barrier::new(2));
    let state_b = Arc::new(NodeState::default());

    let kernel_a = {
        let (connected, linked, settled, done, proxy) = (
            connected.clone(),
            linked.clone(),
            settled.clone(),
            done.clone(),
            proxy.clone(),
        );
        let (username, peer) = (username_a.clone(), username_b.clone());
        ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                remote
                    .register_with_defaults(proxy.addr, &username, &username, PASSWORD)
                    .await?;
                let first = connect(&remote, &username, PASSWORD, standard(false)).await?;
                let cid = first.cid;
                connected.wait().await;
                let p2p = link_peers(&first, &peer).await?;
                linked.wait().await;

                proxy.sever();
                let password = if relogin.correct_password {
                    PASSWORD
                } else {
                    "not-the-password"
                };
                let again = citadel_io::tokio::time::timeout(
                    DISPLACED_WITHIN,
                    login_after_local_teardown(
                        &remote,
                        &username,
                        password,
                        standard(relogin.force_login),
                    ),
                )
                .await
                .expect("the login after the sever did not complete promptly");
                let again = match (again, relogin.displaces()) {
                    (Ok(again), true) => Some(again),
                    (Err(_), false) => None,
                    (Ok(_), false) => panic!("a login with the wrong password was admitted"),
                    (Err(err), true) => {
                        return Err(NetworkError::msg(format!(
                            "the login after the sever was refused: {err}"
                        )))
                    }
                };
                if let Some(again) = &again {
                    assert_eq!(again.cid, cid, "a re-login keeps the account's CID");
                    // The new session's crypto is the account's, not the displaced one's.
                    again.rekey().await?;
                }
                settled.wait().await;
                done.wait().await;
                drop(p2p);
                match again {
                    Some(again) => again.shutdown_kernel().await,
                    None => remote.shutdown().await,
                }
            },
        )
    };

    let kernel_b = {
        let (connected, linked, settled, done) = (
            connected.clone(),
            linked.clone(),
            settled.clone(),
            done.clone(),
        );
        let (username, peer) = (username_b.clone(), username_a.clone());
        ReconnectionTestKernel::new(
            state_b.clone(),
            move |remote: NodeRemote<StackedRatchet>, state: Arc<NodeState>| async move {
                remote
                    .register_with_defaults(server_addr, &username, &username, PASSWORD)
                    .await?;
                let conn = connect(&remote, &username, PASSWORD, standard(false)).await?;
                connected.wait().await;
                let p2p = link_peers(&conn, &peer).await?;
                linked.wait().await;
                settled.wait().await;
                if relogin.displaces() {
                    let deadline =
                        citadel_io::tokio::time::Instant::now() + Duration::from_secs(30);
                    while server_teardown_notices(&state) == 0
                        && citadel_io::tokio::time::Instant::now() < deadline
                    {
                        citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } else {
                    // Give a wrongly sent signal time to arrive before it is counted.
                    citadel_io::tokio::time::sleep(Duration::from_secs(3)).await;
                }
                done.wait().await;
                drop(p2p);
                conn.shutdown_kernel().await
            },
        )
    };

    let client_a = DefaultNodeBuilder::default().build(kernel_a).unwrap();
    let client_b = DefaultNodeBuilder::default().build(kernel_b).unwrap();
    let result = citadel_io::tokio::time::timeout(Duration::from_secs(180), async move {
        citadel_io::tokio::select! {
            res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
            res = futures::future::try_join(client_a, client_b) => res.map(|_| ()),
        }
    })
    .await
    .expect("the test itself timed out");
    assert!(result.is_ok(), "{result:?}");
    server_teardown_notices(&state_b)
}
