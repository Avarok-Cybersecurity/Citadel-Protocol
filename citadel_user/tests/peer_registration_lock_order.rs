//! Registering two accounts as peers on the server finishes whatever the order of the pair, and
//! an account is never registered as its own peer. Each case runs on its own OS thread and runtime,
//! so a registration that never finishes fails the test at its time limit instead of hanging it.
#[path = "common/server_accounts.rs"]
mod server_accounts;

use citadel_io::{tokio, ErrorCode};
use citadel_user::backend::BackendType;
use server_accounts::{cheap_argon, manager, register};
use std::sync::mpsc;
use std::time::Duration;

/// Runs `body` on a fresh thread and runtime; returns its output if it finished within `limit`.
fn within<T: Send + 'static>(
    limit: Duration,
    body: impl FnOnce(tokio::runtime::Runtime) -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    let _detached = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let _ = tx.send(body(rt));
    });
    rx.recv_timeout(limit).ok()
}

#[test]
fn registering_an_account_as_its_own_peer_is_refused() {
    let outcome = within(Duration::from_secs(10), |rt| {
        rt.block_on(async {
            let mgr = manager(BackendType::InMemory, cheap_argon()).await;
            let (a, _) = register(&mgr, "self_pair_a", "password123").await;
            mgr.register_hyperlan_p2p_as_server(a, a)
                .await
                .map_err(|err| err.code)
        })
    })
    .expect("registering an account with itself did not finish");
    assert_eq!(outcome, Err(ErrorCode::PeerRegisterSelf));
}

fn two_racers(same_order: bool) -> bool {
    within(Duration::from_secs(20), move |rt| {
        rt.block_on(async move {
            let mgr = manager(BackendType::InMemory, cheap_argon()).await;
            let (a, _) = register(&mgr, "pair_order_a", "password123").await;
            let (b, _) = register(&mgr, "pair_order_b", "password123").await;
            let spawn = |x: u64, y: u64| {
                let mgr = mgr.clone();
                tokio::spawn(async move {
                    for _ in 0..200_000u32 {
                        mgr.register_hyperlan_p2p_as_server(x, y).await.unwrap();
                    }
                })
            };
            let (t1, t2) = if same_order {
                (spawn(a, b), spawn(a, b))
            } else {
                (spawn(a, b), spawn(b, a))
            };
            t1.await.unwrap();
            t2.await.unwrap();
        })
    })
    .is_some()
}

/// Control: the same workload with both racers in the same argument order finishes in time, so
/// a timeout in the crossed case is the lock order, not slowness.
#[test]
fn control_same_order_registrations_finish() {
    assert!(two_racers(true), "the same-order control did not finish");
}

#[test]
fn registrations_of_one_pair_in_opposite_orders_finish() {
    assert!(
        two_racers(false),
        "register(a, b) racing register(b, a) did not finish"
    );
}
