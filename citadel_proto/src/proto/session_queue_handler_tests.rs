//! The session queue worker: its keys stay unique, a replaced entry leaves nothing behind, and a
//! worker owned by its session's task releases the session's state when that task is dropped.

use crate::proto::session::SessionState;
use crate::proto::session_queue_handler::{
    QueueWorkerResult, QueueWorkerTicket, SessionQueueWorker,
};
use crate::proto::state_container::{test_support, StateContainer, StateContainerInner};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

type R = StackedRatchet;

async fn state_container() -> StateContainer<R> {
    test_support::state_container(false, 0).await
}

/// A worker over `state`, with no entries of its own. The shutdown channel's receiver is kept
/// so an ending worker does not fail to report it.
fn worker(
    state: &StateContainer<R>,
) -> (
    SessionQueueWorker<R>,
    citadel_io::tokio::sync::broadcast::Receiver<()>,
) {
    let (shutdown, shutdown_rx) = citadel_io::tokio::sync::broadcast::channel(1);
    let (mut worker, _handle) = SessionQueueWorker::new(shutdown);
    worker.load_state_container(state.clone());
    (worker, shutdown_rx)
}

fn counting(
    runs: &Arc<AtomicUsize>,
) -> impl Fn(
    &mut dyn crate::inner_arg::ExpectedInnerTargetMut<StateContainerInner<R>>,
) -> QueueWorkerResult
       + Send
       + 'static {
    let runs = runs.clone();
    move |_| {
        let _ = runs.fetch_add(1, Ordering::SeqCst);
        QueueWorkerResult::Complete
    }
}

/// Single-threaded nodes spawn their session tasks locally, so the worker runs in a `LocalSet`.
async fn in_a_local_set<F: std::future::Future>(test: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(test).await
}

/// Lets the spawned worker run everything now due.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_replaced_entry_runs_once_at_its_own_time() {
    in_a_local_set(a_replaced_entry_runs_once_at_its_own_time_body()).await
}

async fn a_replaced_entry_runs_once_at_its_own_time_body() {
    let state = state_container().await;
    let (mut worker, _shutdown) = worker(&state);
    let (replaced, replacing) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let key = Some(QueueWorkerTicket::Oneshot(7, 1));
    worker.insert_reserved_fn(key, Duration::from_secs(1), counting(&replaced));
    worker.insert_reserved_fn(key, Duration::from_secs(3), counting(&replacing));
    let _running = spawn_handle!(worker);

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(
        replacing.load(Ordering::SeqCst),
        0,
        "the replaced entry's delay fired the replacing entry early"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(replaced.load(Ordering::SeqCst), 0);
    assert_eq!(replacing.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn entries_from_one_handle_never_share_a_key() {
    in_a_local_set(entries_from_one_handle_never_share_a_key_body()).await
}

async fn entries_from_one_handle_never_share_a_key_body() {
    let state = state_container().await;
    let (shutdown, _shutdown_rx) = citadel_io::tokio::sync::broadcast::channel(1);
    let (mut worker, handle) = SessionQueueWorker::<R>::new(shutdown);
    worker.load_state_container(state.clone());
    let runs = Arc::new(AtomicUsize::new(0));
    // Same peer, as an inbound and an outbound group with that peer always were.
    handle.insert_ordinary(9, Duration::from_secs(1), counting(&runs));
    handle.insert_ordinary(9, Duration::from_secs(1), counting(&runs));
    let _running = spawn_handle!(worker);
    // The handle's entries reach the worker when it first runs.
    settle().await;

    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "one entry replaced the other"
    );
}

#[tokio::test]
async fn a_dropped_worker_task_releases_the_session_state() {
    in_a_local_set(a_dropped_worker_task_releases_the_session_state_body()).await
}

async fn a_dropped_worker_task_releases_the_session_state_body() {
    let state = state_container().await;
    let (worker, _shutdown) = worker(&state);
    let probe = state.as_weak();
    // The worker holds the state for as long as it runs, and with no timer due it never wakes
    // to notice its session has gone: only dropping its task releases the state.
    let running = spawn_handle!(worker);
    drop(state);
    settle().await;
    assert!(StateContainer::upgrade_weak(&probe).is_some());

    drop(running);
    // Aborting is asynchronous: the runtime drops the task on its next turn. The deadline
    // only bounds that turn.
    tokio::time::timeout(Duration::from_secs(5), async {
        while StateContainer::upgrade_weak(&probe).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the session state outlived its worker's dropped task");
}

/// A worker that finds its session ending stops with `Ok`: that is every session's normal end,
/// and reporting it as an error logged `QueueHandlerShutdown` at the end of every session.
#[tokio::test(start_paused = true)]
async fn a_worker_ends_without_error_when_its_session_ends() {
    in_a_local_set(a_worker_ends_without_error_when_its_session_ends_body()).await
}

async fn a_worker_ends_without_error_when_its_session_ends_body() {
    let state = state_container().await;
    let (mut worker, _shutdown) = worker(&state);
    let runs = Arc::new(AtomicUsize::new(0));
    worker.insert_reserved_fn(
        Some(QueueWorkerTicket::Periodic(3, 0)),
        Duration::from_secs(1),
        counting(&runs),
    );
    let running = spawn_handle!(worker);
    settle().await;
    inner_mut_state!(state)
        .state
        .set(SessionState::Disconnecting);
    tokio::time::advance(Duration::from_secs(2)).await;
    let ended = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("the worker outlived its session")
        .unwrap();
    assert!(ended.is_ok(), "{ended:?}");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "an entry ran after its session ended"
    );
}
