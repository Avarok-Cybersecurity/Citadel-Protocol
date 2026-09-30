//! A rekey trigger dropped before its AliceToBob is sent must leave nothing
//! behind.
//!
//! `trigger_rekey_with_payload` claims `update_in_progress` (via
//! `claim_next_constructor_source`), then awaits the keygen offload; after it,
//! it declares the next version, stores the constructor and registers the
//! listener, then awaits `sender.lock()`. A caller's `select!` or `timeout`
//! can drop the future at either await. Nothing has reached the peer, so no
//! round will ever conclude and clear that state: the next trigger sees the
//! claimed toggle (constructor `None`) or the declared version ("rekey already
//! pending") and returns `Ok` without rekeying.
//!
//! Deterministic: each test parks the trigger at one await by starving what it
//! waits on (the only blocking thread, or the sender lock), polls it there,
//! and drops it.

use super::tests::{create_ratchet_managers, post_checks, TestRatchetManager};
use crate::ratchets::stacked::StackedRatchet;
use crate::sync_toggle::CurrentToggleState;
use citadel_io::tokio;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;

type Manager = TestRatchetManager<StackedRatchet, ()>;

/// Bounds the follow-up rekey so a stalled one fails instead of hanging.
const FOLLOW_UP_TIMEOUT: Duration = Duration::from_secs(30);

/// One blocking thread, so a test can occupy it and hold the trigger at its
/// keygen offload.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap()
}

/// Polls a fresh trigger until `parked` holds, asserting it never completes,
/// then drops it: the cancellation a caller's `select!` or `timeout` performs.
async fn cancel_trigger_once(alice: &Manager, parked: impl Fn(&Manager) -> bool) {
    let mut trigger = Box::pin(alice.trigger_rekey(true));
    std::future::poll_fn(|cx| {
        assert!(
            trigger.as_mut().poll(cx).is_pending(),
            "the trigger completed while what it awaits was held"
        );
        if parked(alice) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn assert_the_next_rekey_happens(alice: &Manager, bob: &Manager) {
    let before = alice.session_crypto_state.latest_usable_version();
    let result = tokio::time::timeout(FOLLOW_UP_TIMEOUT, alice.trigger_rekey(true)).await;
    assert!(matches!(result, Ok(Ok(()))), "follow-up rekey: {result:?}");
    assert_eq!(
        alice.session_crypto_state.latest_usable_version(),
        before + 1,
        "the follow-up rekey returned Ok without rekeying: the cancelled trigger's \
         state (update_in_progress={:?}, declared={}) is still claimed",
        alice.session_crypto_state.update_in_progress.state(),
        alice.session_crypto_state.declared_next_version(),
    );
    post_checks(alice, bob);
}

#[test]
fn a_trigger_cancelled_at_its_keygen_offload_does_not_block_the_next_rekey() {
    citadel_logging::setup_log();
    runtime().block_on(async {
        let (alice, bob) = create_ratchet_managers::<StackedRatchet, ()>();

        let (occupied_tx, occupied_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let occupant = tokio::task::spawn_blocking(move || {
            let _ = occupied_tx.send(());
            let _ = release_rx.recv();
        });
        occupied_rx.await.unwrap();

        cancel_trigger_once(&alice, |m| {
            m.session_crypto_state.update_in_progress.state() == CurrentToggleState::AlreadyToggled
        })
        .await;

        drop(release_tx);
        occupant.await.unwrap();
        assert_the_next_rekey_happens(&alice, &bob).await;
    });
}

#[test]
fn a_trigger_cancelled_at_the_sender_lock_does_not_block_the_next_rekey() {
    citadel_logging::setup_log();
    runtime().block_on(async {
        let (alice, bob) = create_ratchet_managers::<StackedRatchet, ()>();

        let sender_held = alice.sender.clone().lock_owned().await;
        cancel_trigger_once(&alice, |m| {
            let state = &m.session_crypto_state;
            state.declared_next_version() > state.latest_usable_version()
        })
        .await;

        drop(sender_held);
        assert_the_next_rekey_happens(&alice, &bob).await;
    });
}
