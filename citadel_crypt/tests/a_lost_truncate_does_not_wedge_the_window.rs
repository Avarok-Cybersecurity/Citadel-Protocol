//! One Truncate that never applies at Bob (his round had already ended) does not wedge later
//! rounds: a later Truncate retires every version up to the one it names, so the two windows
//! realign and Bob's toolset stays within `MAX_RATCHETS_IN_MEMORY`.
//!
//! Drives two `PeerSessionCrypto`s by hand in `RatchetManager::rekey` order.
use citadel_crypt::endpoint_crypto_container::{
    EndpointRatchetConstructor, KemTransferStatus, PeerSessionCrypto,
};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::toolset::{Toolset, MAX_RATCHETS_IN_MEMORY};
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

type R = StackedRatchet;
const PSKS: &[&[u8]] = &[b"psk"];

fn setup() -> (PeerSessionCrypto<R>, PeerSessionCrypto<R>) {
    let opts = ConstructorOpts::new_vec_init(
        Some(EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem),
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), 10, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(20, opts, a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (
        PeerSessionCrypto::new(Toolset::new(10, a.finish().unwrap()), true),
        PeerSessionCrypto::new(Toolset::new(20, b.finish().unwrap()), false),
    )
}

/// Runs the commits of one round. Returns the version Alice truncated (if the
/// window was full), having already deregistered it on Alice, exactly as the
/// Leader's BobToAlice arm does before sending `Truncate`.
fn commit_round(alice: &PeerSessionCrypto<R>, bob: &PeerSessionCrypto<R>) -> Option<u32> {
    let mut acx = alice.get_next_constructor().expect("alice constructor");
    let opts = bob.get_ratchet(None).unwrap().get_next_constructor_opts();
    let bcx =
        <R as Ratchet>::Constructor::new_bob(20, opts, acx.stage0_alice().unwrap(), PSKS).unwrap();
    let KemTransferStatus::Some(b2a, _) = bob.update_sync_safe(bcx, false).unwrap() else {
        panic!("bob produced no transfer");
    };
    acx.stage1_alice(b2a, PSKS).unwrap();
    let status = alice.update_sync_safe(acx, true).unwrap();
    let truncate = status.requires_truncation();
    if let Some(v) = truncate {
        alice
            .deregister_oldest_ratchet(v)
            .expect("leader-side deregister");
    }
    truncate
}

/// Bob's Truncate / LoserCanFinish arm, then Alice's LeaderCanFinish arm.
fn finish_round(alice: &PeerSessionCrypto<R>, bob: &PeerSessionCrypto<R>, truncate: Option<u32>) {
    if let Some(v) = truncate {
        bob.deregister_oldest_ratchet(v)
            .unwrap_or_else(|e| panic!("Bob could not apply Truncate({v}): {e:?}"));
    }
    bob.post_alice_stage1_or_post_stage1_bob();
    alice.post_alice_stage1_or_post_stage1_bob();
    reset(alice, bob);
}

/// The manager's error path on both sides: toggle off, resync declared.
fn reset(alice: &PeerSessionCrypto<R>, bob: &PeerSessionCrypto<R>) {
    for c in [alice, bob] {
        c.update_in_progress.toggle_off();
        c.sync_declared_version();
    }
}

fn lens(alice: &PeerSessionCrypto<R>, bob: &PeerSessionCrypto<R>) -> (usize, usize) {
    (alice.toolset().read().len(), bob.toolset().read().len())
}

#[test]
fn one_unapplied_truncate_does_not_wedge_later_rounds() {
    let (alice, bob) = setup();
    // Fill the window with clean rounds, including at least one clean truncate.
    let mut saw_truncate = false;
    while !saw_truncate || alice.latest_usable_version() < MAX_RATCHETS_IN_MEMORY as u32 {
        let t = commit_round(&alice, &bob);
        saw_truncate |= t.is_some();
        finish_round(&alice, &bob, t);
    }
    let (a, b) = lens(&alice, &bob);
    eprintln!(
        "steady state: alice len={a} bob len={b} latest={}",
        alice.latest_usable_version()
    );

    // One round whose Truncate Bob never applies (his round already errored).
    let lost = commit_round(&alice, &bob);
    assert!(lost.is_some(), "window should be full here");
    reset(&alice, &bob);
    eprintln!(
        "after lost Truncate({lost:?}): lens={:?}",
        lens(&alice, &bob)
    );

    // The next rounds must still complete.
    for round in 0..3 {
        let t = commit_round(&alice, &bob);
        eprintln!(
            "round {round}: truncate={t:?} lens={:?}",
            lens(&alice, &bob)
        );
        finish_round(&alice, &bob, t);
    }
    assert!(bob.toolset().read().len() <= MAX_RATCHETS_IN_MEMORY);
}
