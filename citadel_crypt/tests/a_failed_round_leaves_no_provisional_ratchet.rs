//! A rekey round that ends after Bob committed its ratchet, but before it completed, leaves
//! nothing behind: the next round builds on the latest *usable* version on both ends, so both
//! number its ratchet alike and hold the same keys under it.
//!
//! Drives two `PeerSessionCrypto`s by hand, in the order `RatchetManager::rekey` does
//! (AliceToBob -> Bob `update_sync_safe(_, false)` -> BobToAlice -> Alice `stage1_alice` +
//! `update_sync_safe(_, true)` -> both `post_alice_stage1_or_post_stage1_bob`).
use citadel_crypt::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::toolset::Toolset;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

type R = StackedRatchet;
const ALICE_CID: u64 = 10;
const BOB_CID: u64 = 20;
const PSKS: &[&[u8]] = &[b"psk"];

fn setup() -> (PeerSessionCrypto<R>, PeerSessionCrypto<R>) {
    let opts = ConstructorOpts::new_vec_init(
        Some(EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem),
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), ALICE_CID, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(BOB_CID, opts, a.stage0_alice().unwrap(), PSKS)
            .unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (
        PeerSessionCrypto::new(Toolset::new(ALICE_CID, a.finish().unwrap()), true),
        PeerSessionCrypto::new(Toolset::new(BOB_CID, b.finish().unwrap()), false),
    )
}

/// One round up to and including Bob's commit. Returns Alice's constructor and
/// Bob's BobToAlice transfer (the caller decides whether it is "delivered").
fn round_until_bob_commits(
    alice: &PeerSessionCrypto<R>,
    bob: &PeerSessionCrypto<R>,
) -> (
    <R as Ratchet>::Constructor,
    <<R as Ratchet>::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
) {
    let alice_cx = alice.get_next_constructor().expect("alice constructor");
    let a2b = alice_cx.stage0_alice().unwrap();
    // Bob derives opts from his latest usable ratchet, as rekey() does.
    let opts = bob.get_ratchet(None).unwrap().get_next_constructor_opts();
    let bob_cx = <R as Ratchet>::Constructor::new_bob(BOB_CID, opts, a2b, PSKS).unwrap();
    let status = bob.update_sync_safe(bob_cx, false).unwrap();
    let citadel_crypt::endpoint_crypto_container::KemTransferStatus::Some(b2a, _) = status else {
        panic!("expected Bob to produce a transfer, got {status:?}");
    };
    (alice_cx, b2a)
}

fn finish_round(
    alice: &PeerSessionCrypto<R>,
    bob: &PeerSessionCrypto<R>,
    mut alice_cx: <R as Ratchet>::Constructor,
    b2a: <<R as Ratchet>::Constructor as EndpointRatchetConstructor<R>>::BobToAliceWireTransfer,
) {
    alice_cx.stage1_alice(b2a, PSKS).unwrap();
    let _ = alice.update_sync_safe(alice_cx, true).unwrap();
    // LoserCanFinish on Bob, LeaderCanFinish on Alice.
    bob.post_alice_stage1_or_post_stage1_bob();
    alice.post_alice_stage1_or_post_stage1_bob();
    alice.update_in_progress.toggle_off();
    bob.update_in_progress.toggle_off();
}

fn assert_keys_agree(alice: &PeerSessionCrypto<R>, bob: &PeerSessionCrypto<R>) {
    assert_eq!(alice.latest_usable_version(), bob.latest_usable_version());
    let ct = alice.get_ratchet(None).unwrap().encrypt(b"hello").unwrap();
    let pt = bob
        .get_ratchet(None)
        .unwrap()
        .decrypt(ct)
        .expect("Bob must decrypt what Alice encrypted at the same latest_usable_version");
    assert_eq!(pt, b"hello");
}

/// Two clean rounds keep the keys in sync.
#[test]
fn clean_rounds_keep_keys_in_sync() {
    let (alice, bob) = setup();
    for _ in 0..2 {
        let (cx, b2a) = round_until_bob_commits(&alice, &bob);
        finish_round(&alice, &bob, cx, b2a);
    }
    assert_eq!(alice.latest_usable_version(), 2);
    assert_keys_agree(&alice, &bob);
}

/// Round 1 ends after Bob's commit (its BobToAlice never arrives). The manager's error path
/// toggles off and resyncs the declared version; the next commit drops the provisional ratchet.
#[test]
fn failed_round_then_clean_round_keeps_keys_in_sync() {
    let (alice, bob) = setup();
    let (_lost_cx, _lost_b2a) = round_until_bob_commits(&alice, &bob);
    // Error path of spawn_rekey_process on both sides (ToggleGuard + sync).
    alice.update_in_progress.toggle_off();
    bob.update_in_progress.toggle_off();
    alice.sync_declared_version();
    bob.sync_declared_version();
    let bob_most_recent = bob.toolset().read().get_most_recent_ratchet_version();
    let alice_most_recent = alice.toolset().read().get_most_recent_ratchet_version();
    eprintln!("after failed round: alice most_recent={alice_most_recent} bob most_recent={bob_most_recent}");

    let (cx, b2a) = round_until_bob_commits(&alice, &bob);
    finish_round(&alice, &bob, cx, b2a);
    eprintln!(
        "after clean round: alice latest={} bob latest={} bob most_recent={}",
        alice.latest_usable_version(),
        bob.latest_usable_version(),
        bob.toolset().read().get_most_recent_ratchet_version()
    );
    assert_keys_agree(&alice, &bob);
}
