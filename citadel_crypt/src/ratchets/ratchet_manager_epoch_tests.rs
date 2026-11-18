//! Steered key-epoch rounds between two real ratchet managers (§5.1-5.2).
//!
//! Each test drives the managers' own wire. The relay from Bob to Alice can be held, which is how
//! a plain rekey is made to cross a steered round deterministically: no sleeps decide an order.

use super::tests::{setup_endpoint_containers, TestRatchetManager, TEST_PSKS};
use super::{RatchetManager, RatchetManagerSink, RatchetManagerStream, RatchetMessage};
use crate::ratchets::key_epoch::{EpochRoundGate, GateFuture, KeyEpochTag};
use crate::ratchets::stacked::StackedRatchet;
use crate::ratchets::Ratchet;
use citadel_io::tokio;
use citadel_io::tokio::sync::{mpsc, watch};
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{Epoch, KeyExchangeOutcome};
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

type Manager = TestRatchetManager<StackedRatchet, ()>;
type Sink = Box<dyn RatchetManagerSink<(), Error = futures::channel::mpsc::SendError>>;
type Stream = Box<dyn RatchetManagerStream<()>>;

/// Bounds every wait, so a round that never ends fails the test instead of hanging it.
const BOUND: Duration = Duration::from_secs(30);

/// A gate that answers with a fixed verdict and reports every round it was asked about.
struct Verdict {
    admit: bool,
    asked: mpsc::UnboundedSender<KeyEpochTag>,
}

impl EpochRoundGate for Verdict {
    fn admit(&self, tag: KeyEpochTag, _current_version: u32) -> GateFuture {
        let _ = self.asked.send(tag);
        let admit = self.admit;
        Box::pin(async move { admit })
    }
}

struct Pair {
    alice: Manager,
    bob: Manager,
    /// While `false`, Bob's frames wait in the relay before reaching Alice.
    bob_to_alice_open: watch::Sender<bool>,
    bob_asked: mpsc::UnboundedReceiver<KeyEpochTag>,
}

/// Alice (CID 10) is the negotiation Leader and the contention initiator, so in a crossing the
/// peer's plain rekey wins: the one arrangement in which a steered round can be superseded.
fn pair(level: SecurityLevel, bob_admits: bool) -> Pair {
    let (alice_container, bob_container) = setup_endpoint_containers::<StackedRatchet>(
        level,
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem,
    );
    let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
    let (tx_bob, mut from_bob) = futures::channel::mpsc::unbounded::<RatchetMessage<()>>();
    let (to_alice, rx_alice) = futures::channel::mpsc::unbounded();
    let (bob_to_alice_open, mut open) = watch::channel(true);
    drop(tokio::spawn(async move {
        while let Some(message) = from_bob.next().await {
            if open.wait_for(|open| *open).await.is_err() {
                return;
            }
            if to_alice.unbounded_send(message).is_err() {
                return;
            }
        }
    }));
    let alice = RatchetManager::new(
        Box::new(tx_alice) as Sink,
        Box::new(rx_alice) as Stream,
        alice_container,
        TEST_PSKS,
    );
    let bob = RatchetManager::new(
        Box::new(tx_bob) as Sink,
        Box::new(rx_bob) as Stream,
        bob_container,
        TEST_PSKS,
    );
    let (asked, bob_asked) = mpsc::unbounded_channel();
    bob.set_epoch_gate(Arc::new(Verdict {
        admit: bob_admits,
        asked,
    }));
    Pair {
        alice,
        bob,
        bob_to_alice_open,
        bob_asked,
    }
}

fn tag(epoch: u32, level: SecurityLevel) -> KeyEpochTag {
    KeyEpochTag {
        epoch: Epoch(epoch),
        profile: KeyProfile::new(
            level,
            EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem,
        ),
    }
}

async fn outcome(manager: &Manager, tag: KeyEpochTag, from: u32) -> KeyExchangeOutcome {
    tokio::time::timeout(BOUND, manager.await_epoch_round(tag, from))
        .await
        .expect("the round ends")
}

fn layers(manager: &Manager) -> usize {
    manager.get_ratchet(None).unwrap().message_ratchet_count()
}

/// A message Alice protects at `level` under her newest version opens at Bob's.
fn assert_opens_at(pair: &Pair, level: SecurityLevel) {
    let mut packet = b"header--payload".to_vec();
    let alice = pair.alice.get_ratchet(None).unwrap();
    alice
        .protect_message_packet(Some(level), 8, &mut packet)
        .unwrap();
    let bob = pair.bob.get_ratchet(None).unwrap();
    assert_eq!(alice.version(), bob.version());
    let (header, body) = packet.split_at(8);
    let mut body = bytes::BytesMut::from(body);
    bob.validate_message_packet_in_place_split(Some(level), header, &mut body)
        .unwrap();
    assert_eq!(&body[..], b"payload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_steered_round_builds_the_negotiated_profile_on_both_ends() {
    citadel_logging::setup_log();
    let mut pair = pair(SecurityLevel::Reinforced, true);
    let raise = tag(1, SecurityLevel::Extreme);
    let from = pair.alice.trigger_rekey_with_profile(raise).await.unwrap();
    assert_eq!(pair.bob_asked.recv().await, Some(raise));
    let applied = KeyExchangeOutcome::Applied { version: from + 1 };
    assert_eq!(outcome(&pair.alice, raise, from).await, applied);
    assert_eq!(outcome(&pair.bob, raise, from).await, applied);
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (5, 5));
    assert_eq!(pair.bob.epoch_of(from + 1), Some(raise));
    assert_opens_at(&pair, SecurityLevel::Extreme);

    // A plain rekey after the epoch keeps its layers.
    tokio::time::timeout(BOUND, pair.alice.trigger_rekey(true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (5, 5));
    assert_opens_at(&pair, SecurityLevel::Extreme);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lowered_profile_truncates_the_layers() {
    citadel_logging::setup_log();
    let pair = pair(SecurityLevel::Extreme, true);
    let lower = tag(1, SecurityLevel::Standard);
    let from = pair.alice.trigger_rekey_with_profile(lower).await.unwrap();
    let applied = KeyExchangeOutcome::Applied { version: from + 1 };
    assert_eq!(outcome(&pair.bob, lower, from).await, applied);
    assert_eq!(outcome(&pair.alice, lower, from).await, applied);
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (1, 1));
    assert_opens_at(&pair, SecurityLevel::Standard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_round_this_side_did_not_agree_to_is_refused() {
    citadel_logging::setup_log();
    let mut pair = pair(SecurityLevel::Reinforced, false);
    let raise = tag(1, SecurityLevel::Extreme);
    let from = pair.alice.trigger_rekey_with_profile(raise).await.unwrap();
    assert_eq!(pair.bob_asked.recv().await, Some(raise));
    assert!(matches!(
        outcome(&pair.alice, raise, from).await,
        KeyExchangeOutcome::Refused(_)
    ));
    let current = pair.alice.session_crypto_state.latest_usable_version();
    assert_eq!(current, from, "a refused round builds nothing");
    assert_eq!(pair.bob.session_crypto_state.latest_usable_version(), from);

    // The pair is not wedged: a plain rekey still runs, at the old layer count.
    tokio::time::timeout(BOUND, pair.alice.trigger_rekey(true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (2, 2));
    assert_opens_at(&pair, SecurityLevel::Reinforced);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_manager_without_a_gate_refuses_every_steered_round() {
    citadel_logging::setup_log();
    let (alice_container, bob_container) = setup_endpoint_containers::<StackedRatchet>(
        SecurityLevel::Standard,
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem,
    );
    let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
    let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();
    let alice: Manager = RatchetManager::new(
        Box::new(tx_alice) as Sink,
        Box::new(rx_alice) as Stream,
        alice_container,
        TEST_PSKS,
    );
    let _bob: Manager = RatchetManager::new(
        Box::new(tx_bob) as Sink,
        Box::new(rx_bob) as Stream,
        bob_container,
        TEST_PSKS,
    );
    let raise = tag(1, SecurityLevel::High);
    let from = alice.trigger_rekey_with_profile(raise).await.unwrap();
    assert!(matches!(
        outcome(&alice, raise, from).await,
        KeyExchangeOutcome::Refused(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_rekey_that_wins_the_crossing_supersedes_the_round() {
    citadel_logging::setup_log();
    let mut pair = pair(SecurityLevel::Reinforced, true);
    let raise = tag(1, SecurityLevel::Extreme);

    // Bob's plain AliceToBob leaves first and is held; Alice's steered one then reaches Bob,
    // who has his own round in flight. Only then do Bob's frames reach Alice.
    let _ = pair.bob_to_alice_open.send_replace(false);
    pair.bob.trigger_rekey(false).await.unwrap();
    let from = pair.alice.trigger_rekey_with_profile(raise).await.unwrap();
    assert_eq!(pair.bob_asked.recv().await, Some(raise));
    let _ = pair.bob_to_alice_open.send_replace(true);

    let superseded = KeyExchangeOutcome::Superseded { version: from + 1 };
    assert_eq!(outcome(&pair.alice, raise, from).await, superseded);
    assert_eq!(outcome(&pair.bob, raise, from).await, superseded);
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (2, 2));

    // The Leader re-issues from the version the plain rekey took, and the epoch applies.
    let again = pair.alice.trigger_rekey_with_profile(raise).await.unwrap();
    assert_eq!(again, from + 1);
    let applied = KeyExchangeOutcome::Applied { version: again + 1 };
    assert_eq!(outcome(&pair.alice, raise, again).await, applied);
    assert_eq!(outcome(&pair.bob, raise, again).await, applied);
    assert_eq!((layers(&pair.alice), layers(&pair.bob)), (5, 5));
    assert_opens_at(&pair, SecurityLevel::Extreme);
}
