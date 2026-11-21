//! A rekey round has one deadline, counted from when this side joined it.
//!
//! The wait for the round's next message used to restart its 60 s timeout on every message
//! received, including the application messages that ride the same stream. So a round whose
//! peer had stopped answering never timed out while the peer kept sending messages, and no
//! later round could start. The test leaves Alice waiting as the Loser of a round whose Leader
//! never answers, while messages keep arriving every 30 s.

use super::tests::{setup_endpoint_containers, TestRatchetManager, TEST_PSKS};
use super::{RatchetManager, RatchetManagerSink, RatchetManagerStream, RatchetMessage, RekeyRole};
use crate::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use futures::channel::mpsc::{unbounded, SendError, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use std::time::Duration;

type Manager = TestRatchetManager<StackedRatchet, u64>;
type Pipe = (
    UnboundedSender<RatchetMessage<u64>>,
    UnboundedReceiver<RatchetMessage<u64>>,
);

fn manager(
    container: crate::endpoint_crypto_container::PeerSessionCrypto<StackedRatchet>,
    out: UnboundedSender<RatchetMessage<u64>>,
    inbound: UnboundedReceiver<RatchetMessage<u64>>,
) -> Manager {
    RatchetManager::new(
        Box::new(out) as Box<dyn RatchetManagerSink<u64, Error = SendError>>,
        Box::new(inbound) as Box<dyn RatchetManagerStream<u64>>,
        container,
        TEST_PSKS,
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_stuck_round_ends_at_its_deadline_despite_steady_messages() {
    citadel_logging::setup_log();
    let (alice_container, bob_container) = setup_endpoint_containers::<StackedRatchet>(
        SecurityLevel::Standard,
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem768Fips203,
    );
    // Nothing Alice sends reaches Bob: her answer to his round is lost.
    let (alice_out, _alice_sent): Pipe = unbounded();
    let (to_alice, alice_in): Pipe = unbounded();
    let (bob_out, mut bob_sent): Pipe = unbounded();
    let (_to_bob, bob_in): Pipe = unbounded();
    let alice = manager(alice_container, alice_out, alice_in);
    let bob = manager(bob_container, bob_out, bob_in);
    let mut alice_rounds = alice.take_on_rekey_finished_event_listener().unwrap();

    bob.trigger_rekey(false).await.unwrap();
    let opening = bob_sent.next().await.expect("Bob opened no round");
    assert!(matches!(opening, RatchetMessage::AliceToBob { .. }));
    to_alice.unbounded_send(opening).unwrap();
    while alice.role() == RekeyRole::Idle {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let chatter = to_alice.clone();
    let _chatter = tokio::spawn(async move {
        for message in 0..40u64 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if chatter
                .unbounded_send(RatchetMessage::JustMessage(message))
                .is_err()
            {
                return;
            }
        }
    });

    // Paused clock: virtual time only. Ten minutes is far past the round's 60 s deadline,
    // and far short of the twenty minutes of chatter that kept the old timeout from firing.
    let ended = tokio::time::timeout(Duration::from_secs(600), alice_rounds.recv()).await;
    assert!(
        matches!(ended, Ok(Some(None))),
        "the stuck round was still open after 600 s of steady messages: {ended:?}"
    );
    assert_eq!(alice.role(), RekeyRole::Idle);
}
