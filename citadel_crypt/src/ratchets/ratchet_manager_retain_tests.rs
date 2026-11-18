//! A payload a rekey trigger could not send stays with the caller when the trigger fails, so the
//! messenger's Perfect-mode drainer can put it back at the front of its queue (§ ordered ids).

use super::tests::create_ratchet_managers;
use super::RekeyState;
use crate::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_trigger_leaves_the_payload_with_the_caller() {
    citadel_logging::setup_log();
    let (alice, bob) = create_ratchet_managers::<StackedRatchet, u64>();
    // Shutdown ends the rekey process once inbound traffic has been quiet for two seconds.
    let _ = (alice.shutdown(), bob.shutdown());
    tokio::time::timeout(Duration::from_secs(30), async {
        while alice.state() != RekeyState::Halted {
            tokio::time::sleep(Duration::from_millis(50)).await; // polls a condition; orders nothing
        }
    })
    .await
    .expect("the rekey process halts once its peer is gone");

    let mut payload = Some(7u64);
    let result = alice
        .trigger_rekey_retaining_payload(&mut payload, false)
        .await;
    let Err(err) = result else {
        panic!("a halted manager starts no round");
    };
    assert_eq!(err.code(), citadel_io::ErrorCode::RekeyHalted);
    assert_eq!(payload, Some(7), "the unsent payload is still the caller's");
}
