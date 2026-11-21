//! The retired recovery-code slots: reading one is refused by name, and the variants after them
//! keep their encoding.

use super::*;
use citadel_io::decode::deserialize;

fn index(value: &impl Serialize) -> Vec<u8> {
    bincode::serialize(value).unwrap()
}

fn refused<T: std::fmt::Debug + for<'de> Deserialize<'de>>(slot: u32) {
    let err = deserialize::<T>(&slot.to_le_bytes()).unwrap_err();
    assert!(err.to_string().contains(RECOVERY_CODES_RETIRED), "{err}");
}

/// Control: drop `FactorKind::RetiredRecoveryCode`, so `RecoveryPhrase` shifts into its slot, and
/// slot 2 reads as the phrase: this fails.
#[test]
fn the_retired_slots_are_refused_and_their_successors_keep_theirs() {
    refused::<FactorKind>(2);
    assert_eq!(index(&FactorKind::RecoveryPhrase), 3u32.to_le_bytes());

    refused::<SignInManagementOp>(5);
    assert_eq!(index(&SignInManagementOp::SetPassword), 6u32.to_le_bytes());

    refused::<SignInManagementOutcome>(5);
    assert_eq!(
        index(&SignInManagementOutcome::PasswordSet),
        6u32.to_le_bytes()
    );
}
