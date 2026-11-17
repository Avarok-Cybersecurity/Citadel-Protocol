//! The merge laws of every setting this crate ships (§3.1, §9.1 `merge_laws_<setting>`).

mod common;

use citadel_negotiation::settings::{KeyProfile, MediaTransport, MediaTransportKind, TransferMode};
use citadel_negotiation::Setting;
use citadel_types::crypto::SecurityLevel;
use proptest::prelude::*;

pub fn key_profile() -> impl Strategy<Value = KeyProfile> {
    (0u8..=8, prop::sample::select(common::suites()))
        .prop_map(|(level, params)| KeyProfile::new(SecurityLevel::from(level), params))
}

fn media() -> impl Strategy<Value = MediaTransport> {
    prop_oneof![
        Just(MediaTransportKind::Unreliable),
        Just(MediaTransportKind::Reliable)
    ]
    .prop_map(|kind| MediaTransport { kind })
}

fn transfer() -> impl Strategy<Value = TransferMode> {
    prop_oneof![Just(TransferMode::Async), Just(TransferMode::P2p)]
}

/// The laws of an ordered setting: a join semilattice whose join is never weaker than its inputs.
fn ordered_laws<S: Setting>(a: &S, b: &S, c: &S) -> Result<(), TestCaseError> {
    prop_assert_eq!(S::merge(a, b), S::merge(b, a), "commutative");
    prop_assert_eq!(
        S::merge(&S::merge(a, b), c),
        S::merge(a, &S::merge(b, c)),
        "associative"
    );
    prop_assert_eq!(S::merge(a, a), a.clone(), "idempotent");
    let joined = S::merge(a, b);
    prop_assert_eq!(
        S::is_downgrade(a, &joined),
        Some(false),
        "never weaker than the leader's"
    );
    prop_assert_eq!(
        S::is_downgrade(b, &joined),
        Some(false),
        "never weaker than the loser's"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn merge_laws_key_profile(a in key_profile(), b in key_profile(), c in key_profile()) {
        ordered_laws(&a, &b, &c)?;
    }

    #[test]
    fn merge_laws_media_transport(a in media(), b in media(), c in media()) {
        ordered_laws(&a, &b, &c)?;
    }

    /// Unordered (D4): the merge is the leader's value, which is associative and idempotent;
    /// it is not commutative, and does not need to be, because both ends agree who leads.
    #[test]
    fn merge_laws_transfer_mode(a in transfer(), b in transfer(), c in transfer()) {
        prop_assert_eq!(TransferMode::merge(&a, &b), a);
        prop_assert_eq!(TransferMode::merge(&TransferMode::merge(&a, &b), &c), TransferMode::merge(&a, &TransferMode::merge(&b, &c)));
        prop_assert_eq!(TransferMode::merge(&a, &a), a);
        prop_assert_eq!(TransferMode::is_downgrade(&a, &b), None);
    }
}
