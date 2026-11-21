//! Random schedules (§11.1 `schedule_proptest`): whatever the network, the peer and the user do,
//! once the network comes back and nothing is suspended, the pair rests either both up on the
//! same incarnation and settings or both closed, and every per-step invariant held on the way.

mod common;

use citadel_link::schedule::{Action, Side};
use citadel_link::LossCause;
use citadel_types::crypto::SecurityLevel;
use common::*;
use proptest::prelude::*;

fn side() -> impl Strategy<Value = Side> {
    prop_oneof![Just(Side::A), Just(Side::B)]
}

fn level() -> impl Strategy<Value = SecurityLevel> {
    (0u8..=4).prop_map(SecurityLevel::from)
}

fn action() -> BoxedStrategy<Action> {
    prop_oneof![
        3 => Just(Action::Lose(LossCause::Transient)),
        1 => Just(Action::Lose(LossCause::RouteLost)),
        1 => side().prop_map(Action::NatChange),
        1 => side().prop_map(Action::Interface),
        2 => level().prop_map(|l| Action::Agree(settings(l))),
        1 => level().prop_map(|l| Action::Agree(other_kem(l))),
        1 => (level(), level()).prop_map(|(a, b)| Action::AgreeBoth(settings(a), settings(b))),
        1 => side().prop_map(Action::Suspend),
        1 => side().prop_map(Action::Resume),
        1 => Just(Action::ServerDown),
        1 => Just(Action::ServerUp),
        1 => Just(Action::DirectDown),
        1 => Just(Action::DirectUp),
        2 => side().prop_map(|s| Action::Resolve(s, 0, false)),
        1 => side().prop_map(Action::Tick),
        1 => side().prop_map(Action::Reachable),
        1 => side().prop_map(Action::Shutdown),
    ]
    .boxed()
}

fn caps() -> impl Strategy<Value = citadel_link::PeerCaps> {
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(in_band, reseal, reattach)| {
        citadel_link::PeerCaps {
            in_band,
            reseal,
            reattach,
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn every_schedule_rests_consistent(caps in caps(), actions in prop::collection::vec(action(), 0..8)) {
        let mut w = up(caps);
        for action in actions {
            w.apply(action);
            if let Err(e) = w.run_to_quiescence(5_000) {
                return Err(TestCaseError::fail(e));
            }
        }
        for heal in [Action::ServerUp, Action::DirectUp, Action::Resume(Side::A), Action::Resume(Side::B)] {
            w.apply(heal);
        }
        if let Err(e) = w.run_to_quiescence(5_000) {
            return Err(TestCaseError::fail(e));
        }
        prop_assert!(w.check().is_ok(), "{:?}\nA {:?}\nB {:?}", w.check(), w.a.commands, w.b.commands);
    }
}
