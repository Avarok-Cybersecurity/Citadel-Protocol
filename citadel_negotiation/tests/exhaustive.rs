//! §9.1 `exhaustive_two_party_small`: every interleaving, to a fixed depth, of the two users'
//! actions with the network's (deliver any in-flight frame, so any reordering; duplicate each
//! frame once; hold any frame back), over a three-value ordered setting, then run to rest and
//! check the invariants. Run for a locally applied setting and for the key profile, whose apply
//! is a key round the Loser verifies.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::Setting;
use citadel_types::crypto::SecurityLevel::{High, Reinforced, Standard};
use common::{profile, world, Tier};

const DEPTH: usize = 7;
const BUDGET: usize = 400;

/// The user actions still available on a path: each at most once.
#[derive(Copy, Clone, Default)]
struct Users {
    a_proposed: bool,
    b_proposed: bool,
    a_cancelled: bool,
    a_ticked: bool,
    b_ticked: bool,
}

fn explore<S: Setting>(w: World<S>, depth: usize, users: Users, values: &[S], leaves: &mut u64) {
    let mut moves: Vec<(Action<S>, Users)> = w
        .network_actions(true)
        .into_iter()
        .map(|a| (a, users))
        .collect();
    if !w.dropped {
        for v in values {
            if !users.a_proposed {
                moves.push((
                    Action::Request(Side::A, v.clone()),
                    Users {
                        a_proposed: true,
                        ..users
                    },
                ));
            }
            if !users.b_proposed {
                moves.push((
                    Action::Request(Side::B, v.clone()),
                    Users {
                        b_proposed: true,
                        ..users
                    },
                ));
            }
        }
        if users.a_proposed && !users.a_cancelled {
            moves.push((
                Action::Cancel(Side::A),
                Users {
                    a_cancelled: true,
                    ..users
                },
            ));
        }
        if !users.a_ticked && w.party(Side::A).neg.next_wake().is_some() {
            moves.push((
                Action::Tick(Side::A),
                Users {
                    a_ticked: true,
                    ..users
                },
            ));
        }
        if !users.b_ticked && w.party(Side::B).neg.next_wake().is_some() {
            moves.push((
                Action::Tick(Side::B),
                Users {
                    b_ticked: true,
                    ..users
                },
            ));
        }
    }
    if depth == 0 || moves.is_empty() {
        let mut rest = w.clone();
        let verdict = rest
            .run_to_quiescence(BUDGET)
            .and_then(|()| rest.check(true));
        if let Err(error) = verdict {
            panic!("{error}\nschedule start: {w:?}\nat rest: {rest:?}");
        }
        *leaves += 1;
        return;
    }
    for (action, next_users) in moves {
        let mut next = w.clone();
        next.apply(action);
        explore(next, depth - 1, next_users, values, leaves);
    }
}

#[test]
fn exhaustive_two_party_small() {
    let mut leaves = 0;
    explore(
        world(Tier(0), true),
        DEPTH,
        Users::default(),
        &[Tier(0), Tier(1), Tier(2)],
        &mut leaves,
    );
    eprintln!("local setting: {leaves} schedules");
    assert!(leaves > 10_000, "the enumeration ran ({leaves} schedules)");
}

#[test]
fn exhaustive_two_party_small_key_profile() {
    let mut leaves = 0;
    let values = [profile(Standard), profile(Reinforced), profile(High)];
    explore(
        world(profile(Standard), true),
        DEPTH,
        Users::default(),
        &values,
        &mut leaves,
    );
    eprintln!("key profile: {leaves} schedules");
    assert!(leaves > 10_000, "the enumeration ran ({leaves} schedules)");
}
