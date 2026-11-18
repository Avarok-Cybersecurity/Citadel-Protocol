//! §9.1 `schedule_proptest`: 10,000 random schedules over random settings, up to four requests per
//! side, with arbitrary delay, duplication, reordering and loss (loss ends in a timeout). The
//! invariants are `exhaustive_two_party_small`'s; a failure shrinks to a minimal schedule.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::settings::{KeyProfile, MediaTransport, MediaTransportKind, TransferMode};
use citadel_types::crypto::{CryptoParameters, KemAlgorithm, SecurityLevel};
use common::{world, Tier};
use proptest::prelude::*;

const MAX_REQUESTS: usize = 4;
const BUDGET: usize = 2_000;

/// One scheduling decision: which kind of thing happens, and a number to pick among them.
type Seed = (u8, u8);

fn run<S: common::WidestBound>(
    initial: S,
    values: &[S],
    seeds: &[Seed],
    ordered: bool,
) -> Result<(), TestCaseError> {
    let mut w: World<S> = world(initial, ordered);
    let mut requests = [0usize; 2];
    for &(kind, pick) in seeds {
        let side = if pick % 2 == 0 { Side::A } else { Side::B };
        let slot = usize::from(side == Side::B);
        let action = match kind % 32 {
            0..=4 if requests[slot] < MAX_REQUESTS => {
                requests[slot] += 1;
                Action::Request(side, values[usize::from(pick / 2) % values.len()].clone())
            }
            5 => Action::Cancel(side),
            6 => Action::Tick(side),
            7 if !w.net.is_empty() => Action::Lose(usize::from(pick) % w.net.len()),
            _ => {
                let network = w.network_actions(true);
                if network.is_empty() {
                    continue;
                }
                network[usize::from(pick) % network.len()].clone()
            }
        };
        w.apply(action);
    }
    let start = w.clone();
    let verdict = w.run_to_quiescence(BUDGET).and_then(|()| w.check(ordered));
    prop_assert!(
        verdict.is_ok(),
        "{:?}\nbefore rest: {:?}\nat rest: {:?}",
        verdict,
        start,
        w
    );
    Ok(())
}

fn profiles() -> Vec<KeyProfile> {
    let wider = CryptoParameters {
        kem_algorithm: KemAlgorithm::MlKem1024Fips203,
        ..CryptoParameters::default()
    };
    let mut values: Vec<KeyProfile> = (0..=4)
        .map(|l| KeyProfile::new(SecurityLevel::from(l), CryptoParameters::default()))
        .collect();
    values.push(KeyProfile::new(SecurityLevel::Extreme, wider)); // a KEM change: the handshake path
    values
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn schedule_proptest(setting in 0u8..4, initial in 0usize..3, seeds in prop::collection::vec(any::<Seed>(), 1..60)) {
        match setting {
            0 => run(Tier(initial as u8), &[Tier(0), Tier(1), Tier(2)], &seeds, true)?,
            1 => {
                let values = profiles();
                run(values[initial], &values, &seeds, true)?
            }
            2 => {
                let kinds = [MediaTransportKind::Unreliable, MediaTransportKind::Reliable];
                let values = kinds.map(|kind| MediaTransport { kind });
                run(values[initial % 2], &values, &seeds, true)?
            }
            _ => {
                let values = [TransferMode::Async, TransferMode::P2p];
                run(values[initial % 2], &values, &seeds, false)?
            }
        }
    }
}
