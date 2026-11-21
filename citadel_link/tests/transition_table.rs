//! The §3.2 table as an oracle: every state × every input, the state reached and the commands
//! issued. Anything not in the table is a no-op in that state, and the test asserts that too.

mod common;
#[path = "table/fixtures.rs"]
mod fixtures;
#[path = "table/kinds.rs"]
mod kinds;
#[path = "table/oracle.rs"]
mod oracle;

use fixtures::{fixture, inputs};
use kinds::{kind_of, names, StateKind, INPUTS, STATES};
use oracle::expected;

#[test]
fn every_state_and_every_input_follow_the_table() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for state in STATES {
        for (input_index, input_kind) in INPUTS.iter().enumerate() {
            let mut fx = fixture(state);
            assert_eq!(kind_of(fx.core.state()), state, "fixture for {state:?}");
            let input = inputs(&fx).swap_remove(input_index);
            if matches!(input, citadel_link::LinkInput::Tick) {
                fx.now = fx.core.next_wake().unwrap_or(fx.now).max(fx.now);
            }
            let commands = fx.core.step(fx.now, input);
            let got = (kind_of(fx.core.state()), names(&commands));
            let want = expected(state, *input_kind);
            if got.0 != want.0 || got.1 != want.1 {
                failures.push(format!(
                    "{state:?} + {input_kind:?}: got {got:?}, want {want:?}"
                ));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, STATES.len() * INPUTS.len());
    assert!(
        failures.is_empty(),
        "{} rows differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn nothing_is_issued_after_closed() {
    let fx = fixture(StateKind::Closed);
    for input in inputs(&fx) {
        let mut core = fx.core.clone();
        assert!(core.step(fx.now, input).is_empty());
        assert_eq!(kind_of(core.state()), StateKind::Closed);
    }
}

#[test]
fn a_stale_incarnation_or_attempt_is_ignored_in_every_state() {
    use citadel_link::{Incarnation, LinkInput, LossCause, SealFailure};
    for state in STATES {
        let fx = fixture(state);
        let stale = Incarnation {
            connection: fx.inc.connection,
            n: 99,
        };
        let inputs = [
            LinkInput::Sealed { incarnation: stale },
            LinkInput::SealFailed {
                incarnation: stale,
                failure: SealFailure::Handshake,
            },
            LinkInput::LinkLost {
                incarnation: stale,
                cause: LossCause::Transient,
            },
            LinkInput::MeetFailed {
                attempt: 99,
                failure: citadel_link::StageFailure::Signalling,
            },
        ];
        for input in inputs {
            let mut core = fx.core.clone();
            let before = core.state().clone();
            let commands = core.step(fx.now, input.clone());
            assert!(
                names(&commands).is_empty(),
                "{state:?} + {input:?}: {commands:?}"
            );
            assert_eq!(*core.state(), before, "{state:?} + {input:?}");
        }
    }
}
