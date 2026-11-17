//! §4.1: frames from an epoch already left, or from one not yet reached.

mod common;

use citadel_negotiation::{
    encode_value, value_digest, ApplyEvidence, Command, Envelope, Epoch, Frame, Input, Millis,
    NegotiationState, Negotiator, PeerSupport, RejectReason, RenegotiationReason, Setting,
};
use common::{config, Tier, A, B};

const NOW: Millis = Millis(0);

fn envelope(n: u64, frame: Frame) -> Input<Tier> {
    Input::Recv(Envelope {
        setting: Tier::ID,
        n,
        frame,
    })
}

/// B, driven by hand the way a shell drives it, agrees A's Tier(1) and reaches epoch 1.
fn b_at_epoch_one() -> Negotiator<Tier> {
    let mut b = Negotiator::new(config(B, Tier(0), Tier(0), PeerSupport::InBand)).expect("config");
    let bytes = encode_value(&Tier(1)).expect("encode");
    b.step(
        NOW,
        envelope(
            0,
            Frame::Propose {
                from_epoch: Epoch(0),
                seq: 0,
                value: bytes.clone(),
            },
        ),
    );
    b.step(
        NOW,
        Input::LocalOutcome {
            epoch: Epoch(1),
            result: Ok(()),
        },
    );
    let evidence = ApplyEvidence {
        version: None,
        digest: value_digest(&bytes),
    };
    b.step(
        NOW,
        envelope(
            1,
            Frame::Applied {
                epoch: Epoch(1),
                evidence,
            },
        ),
    );
    assert_eq!(b.current(), (Epoch(1), &Tier(1)));
    b
}

fn sends(commands: &[Command<Tier>]) -> Vec<Frame> {
    commands
        .iter()
        .filter_map(|c| match c {
            Command::Send(envelope) => Some(envelope.frame.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn stale_and_future_epochs() {
    let mut b = b_at_epoch_one();
    let stale = Frame::Propose {
        from_epoch: Epoch(0),
        seq: 1,
        value: encode_value(&Tier(2)).expect("encode"),
    };
    let out = b.step(NOW, envelope(2, stale));
    assert_eq!(
        sends(&out),
        vec![Frame::Reject {
            from_epoch: Epoch(0),
            seq: 1,
            reason: RejectReason::Stale
        }]
    );
    assert_eq!(
        b.current(),
        (Epoch(1), &Tier(1)),
        "a stale proposal changes nothing"
    );
    assert!(b.is_idle());

    // Envelopes are processed in send order, so a peer can never legitimately be ahead of us.
    let future = Frame::Propose {
        from_epoch: Epoch(2),
        seq: 0,
        value: encode_value(&Tier(2)).expect("encode"),
    };
    let out = b.step(NOW, envelope(3, future));
    assert!(out.contains(&Command::Drop {
        reason: RenegotiationReason::Desync,
        next: Tier(1)
    }));
    assert!(out.iter().any(|c| matches!(c, Command::Report(e) if matches!(e.state, NegotiationState::FellBack { reason: RenegotiationReason::Desync, .. }))));
    assert!(b.is_closed());
}

#[test]
fn a_late_answer_after_close_is_a_no_op() {
    let mut a = Negotiator::new(config(A, Tier(0), Tier(0), PeerSupport::InBand)).expect("config");
    a.step(NOW, Input::Request(Tier(2)));
    let wake = a.next_wake().expect("a proposal waits on its deadline");
    a.step(wake, Input::Tick);
    assert!(a.is_closed());
    let late = Frame::Accept {
        from_epoch: Epoch(0),
        seq: 0,
        agreed: encode_value(&Tier(2)).expect("encode"),
    };
    assert!(a.step(wake, envelope(0, late)).is_empty());
}

#[test]
fn a_duplicated_frame_is_handled_once() {
    // B refuses a lowering; its minimum then drops. A replay of the same proposal must not be
    // answered again, or B would apply a value A no longer proposes.
    let mut b = Negotiator::new(config(B, Tier(2), Tier(2), PeerSupport::InBand)).expect("config");
    let propose = Frame::Propose {
        from_epoch: Epoch(0),
        seq: 0,
        value: encode_value(&Tier(1)).expect("encode"),
    };
    let first = b.step(NOW, envelope(0, propose.clone()));
    assert_eq!(
        sends(&first),
        vec![Frame::Reject {
            from_epoch: Epoch(0),
            seq: 0,
            reason: RejectReason::BelowPolicy
        }]
    );
    b.step(NOW, Input::SetMinimum(Tier(0)));
    assert!(
        b.step(NOW, envelope(0, propose)).is_empty(),
        "the duplicate is a no-op"
    );
    assert!(b.is_idle());
}

#[test]
fn a_key_round_that_overtakes_its_proposal_is_held_not_refused() {
    use citadel_negotiation::settings::KeyProfile;
    use citadel_negotiation::RoundAdmission;
    use citadel_types::crypto::SecurityLevel::{Extreme, High, Standard};
    let mut b = Negotiator::new(config(
        B,
        common::profile(Standard),
        common::profile(Standard),
        PeerSupport::InBand,
    ))
    .expect("config");
    let extreme = common::profile(Extreme);
    assert_eq!(
        b.admit_key_round(Epoch(1), &extreme),
        RoundAdmission::Wait,
        "the Leader's Propose is still on its way"
    );
    let bytes = encode_value(&extreme).expect("encode");
    let propose = Frame::Propose {
        from_epoch: Epoch(0),
        seq: 0,
        value: bytes,
    };
    b.step(
        NOW,
        Input::Recv(Envelope {
            setting: KeyProfile::ID,
            n: 0,
            frame: propose,
        }),
    );
    assert_eq!(b.admit_key_round(Epoch(1), &extreme), RoundAdmission::Build);
    assert_eq!(
        b.admit_key_round(Epoch(1), &common::profile(High)),
        RoundAdmission::Refuse,
        "never a profile it did not agree"
    );
    assert_eq!(
        b.admit_key_round(Epoch(2), &extreme),
        RoundAdmission::Refuse
    );
}
