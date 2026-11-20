//! A key profile names how many ratchet layers both sides build. A node never agrees to more
//! than its maximum security level: a peer's proposal above it is refused as unsupported, never
//! accepted or applied, and so is a local request above it.

mod common;

use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{
    encode_value, Command, Envelope, Epoch, Frame, Input, Millis, NegotiationState, Negotiator,
    NegotiatorConfig, PeerSupport, RejectReason, Setting,
};
use citadel_types::crypto::{MaxSecurityLevel, SecurityLevel};
use common::{policy, profile, A, B};

const NOW: Millis = Millis(0);

fn bounded(local: u64, maximum: SecurityLevel) -> Negotiator<KeyProfile> {
    Negotiator::new(NegotiatorConfig {
        local,
        peer: if local == A { B } else { A },
        initial: profile(SecurityLevel::Standard),
        minimum: profile(SecurityLevel::Standard),
        bound: MaxSecurityLevel::new(maximum).unwrap(),
        support: PeerSupport::InBand,
        policy: policy(),
    })
    .expect("config")
}

fn proposal(level: SecurityLevel) -> Input<KeyProfile> {
    Input::Recv(Envelope {
        setting: KeyProfile::ID,
        n: 0,
        frame: Frame::Propose {
            from_epoch: Epoch(0),
            seq: 0,
            value: encode_value(&profile(level)).unwrap(),
        },
    })
}

fn answer(out: &[Command<KeyProfile>]) -> Option<&Frame> {
    out.iter().find_map(|command| match command {
        Command::Send(envelope) => Some(&envelope.frame),
        _ => None,
    })
}

fn applies(out: &[Command<KeyProfile>]) -> bool {
    out.iter().any(|command| {
        matches!(
            command,
            Command::ApplyKeyEpoch { .. } | Command::ApplyLocal { .. }
        )
    })
}

#[test]
fn a_proposal_above_the_maximum_is_refused_as_unsupported() {
    for side in [A, B] {
        let mut negotiator = bounded(side, SecurityLevel::Extreme);
        let out = negotiator.step(NOW, proposal(SecurityLevel::Custom(254)));
        assert!(
            matches!(
                answer(&out),
                Some(Frame::Reject {
                    reason: RejectReason::Unsupported,
                    ..
                })
            ),
            "{out:?}"
        );
        assert!(!applies(&out));
        assert_eq!(
            negotiator.current(),
            (Epoch(0), &profile(SecurityLevel::Standard))
        );
    }
}

#[test]
fn a_proposal_at_the_maximum_is_accepted() {
    let mut negotiator = bounded(B, SecurityLevel::Extreme);
    let out = negotiator.step(NOW, proposal(SecurityLevel::Extreme));
    assert!(
        matches!(answer(&out), Some(Frame::Accept { .. })),
        "{out:?}"
    );
}

#[test]
fn a_local_request_above_the_maximum_is_refused_unsent() {
    let mut negotiator = bounded(A, SecurityLevel::High);
    let out = negotiator.step(NOW, Input::Request(profile(SecurityLevel::Ultra)));
    assert!(answer(&out).is_none(), "{out:?}");
    assert!(out.iter().any(|command| matches!(
        command,
        Command::Report(event) if matches!(
            event.state,
            NegotiationState::Rejected { reason: RejectReason::Unsupported, .. }
        )
    )));
}
