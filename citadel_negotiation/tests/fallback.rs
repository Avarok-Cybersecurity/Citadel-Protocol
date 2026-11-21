//! §6: the deliberate drop, with a reason and a single redialer.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{
    Command, Input, Millis, NegotiationState, Negotiator, PeerSupport, RenegotiationReason, Setting,
};
use citadel_types::crypto::{CryptoParameters, KemAlgorithm, SecurityLevel};
use common::{config, profile, states, world, B};

fn fell_back(w: &World<KeyProfile>, side: Side) -> Option<(RenegotiationReason, bool)> {
    states(w, side).iter().find_map(|s| match s {
        NegotiationState::FellBack {
            reason, we_redial, ..
        } => Some((*reason, *we_redial)),
        _ => None,
    })
}

#[test]
fn a_legacy_peer_takes_the_handshake_and_the_requester_redials() {
    // B is the Loser by CID, yet it is the only one that can act toward a legacy peer.
    let mut b = Negotiator::new(config(
        B,
        profile(SecurityLevel::Standard),
        profile(SecurityLevel::Standard),
        PeerSupport::Legacy,
    ))
    .expect("config");
    let out = b.step(Millis(0), Input::Request(profile(SecurityLevel::Extreme)));
    assert!(
        !out.iter().any(|c| matches!(c, Command::Send(_))),
        "nothing is sent to a legacy peer"
    );
    assert!(out.contains(&Command::Drop {
        reason: RenegotiationReason::PeerLegacy,
        next: profile(SecurityLevel::Extreme)
    }));
    assert!(out.iter().any(|c| matches!(c, Command::Report(e) if e.state == NegotiationState::FellBack {
        reason: RenegotiationReason::PeerLegacy, next: profile(SecurityLevel::Extreme), we_redial: true })));
}

#[test]
fn a_kem_change_is_agreed_in_band_then_taken_by_handshake() {
    let params = CryptoParameters {
        kem_algorithm: KemAlgorithm::MlKem1024Fips203,
        ..common::BASE_PARAMS
    };
    let target = KeyProfile::new(SecurityLevel::High, params);
    assert_ne!(params.kem_algorithm, common::BASE_PARAMS.kem_algorithm);
    let mut w = world(profile(SecurityLevel::Standard), true);
    w.apply(Action::Request(Side::B, target));
    w.run_to_quiescence(100).expect("quiescent");
    w.check(true).expect("invariants");
    assert!(w.dropped);
    let reason = RenegotiationReason::HandshakeRequired(KeyProfile::ID);
    assert_eq!(
        fell_back(&w, Side::A),
        Some((reason, true)),
        "the Leader redials"
    );
    assert_eq!(fell_back(&w, Side::B), Some((reason, false)));
    assert_eq!(w.version, 0, "no key round is run for a KEM change");
}
