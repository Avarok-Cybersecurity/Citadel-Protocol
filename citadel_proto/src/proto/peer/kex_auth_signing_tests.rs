//! Which stages a node signs: none without an identity port or an identity key, an initiator's
//! always, and a responder's only toward an initiator at or above the gate.

use super::super::*;
use super::{checked, context, initiator_body, port, Key, Store, ALICE, BOB};
use crate::constants::PROTOCOL_VERSION;
use embedded_semver::Semver;

#[test]
fn a_node_without_an_identity_port_neither_signs_nor_checks() {
    let auth = Key::new(1).sign(&initiator_body());
    let verdict = checked(None, BOB, ALICE, Some(&auth), &initiator_body());
    assert_eq!(verdict, Ok(PeerKexIdentity::Unsigned));
    let stage = KexStage::Initiator { stage0: [1; 32] };
    assert_eq!(sign_stage(None, ALICE, &context(), &stage, None), None);
}

#[test]
fn a_legacy_account_signs_nothing() {
    let (_, legacy) = port(Store::default());
    let stage = KexStage::Initiator { stage0: [1; 32] };
    let version = Some(*PROTOCOL_VERSION);
    assert_eq!(
        sign_stage(Some(&legacy), ALICE, &context(), &stage, version),
        None
    );
}

#[test]
fn a_responder_signs_only_toward_an_initiator_at_the_gate_and_an_initiator_always() {
    let (_, signer) = port(Store {
        key: Some(Key::new(3)),
        ..Default::default()
    });
    let older = Some(Semver::new(0, 12, 3).to_u32().unwrap());
    let responder = KexStage::Responder {
        stage0: [1; 32],
        stage1: [2; 32],
    };
    let initiator = KexStage::Initiator { stage0: [1; 32] };
    assert!(sign_stage(Some(&signer), BOB, &context(), &responder, older).is_none());
    assert!(sign_stage(Some(&signer), BOB, &context(), &responder, None).is_none());
    let current = Some(*PROTOCOL_VERSION);
    assert!(sign_stage(Some(&signer), BOB, &context(), &responder, current).is_some());
    assert!(sign_stage(Some(&signer), ALICE, &context(), &initiator, None).is_some());
}
