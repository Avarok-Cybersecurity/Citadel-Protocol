//! Which stages a node signs: none without an identity port or an identity key, and every stage
//! with one, whichever side it is.

use super::super::*;
use super::{checked, context, initiator_body, port, Key, Store, ALICE, BOB};

#[test]
fn a_node_without_an_identity_port_neither_signs_nor_checks() {
    let auth = Key::new(1).sign(&initiator_body());
    let verdict = checked(None, BOB, ALICE, Some(&auth), &initiator_body());
    assert_eq!(verdict, Ok(PeerKexIdentity::Unsigned));
    let stage = KexStage::Initiator { stage0: [1; 32] };
    assert_eq!(sign_stage(None, ALICE, &context(), &stage), None);
}

#[test]
fn a_legacy_account_signs_nothing() {
    let (_, legacy) = port(Store::default());
    let stage = KexStage::Initiator { stage0: [1; 32] };
    assert_eq!(sign_stage(Some(&legacy), ALICE, &context(), &stage), None);
}

#[test]
fn an_account_with_a_key_signs_as_responder_and_as_initiator() {
    let (_, signer) = port(Store {
        key: Some(Key::new(3)),
        ..Default::default()
    });
    let responder = KexStage::Responder {
        stage0: [1; 32],
        stage1: [2; 32],
    };
    let initiator = KexStage::Initiator { stage0: [1; 32] };
    assert!(sign_stage(Some(&signer), BOB, &context(), &responder).is_some());
    assert!(sign_stage(Some(&signer), ALICE, &context(), &initiator).is_some());
}
