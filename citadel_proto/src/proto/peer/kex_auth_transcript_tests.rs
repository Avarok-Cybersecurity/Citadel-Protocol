//! A relay between the peers, over real KEM transfers; what the transcript covers; and the
//! field on the wire.

use super::super::*;
use super::{checked, context, port, refused_with, Key, Store, ALICE, BOB};
use crate::proto::misc::session_security_settings::{
    default_session_security_settings, DEFAULT_SESSION_CRYPTO_PARAMS,
};
use crate::proto::peer::kex_path::KexPath;
use crate::proto::peer::p2p_seal_binding::tests::{opens, Constructor};
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::prelude::ConstructorOpts;
use citadel_types::crypto::{PreSharedKey, SecurityLevel};

fn opts() -> Vec<ConstructorOpts> {
    ConstructorOpts::new_vec_init(DEFAULT_SESSION_CRYPTO_PARAMS, SecurityLevel::Standard)
}

fn settings() -> SessionSecuritySettings {
    default_session_security_settings()
}

fn psks() -> Vec<Vec<u8>> {
    PreSharedKey::from("pair").as_ref().to_vec()
}

/// An initiator's Stage0 transfer as it goes on the wire, and its constructor.
fn stage0() -> (Constructor, Vec<u8>) {
    let alice = Constructor::new_alice(opts(), ALICE, 0).unwrap();
    let transfer = alice.stage0_alice().unwrap().serialize_to_vector().unwrap();
    (alice, transfer)
}

fn digest0(transfer: &[u8]) -> [u8; 32] {
    stage0_digest(
        transfer,
        settings(),
        UdpMode::Disabled,
        context().connection,
    )
    .unwrap()
}

fn body0(transfer: &[u8]) -> Vec<u8> {
    let stage0 = digest0(transfer);
    transcript_body(&context(), &KexStage::Initiator { stage0 })
}

/// Bob, pinned to Alice's key, receiving a Stage0.
fn bob_pinned_to(alice: &Key) -> P2pKexIdentities {
    let (store, port) = port(Store::default());
    store.pin(ALICE, alice.public());
    port
}

#[test]
fn a_relay_that_swaps_the_initiators_kem_transfer_is_refused() {
    let alice = Key::new(1);
    let (_, alice_transfer) = stage0();
    let auth = alice.sign(&body0(&alice_transfer));
    let (mut relay, relay_transfer) = stage0();
    let (store, bob) = port(Store::default());
    let verdict = checked(Some(&bob), BOB, ALICE, Some(&auth), &body0(&relay_transfer));
    refused_with(verdict, ErrorCode::P2pKexSignatureInvalid);
    assert!(
        store.pins.lock().unwrap().is_empty(),
        "the swap pinned nothing"
    );
    // What the check stops: answered, the swapped transfer gives the relay Bob's keys.
    let relayed = SyncIO::deserialize_from_vector(&relay_transfer).unwrap();
    let mut answer = Constructor::new_bob(BOB, opts(), relayed, &psks()).unwrap();
    relay
        .stage1_alice(answer.stage0_bob().unwrap(), &psks())
        .unwrap();
    let ends = (relay.finish_with_custom_cid(ALICE), answer.finish());
    assert!(
        opens(ends.0.zip(ends.1)),
        "unchecked, the relay holds the link"
    );
}

#[test]
fn a_relay_that_swaps_the_responders_reply_is_refused() {
    let bob = Key::new(2);
    let (_, alice_transfer) = stage0();
    let reply = |transfer: &[u8]| {
        let stage1 = stage1_digest(transfer, true, context().connection).unwrap();
        let stage0 = digest0(&alice_transfer);
        transcript_body(&context(), &KexStage::Responder { stage0, stage1 })
    };
    let bobs = Constructor::new_bob(BOB, opts(), stage0().0.stage0_alice().unwrap(), &psks());
    let bob_transfer = bobs
        .unwrap()
        .stage0_bob()
        .unwrap()
        .serialize_to_vector()
        .unwrap();
    let relays = Constructor::new_bob(BOB, opts(), stage0().0.stage0_alice().unwrap(), &psks());
    let relay_transfer = relays
        .unwrap()
        .stage0_bob()
        .unwrap()
        .serialize_to_vector()
        .unwrap();
    let auth = bob.sign(&reply(&bob_transfer));
    let (_, alice) = port(Store::default());
    let verdict = checked(
        Some(&alice),
        ALICE,
        BOB,
        Some(&auth),
        &reply(&relay_transfer),
    );
    refused_with(verdict, ErrorCode::P2pKexSignatureInvalid);
    let honest = checked(Some(&alice), ALICE, BOB, Some(&auth), &reply(&bob_transfer));
    assert_eq!(
        honest,
        Ok(PeerKexIdentity::Signed {
            identity_key: bob.public()
        })
    );
}

#[test]
fn a_relay_that_signs_its_swap_with_its_own_key_is_refused_by_a_pinned_peer() {
    let (alice, relay_key) = (Key::new(1), Key::new(9));
    let (_, relay_transfer) = stage0();
    let auth = relay_key.sign(&body0(&relay_transfer));
    let verdict = checked(
        Some(&bob_pinned_to(&alice)),
        BOB,
        ALICE,
        Some(&auth),
        &body0(&relay_transfer),
    );
    refused_with(verdict, ErrorCode::P2pKexPeerKeyChanged);
}

/// Every field the transcript names, changed one at a time, makes another transcript.
#[test]
fn the_signature_covers_every_field_of_the_transcript() {
    let key = Key::new(4);
    let stage = KexStage::Responder {
        stage0: [1; 32],
        stage1: [2; 32],
    };
    let auth = key.sign(&transcript_body(&context(), &stage));
    assert_eq!(verify(&auth, &transcript_body(&context(), &stage)), Ok(()));
    let with = |change: &dyn Fn(&mut P2pSealContext)| {
        let mut changed = context();
        change(&mut changed);
        transcript_body(&changed, &stage)
    };
    let altered = [
        ("initiator cid", with(&|c| c.initiator += 1)),
        ("responder cid", with(&|c| c.responder += 1)),
        (
            "connection id",
            with(&|c| c.connection = Ticket(c.connection.0 + 1)),
        ),
        ("stage0 digest", {
            let stage = KexStage::Responder {
                stage0: [3; 32],
                stage1: [2; 32],
            };
            transcript_body(&context(), &stage)
        }),
        ("stage1 digest", {
            let stage = KexStage::Responder {
                stage0: [1; 32],
                stage1: [3; 32],
            };
            transcript_body(&context(), &stage)
        }),
        ("role", {
            let mut body = transcript_body(&context(), &stage);
            *body.last_mut().unwrap() = 0;
            body
        }),
    ];
    for (field, body) in altered {
        assert!(
            verify(&auth, &body).is_err(),
            "the signature does not cover the {field}"
        );
    }
    let initiator = key.sign(&transcript_body(
        &context(),
        &KexStage::Initiator { stage0: [1; 32] },
    ));
    assert!(
        verify(&initiator, &transcript_body(&context(), &stage)).is_err(),
        "role"
    );
}

#[test]
fn the_signature_is_made_under_its_domain() {
    let key = Key::new(5);
    let body = transcript_body(&context(), &KexStage::Initiator { stage0: [1; 32] });
    let mut auth = key.sign(&body);
    let undomained: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::signature::Signer::sign(&key.0, &body);
    auth.signature = undomained.encode().as_slice().to_vec();
    assert!(verify(&auth, &body).is_err());
}

fn kex(auth: Option<KexAuth>) -> PeerSignal {
    PeerSignal::Kex {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: ALICE,
            peer_cid: BOB,
        },
        kex_payload: KeyExchangeProcess::Stage0(
            vec![7; 4],
            settings(),
            UdpMode::Disabled,
            Ticket(3),
        ),
        sender_protocol_version: *crate::constants::PROTOCOL_VERSION,
        path: Some(KexPath::default()),
        auth,
    }
}

fn auth_of(bytes: &[u8]) -> (Option<KexAuth>, bool) {
    match PeerSignal::deserialize_from_vector(bytes).unwrap() {
        PeerSignal::Kex { auth, path, .. } => (auth, path.is_some()),
        other => panic!("not a Kex: {other:?}"),
    }
}

#[test]
fn a_signed_stage_crosses_the_wire_and_one_without_the_field_is_refused() {
    let auth = Key::new(6).sign(b"body");
    let signed = kex(Some(auth.clone())).serialize_to_vector().unwrap();
    assert_eq!(auth_of(&signed), (Some(auth), true));
    let unsigned = kex(None).serialize_to_vector().unwrap();
    assert_eq!(auth_of(&unsigned), (None, true));
    // The encoding before the field (without its one-byte absent marker) does not parse.
    let mut older = unsigned;
    older.pop();
    assert!(PeerSignal::deserialize_from_vector(&older).is_err());
}
