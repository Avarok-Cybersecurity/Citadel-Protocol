//! The decision and the port: what is pinned, refused and reported. The port here is an
//! in-memory store (the agent's is persistent); the keys are real ML-DSA-65 keys and every
//! signature is checked for real.

use super::*;
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa65, Seed, SigningKey};
use std::collections::HashMap;
use std::sync::Mutex;

pub(super) const ALICE: u64 = 10;
pub(super) const BOB: u64 = 20;

/// An identity key from a fixed seed.
pub(super) struct Key(SigningKey<MlDsa65>);

impl Key {
    pub(super) fn new(byte: u8) -> Self {
        let mut seed = Seed::default();
        seed.copy_from_slice(&[byte; 32]);
        Key(SigningKey::<MlDsa65>::from_seed(&seed))
    }

    pub(super) fn public(&self) -> Vec<u8> {
        self.0.verifying_key().encode().as_slice().to_vec()
    }

    pub(super) fn sign(&self, body: &[u8]) -> KexAuth {
        let signature: ml_dsa::Signature<MlDsa65> = self.0.sign(&transcript_message(body));
        KexAuth {
            identity_key: self.public(),
            signature: signature.encode().as_slice().to_vec(),
        }
    }
}

/// One account's identity key and its pins, in memory.
#[derive(Default)]
pub(super) struct Store {
    pub(super) key: Option<Key>,
    pub(super) pins: Mutex<HashMap<u64, Vec<u8>>>,
    pub(super) changes: Mutex<Vec<(u64, Vec<u8>)>>,
    /// The pin cannot be kept: storage refuses every write.
    pub(super) unwritable: bool,
}

impl Store {
    pub(super) fn pin(&self, peer_cid: u64, key: Vec<u8>) {
        self.pins.lock().unwrap().insert(peer_cid, key);
    }

    pub(super) fn changes(&self) -> Vec<(u64, Vec<u8>)> {
        self.changes.lock().unwrap().clone()
    }
}

impl P2pKexIdentity for Store {
    fn sign(&self, _local_cid: u64, body: &[u8]) -> Option<KexAuth> {
        Some(self.key.as_ref()?.sign(body))
    }
    fn pinned_key(&self, _local_cid: u64, peer_cid: u64) -> Option<Vec<u8>> {
        self.pins.lock().unwrap().get(&peer_cid).cloned()
    }
    fn pin_first_key(
        &self,
        _local_cid: u64,
        peer_cid: u64,
        identity_key: &[u8],
    ) -> BoxFuture<'static, Result<(), String>> {
        let kept = if self.unwritable {
            Err("the disk is full".to_string())
        } else {
            self.pin(peer_cid, identity_key.to_vec());
            Ok(())
        };
        Box::pin(async move { kept })
    }
    fn peer_key_changed(&self, _local_cid: u64, peer_cid: u64, presented: &[u8]) {
        self.changes
            .lock()
            .unwrap()
            .push((peer_cid, presented.to_vec()));
    }
}

/// [`authenticate`], run to completion.
pub(super) fn checked(
    port: Option<&P2pKexIdentities>,
    local_cid: u64,
    peer_cid: u64,
    auth: Option<&KexAuth>,
    body: &[u8],
) -> Result<PeerKexIdentity, String> {
    futures::executor::block_on(authenticate(port, local_cid, peer_cid, auth, body))
}

/// A store, and the same store as the node holds it.
pub(super) fn port(store: Store) -> (Arc<Store>, P2pKexIdentities) {
    let store = Arc::new(store);
    (store.clone(), store)
}

pub(super) fn context() -> P2pSealContext {
    P2pSealContext {
        initiator: ALICE,
        responder: BOB,
        connection: Ticket(77),
    }
}

pub(super) fn initiator_body() -> Vec<u8> {
    transcript_body(&context(), &KexStage::Initiator { stage0: [1; 32] })
}

/// The refusal is `code`'s: its text carries the code's template between the placeholders.
pub(super) fn refused_with(result: Result<PeerKexIdentity, String>, code: ErrorCode) {
    let error = result.expect_err("the stage is refused");
    let fixed = code.raw_string().split("{}").nth(1).unwrap();
    assert!(
        error.contains(fixed),
        "refused as {error:?}, not as {code:?}"
    );
}

fn signed(key: &Key) -> Result<PeerKexIdentity, String> {
    Ok(PeerKexIdentity::Signed {
        identity_key: key.public(),
    })
}

#[test]
fn a_peer_seen_first_is_pinned_and_then_matches_its_pin() {
    let alice = Key::new(1);
    let (store, bob) = port(Store::default());
    let auth = alice.sign(&initiator_body());
    let first = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    assert_eq!(first, signed(&alice));
    assert_eq!(store.pinned_key(BOB, ALICE), Some(alice.public()));
    let again = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    assert_eq!(again, signed(&alice));
}

#[test]
fn a_key_other_than_the_pin_is_refused_reported_and_not_pinned() {
    let (pinned, other) = (Key::new(1), Key::new(2));
    let (store, bob) = port(Store::default());
    store.pin(ALICE, pinned.public());
    let auth = other.sign(&initiator_body());
    let refused = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    refused_with(refused, ErrorCode::P2pKexPeerKeyChanged);
    assert_eq!(store.changes(), vec![(ALICE, other.public())]);
    assert_eq!(
        store.pinned_key(BOB, ALICE),
        Some(pinned.public()),
        "the pin stays"
    );
}

#[test]
fn a_changed_key_connects_once_the_person_accepts_it() {
    let (pinned, other) = (Key::new(1), Key::new(2));
    let (store, bob) = port(Store::default());
    store.pin(ALICE, pinned.public());
    let auth = other.sign(&initiator_body());
    let before = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    refused_with(before, ErrorCode::P2pKexPeerKeyChanged);
    let again = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    refused_with(again, ErrorCode::P2pKexPeerKeyChanged);
    // Accepting is the person's, through the application: it re-pins the reported key.
    let (peer, presented) = store.changes()[0].clone();
    store.pin(peer, presented);
    let accepted = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    assert_eq!(accepted, signed(&other));
}

#[test]
fn an_unsigned_stage_from_a_pinned_peer_is_refused() {
    let (store, bob) = port(Store::default());
    store.pin(ALICE, Key::new(1).public());
    let refused = checked(Some(&bob), BOB, ALICE, None, &initiator_body());
    refused_with(refused, ErrorCode::P2pKexSignatureMissing);
}

#[test]
fn an_unsigned_stage_from_an_unpinned_peer_connects_unsigned() {
    let (store, bob) = port(Store::default());
    let unsigned = checked(Some(&bob), BOB, ALICE, None, &initiator_body());
    assert_eq!(unsigned, Ok(PeerKexIdentity::Unsigned));
    assert_eq!(
        store.pinned_key(BOB, ALICE),
        None,
        "a missing signature pins nothing"
    );
}

#[test]
fn a_signature_that_does_not_verify_pins_nothing_and_reports_no_change() {
    let (store, bob) = port(Store::default());
    let mut auth = Key::new(1).sign(&initiator_body());
    auth.signature[10] ^= 1;
    let refused = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    refused_with(refused, ErrorCode::P2pKexSignatureInvalid);
    assert!(store.pins.lock().unwrap().is_empty() && store.changes().is_empty());
}

#[test]
fn a_first_key_that_cannot_be_kept_is_refused_not_reported_verified() {
    let alice = Key::new(1);
    let (store, bob) = port(Store {
        unwritable: true,
        ..Default::default()
    });
    let auth = alice.sign(&initiator_body());
    let refused = checked(Some(&bob), BOB, ALICE, Some(&auth), &initiator_body());
    refused_with(refused, ErrorCode::P2pKexPinNotSaved);
    assert!(store.pins.lock().unwrap().is_empty());
}

#[path = "kex_auth_signing_tests.rs"]
mod signing;

#[path = "kex_auth_transcript_tests.rs"]
mod transcript;

#[path = "kex_auth_digest_tests.rs"]
mod digest;

#[path = "kex_auth_size_tests.rs"]
mod size;
