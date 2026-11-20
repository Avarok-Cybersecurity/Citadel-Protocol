//! A signed Stage0 at the real sizes -- ML-KEM-1024 public keys (1,568 bytes each), an ML-DSA-65
//! identity key and signature -- from one layer up to the most layers a ratchet carries,
//! decodes through the bounded decoder and fits the primary stream's frame.

use super::super::*;
use super::{context, Key, ALICE, BOB};
use crate::proto::misc::primary_frame::MAX_PRIMARY_FRAME_LEN;
use crate::proto::peer::kex_path::KexPath;
use crate::proto::peer::p2p_seal_binding::tests::Constructor;
use crate::proto::peer::peer_crypt::KeyExchangeProcess;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::prelude::ConstructorOpts;
use citadel_types::crypto::{CryptoParameters, KemAlgorithm, SecurityLevel, STRUCTURAL_MAX_LEVEL};

const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

fn ml_kem_1024_settings(level: SecurityLevel) -> SessionSecuritySettings {
    let mut settings = SessionSecuritySettings {
        security_level: level,
        ..crate::proto::misc::session_security_settings::default_session_security_settings()
    };
    settings.crypto_params.kem_algorithm = KemAlgorithm::MlKem1024Fips203;
    settings
}

/// A signed Stage0 at `level` on the wire, and the size of its KEM transfer.
fn signed_stage0(level: SecurityLevel) -> (Vec<u8>, usize) {
    let settings = ml_kem_1024_settings(level);
    let params: CryptoParameters = settings.crypto_params;
    let opts = ConstructorOpts::new_vec_init(params, level);
    let alice = Constructor::new_alice(opts, ALICE, 0).unwrap();
    let transfer = alice.stage0_alice().unwrap().serialize_to_vector().unwrap();
    let stage0 =
        stage0_digest(&transfer, settings, UdpMode::Disabled, context().connection).unwrap();
    let auth = Key::new(9).sign(&transcript_body(
        &context(),
        &KexStage::Initiator { stage0 },
    ));
    assert_eq!(auth.signature.len(), ML_DSA_65_SIGNATURE_LEN);
    assert_eq!(auth.identity_key.len(), ML_DSA_65_PUBLIC_KEY_LEN);
    let transfer_len = transfer.len();
    let signal = PeerSignal::Kex {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: ALICE,
            peer_cid: BOB,
        },
        kex_payload: KeyExchangeProcess::Stage0(transfer, settings, UdpMode::Disabled, Ticket(3)),
        sender_protocol_version: *crate::constants::PROTOCOL_VERSION,
        path: Some(KexPath::default()),
        auth: Some(auth),
    };
    (signal.serialize_to_vector().unwrap(), transfer_len)
}

#[test]
fn a_signed_ml_kem_1024_stage0_decodes_bounded_and_fits_a_frame_at_every_layer_count() {
    for level in [
        SecurityLevel::Standard,
        SecurityLevel::Custom(STRUCTURAL_MAX_LEVEL),
    ] {
        let layers = usize::from(level.value()) + 1;
        let (wire, transfer_len) = signed_stage0(level);
        assert!(
            transfer_len >= layers * ML_KEM_1024_PUBLIC_KEY_LEN,
            "{level:?}: {transfer_len}"
        );
        assert!(
            wire.len() <= MAX_PRIMARY_FRAME_LEN,
            "{level:?}: {} bytes",
            wire.len()
        );
        let decoded = PeerSignal::deserialize_from_vector(&wire).expect("bounded decode");
        let PeerSignal::Kex {
            auth: Some(auth),
            kex_payload: KeyExchangeProcess::Stage0(t, ..),
            ..
        } = decoded
        else {
            panic!("{level:?}: the signed Stage0 did not survive the decode");
        };
        assert_eq!(
            (t.len(), auth.signature.len()),
            (transfer_len, ML_DSA_65_SIGNATURE_LEN)
        );
    }
}
