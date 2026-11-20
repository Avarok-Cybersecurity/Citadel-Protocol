//! A refusal's challenge on the wire: in the connect FAILURE's final status packet and in the
//! registration FAILURE. A challenge naming a provider this node does not know reads as none.

use super::refusal::{read_register_failure, register_failure};
use crate::proto::packet_crafter::do_connect::DoConnectFinalStatusPacket;
use crate::proto::session_resume::ResumeToken;
use citadel_io::ErrorCode;
use citadel_user::auth::pq::admission::{
    challenge_of, refusal_error, refusal_from_message, AdmissionChallenge, AdmissionRefusal,
};
use citadel_user::external_services::ServicesObject;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};

fn challenge() -> AdmissionChallenge {
    AdmissionChallenge::turnstile("0x4AAA-site-key", Some("acme".into()))
}

fn required(challenge: Option<AdmissionChallenge>) -> citadel_io::NetworkError {
    refusal_error(AdmissionRefusal::Required(challenge))
}

fn refusal_message() -> &'static [u8] {
    ErrorCode::PqSignInAdmissionRequired.raw_string().as_bytes()
}

/// The 0.14.0 shape of the final status packet.
#[derive(Serialize, Deserialize)]
struct FinalStatusOf0140<'a> {
    mailbox: Option<crate::proto::peer::peer_layer::MailboxTransfer>,
    peers: Vec<citadel_types::user::MutualPeer>,
    post_login_object: ServicesObject,
    #[serde(borrow)]
    message: &'a [u8],
    resume_token: Option<ResumeToken>,
}

/// A later node's challenge, naming a provider this node does not know.
#[derive(Serialize, Deserialize)]
enum LaterProvider {
    Turnstile,
    Other,
}

#[derive(Serialize, Deserialize)]
struct LaterChallenge {
    provider: LaterProvider,
    site_key: String,
    identity: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LaterFinalStatus<'a> {
    #[serde(borrow)]
    base: FinalStatusOf0140<'a>,
    admission_challenge: Option<LaterChallenge>,
}

fn old_status() -> FinalStatusOf0140<'static> {
    FinalStatusOf0140 {
        mailbox: None,
        peers: Vec::new(),
        post_login_object: ServicesObject::default(),
        message: refusal_message(),
        resume_token: None,
    }
}

#[test]
fn the_connect_failure_carries_the_challenge_and_reads_in_both_directions() {
    let new = DoConnectFinalStatusPacket {
        mailbox: None,
        peers: Vec::new(),
        post_login_object: ServicesObject::default(),
        message: refusal_message(),
        resume_token: None,
        admission_challenge: Some(challenge()),
        path_policy: None,
    };
    let bytes = new.serialize_to_vector().unwrap();
    let here = DoConnectFinalStatusPacket::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(here.admission_challenge, Some(challenge()));
    let old = FinalStatusOf0140::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(
        old.message,
        refusal_message(),
        "an older client lost the message"
    );

    let from_old = old_status().serialize_to_vector().unwrap();
    let read = DoConnectFinalStatusPacket::deserialize_from_vector(&from_old).unwrap();
    assert_eq!(
        read.admission_challenge, None,
        "an absent challenge appeared"
    );
}

#[test]
fn a_challenge_from_an_unknown_provider_reads_as_absent() {
    let later = LaterFinalStatus {
        base: old_status(),
        admission_challenge: Some(LaterChallenge {
            provider: LaterProvider::Other,
            site_key: "k".into(),
            identity: None,
        }),
    };
    let bytes = later.serialize_to_vector().unwrap();
    let read = DoConnectFinalStatusPacket::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(read.admission_challenge, None);
    assert_eq!(read.message, refusal_message());
    let known = LaterFinalStatus {
        admission_challenge: Some(LaterChallenge {
            provider: LaterProvider::Turnstile,
            site_key: "k".into(),
            identity: None,
        }),
        base: old_status(),
    };
    let read_known = known.serialize_to_vector().unwrap();
    let read = DoConnectFinalStatusPacket::deserialize_from_vector(&read_known).unwrap();
    assert_eq!(
        read.admission_challenge,
        Some(AdmissionChallenge::turnstile("k", None))
    );
}

#[test]
fn a_registration_failure_carries_the_challenge() {
    let read = read_register_failure(register_failure(required(Some(challenge()))));
    assert_eq!(read.admission_challenge, Some(challenge()));
    let err = refusal_from_message(&read.message, read.admission_challenge)
        .expect("the refusal was not recognised");
    assert_eq!(challenge_of(&err), Some(&challenge()));
}

/// The 0.12.3 shape of a structured registration refusal: no error code.
#[derive(Serialize, Deserialize)]
struct RegisterRefusalOf0123 {
    message: String,
    admission_challenge: Option<AdmissionChallenge>,
}

/// A structured refusal without its code is an older server's, and reads as malformed; a plain
/// message (a refusal before the post-quantum exchange) still reads as itself.
/// Control: read `RegisterRefusal::code` as an appended field and the older refusal reads.
#[test]
fn a_structured_refusal_without_its_code_is_malformed() {
    let older = RegisterRefusalOf0123 {
        message: String::from_utf8(refusal_message().to_vec()).unwrap(),
        admission_challenge: Some(challenge()),
    };
    let payload = [&[0xFF][..], &older.serialize_to_vector().unwrap()].concat();
    let read = read_register_failure(payload);
    assert_eq!(read.message, "Malformed registration refusal");
    assert_eq!((read.admission_challenge, read.code), (None, None));

    let current = read_register_failure(register_failure(required(None)));
    let expected = String::from_utf8(refusal_message().to_vec()).unwrap();
    assert_eq!(current.message, expected);
    assert_eq!(current.code, Some(required(None).code_u16()));

    let plain = read_register_failure(b"Server busy".to_vec());
    assert_eq!((plain.message.as_str(), plain.code), ("Server busy", None));
}

/// Control: leave the code out of `register_failure` and the client reads none.
#[test]
fn a_registration_failure_carries_its_code() {
    let failed = citadel_io::error!(citadel_io::ErrorCode::PqSignInFailed);
    let read = read_register_failure(register_failure(failed.clone()));
    assert_eq!(read.code, Some(failed.code_u16()));
    assert_eq!(read.message, failed.to_string());
    let rebuilt = citadel_io::NetworkError::from_wire(read.code.unwrap(), read.message);
    assert_eq!(rebuilt.code(), citadel_io::ErrorCode::PqSignInFailed);
    let with_challenge = read_register_failure(register_failure(required(Some(challenge()))));
    assert_eq!(with_challenge.admission_challenge, Some(challenge()));
    assert!(with_challenge.code.is_some());
}
