//! A refusal's challenge on the wire: in the connect FAILURE's final status packet and in the
//! registration FAILURE, read by this node and ignored (or never sent) by an older one.

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
    refusal_error(AdmissionRefusal::Required(challenge), false)
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
fn a_registration_failure_carries_the_challenge_to_a_client_that_reads_one() {
    let (message, read) =
        read_register_failure(register_failure(required(Some(challenge())), true));
    assert_eq!(read, Some(challenge()));
    let err = refusal_from_message(&message, read).expect("the refusal was not recognised");
    assert_eq!(challenge_of(&err), Some(&challenge()));
}

#[test]
fn an_older_client_and_an_absent_challenge_get_the_plain_message() {
    let to_old = register_failure(required(Some(challenge())), false);
    assert_eq!(
        to_old,
        refusal_message(),
        "an older client was sent a challenge"
    );
    let absent = register_failure(required(None), true);
    assert_eq!(absent, refusal_message());
    assert_eq!(
        read_register_failure(absent),
        (String::from_utf8(refusal_message().to_vec()).unwrap(), None)
    );
    let generic = register_failure(citadel_io::NetworkError::msg("Server busy"), true);
    assert_eq!(
        read_register_failure(generic),
        ("Server busy".to_string(), None)
    );
}
