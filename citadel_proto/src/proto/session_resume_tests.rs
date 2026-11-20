use super::*;
use crate::proto::packet_crafter::do_connect::{DoConnectFinalStatusPacket, DoConnectStage0Packet};
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::external_services::ServicesObject;
use citadel_user::serialization::SyncIO;

#[test]
fn a_held_session_yields_to_the_token_it_was_issued() {
    let issued = ResumeToken::generate();
    let held = HeldSessionResume::admitted(issued, None);
    assert_eq!(
        displacement(false, &held, Some(&issued)),
        Some(Displacement::OwnSession)
    );
}

#[test]
fn a_held_session_yields_to_the_token_its_own_login_presented() {
    // That login's SUCCESS was lost: its client still holds the older token.
    let older = ResumeToken::generate();
    let held = HeldSessionResume::admitted(ResumeToken::generate(), Some(older));
    assert_eq!(
        displacement(false, &held, Some(&older)),
        Some(Displacement::OwnSession)
    );
}

#[test]
fn a_held_session_refuses_any_other_token_or_none() {
    let held = HeldSessionResume::admitted(ResumeToken::generate(), Some(ResumeToken::generate()));
    assert_eq!(
        displacement(false, &held, Some(&ResumeToken::generate())),
        None
    );
    assert_eq!(displacement(false, &held, None), None);
}

#[test]
fn a_session_admitted_before_tokens_existed_refuses_every_token() {
    let held = HeldSessionResume::default();
    assert_eq!(
        displacement(false, &held, Some(&ResumeToken::generate())),
        None
    );
}

#[test]
fn force_login_displaces_whatever_is_held() {
    let held = HeldSessionResume::admitted(ResumeToken::generate(), None);
    assert_eq!(displacement(true, &held, None), Some(Displacement::Forced));
}

#[test]
fn a_client_keeps_the_latest_token_and_forgets_it_for_a_server_that_issues_none() {
    let mut tokens = ResumeTokens::default();
    let first = ResumeToken::generate();
    tokens.on_connect_success(7, Some(first));
    assert!(tokens.for_cid(7).is_some_and(|held| held.same_as(&first)));
    assert!(tokens.for_cid(8).is_none());
    tokens.on_connect_success(7, None);
    assert!(tokens.for_cid(7).is_none());
}

#[test]
fn a_token_never_prints() {
    let token = ResumeToken([0xab; RESUME_TOKEN_LEN]);
    assert_eq!(format!("{token:?}"), "ResumeToken(..)");
}

/// STAGE0 as a node before session resumption encoded it.
#[derive(Serialize, Deserialize)]
struct LegacyStage0 {
    proposed_credentials: ProposedCredentials,
    uses_filesystem: bool,
}

#[test]
fn stage0_carries_the_token_and_the_encoding_before_it_is_refused() {
    let issued = ResumeToken::generate();
    let current = DoConnectStage0Packet {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: true,
        resume_token: Some(issued),
        pq_proof: None,
    };
    let read =
        DoConnectStage0Packet::deserialize_from_vector(&current.serialize_to_vector().unwrap())
            .unwrap();
    assert!(read
        .resume_token
        .is_some_and(|token| token.same_as(&issued)));

    let legacy = LegacyStage0 {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: true,
    };
    assert!(
        DoConnectStage0Packet::deserialize_from_vector(&legacy.serialize_to_vector().unwrap())
            .is_err()
    );
}

#[test]
fn success_carries_the_token_and_the_encoding_before_it_is_refused() {
    #[derive(Serialize, Deserialize)]
    struct LegacyFinalStatus<'a> {
        mailbox: Option<crate::proto::peer::peer_layer::MailboxTransfer>,
        peers: Vec<citadel_types::user::MutualPeer>,
        post_login_object: ServicesObject,
        #[serde(borrow)]
        message: &'a [u8],
    }
    let legacy = LegacyFinalStatus {
        mailbox: None,
        peers: Vec::new(),
        post_login_object: ServicesObject::default(),
        message: b"welcome",
    };
    let bytes = legacy.serialize_to_vector().unwrap();
    assert!(DoConnectFinalStatusPacket::deserialize_from_vector(&bytes).is_err());

    let issued = ResumeToken::generate();
    let current = DoConnectFinalStatusPacket {
        mailbox: None,
        peers: Vec::new(),
        post_login_object: ServicesObject::default(),
        message: b"welcome",
        resume_token: Some(issued),
        admission_challenge: None,
        path_policy: None,
    };
    let bytes = current.serialize_to_vector().unwrap();
    let round_trip = DoConnectFinalStatusPacket::deserialize_from_vector(&bytes).unwrap();
    assert!(round_trip
        .resume_token
        .is_some_and(|token| token.same_as(&issued)));
}
