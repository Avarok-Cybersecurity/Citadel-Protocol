//! A post-quantum login proves the password registration enrolled, typed the same way. The SDK
//! enrolls `ProposedCredentials::registration_password` (surrounding whitespace removed), and a
//! login passes the password as typed.

use super::client::ClientRegistration;
use super::record::PqAuthRecord;
use super::server::registration_reply;
use super::tests::{begin, complete, password, settings};
use crate::auth::proposed_credentials::ProposedCredentials;
use citadel_io::tokio;

async fn register_as_the_sdk_does(typed: &str) -> PqAuthRecord {
    let enrolled = ProposedCredentials::registration_password(&password(typed));
    let (start, client) = ClientRegistration::start("alice", &enrolled).unwrap();
    let (reply, pending) = registration_reply(&settings(), &start).unwrap();
    let (finish, _) = client.finish(&reply, true).await.unwrap();
    pending.finish(finish, 1_000).unwrap()
}

#[citadel_io::tokio::test]
async fn control_a_password_without_surrounding_whitespace_signs_in() {
    let record = register_as_the_sdk_does("correct horse").await;
    assert!(
        complete(begin(Some(&record), "alice", Some("correct horse"), None))
            .await
            .is_ok()
    );
}

#[citadel_io::tokio::test]
async fn a_password_with_surrounding_whitespace_signs_in_when_typed_the_same_way() {
    let record = register_as_the_sdk_does("  correct horse\t").await;
    assert!(
        complete(begin(
            Some(&record),
            "alice",
            Some("  correct horse\t"),
            None
        ))
        .await
        .is_ok(),
        "registered and signed in with the identical password, the login was refused"
    );
}

#[citadel_io::tokio::test]
async fn whitespace_inside_a_password_still_counts() {
    let record = register_as_the_sdk_does("correct horse").await;
    assert!(
        complete(begin(Some(&record), "alice", Some("correcthorse"), None))
            .await
            .is_err()
    );
}
