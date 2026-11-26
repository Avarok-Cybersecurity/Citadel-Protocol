//! The default credential rules accept a password of up to 64 bytes, and such a password is used
//! whole: registration and login read every byte of it, so two passwords that differ only in
//! their last byte are two different passwords.
use citadel_crypt::argon::argon_container::ArgonSettings;
use citadel_io::{tokio, ErrorCode};
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::credentials::CredentialRequirements;
use citadel_user::prelude::ConnectionInfo;
use citadel_user::server_misc_settings::ServerMiscSettings;

type Cnac = ClientNetworkAccount<citadel_crypt::ratchets::stacked::StackedRatchet>;

/// A password of exactly `len` bytes (ASCII, no spaces), ending in `last`.
fn password_of(len: usize, last: char) -> String {
    let mut password: String = "Xk9$mQ2#vL7@pR4!".chars().cycle().take(len - 1).collect();
    password.push(last);
    assert_eq!(password.len(), len);
    password
}

fn check(password: &str) -> Result<(), ErrorCode> {
    CredentialRequirements::default()
        .check("alice", Some(password), "Alice")
        .map_err(|err| err.code())
}

#[test]
fn a_64_byte_password_is_accepted() {
    assert_eq!(check(&password_of(64, 'a')), Ok(()));
}

#[test]
fn a_65_byte_password_is_refused() {
    assert_eq!(
        check(&password_of(65, 'a')),
        Err(ErrorCode::PasswordLengthOutOfRange)
    );
}

#[test]
fn every_length_accepted_before_is_still_accepted() {
    for len in 7..=17 {
        assert_eq!(check(&password_of(len, 'a')), Ok(()), "{len} bytes");
    }
}

#[test]
fn the_minimum_is_unchanged() {
    assert_eq!(
        check(&password_of(6, 'a')),
        Err(ErrorCode::PasswordLengthOutOfRange)
    );
}

/// Cheap parameters for the server side of this test (below the floor, which is not under test).
fn test_server_settings() -> ArgonSettings {
    ArgonSettings::new_gen_salt(vec![], 1, 32, 1024, 1, vec![])
}

async fn login_with(registered_as: &str, typed_at_login: &str) -> bool {
    let reg = ProposedCredentials::new_register("Alice", "alice", SecBuffer::from(registered_as))
        .await
        .unwrap();
    let (_, _, _, client_settings) = reg.clone().decompose();
    let server_side = reg
        .derive_server_container(&test_server_settings(), &ServerMiscSettings::default())
        .await
        .unwrap();
    let info = ConnectionInfo::new("127.0.0.1:1").unwrap();
    let server = Cnac::new(78, false, info, server_side, None).await.unwrap();
    let login = ProposedCredentials::new_connect(
        "Alice",
        "alice",
        SecBuffer::from(typed_at_login),
        client_settings.unwrap(),
    )
    .await
    .unwrap();
    server.validate_credentials(login).await.is_ok()
}

#[tokio::test]
async fn a_64_byte_password_logs_in() {
    let password = password_of(64, 'a');
    assert!(login_with(&password, &password).await);
}

#[tokio::test]
async fn a_64_byte_password_differing_only_in_its_last_byte_is_refused() {
    assert!(!login_with(&password_of(64, 'a'), &password_of(64, 'b')).await);
}

#[test]
fn the_post_quantum_pre_hash_reads_the_last_byte_of_a_64_byte_password() {
    assert_ne!(
        ProposedCredentials::password_transform(password_of(64, 'a')).as_ref(),
        ProposedCredentials::password_transform(password_of(64, 'b')).as_ref()
    );
}
