//! A password is accepted at login exactly as it was registered: registration and login apply
//! the same normalization (surrounding whitespace removed) on the legacy Argon2 path.
use citadel_crypt::argon::argon_container::ArgonSettings;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::prelude::ConnectionInfo;
use citadel_user::server_misc_settings::ServerMiscSettings;

type Cnac = ClientNetworkAccount<citadel_crypt::ratchets::stacked::StackedRatchet>;

/// Cheap parameters for the server side of this test (below the floor, which is not under test).
fn test_server_settings() -> ArgonSettings {
    ArgonSettings::new_gen_salt(vec![], 1, 32, 1024, 1, vec![])
}

async fn login_with(registered_as: &str, typed_at_login: &str) -> bool {
    let reg = ProposedCredentials::new_register("Alice", "alice", SecBuffer::from(registered_as))
        .await
        .unwrap();
    // The client keeps these settings in its account; generate_connect_credentials reads them back.
    let (_, _, _, client_settings) = reg.clone().decompose();
    let server_side = reg
        .derive_server_container(&test_server_settings(), &ServerMiscSettings::default())
        .await
        .unwrap();
    let info = ConnectionInfo::new("127.0.0.1:1").unwrap();
    let server = Cnac::new(77, false, info, server_side, None).await.unwrap();
    // What ClientNetworkAccount::generate_connect_credentials does for an Argon2 account.
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
async fn control_the_same_password_without_surrounding_whitespace_logs_in() {
    assert!(login_with("hunter2-pw", "hunter2-pw").await);
}

#[tokio::test]
async fn a_password_with_surrounding_whitespace_logs_in_when_typed_the_same_way() {
    assert!(
        login_with("  hunter2-pw  ", "  hunter2-pw  ").await,
        "registered and logged in with the identical password, login refused"
    );
}

#[tokio::test]
async fn a_different_password_is_still_refused() {
    assert!(!login_with("  hunter2-pw  ", "hunter2-px").await);
}
