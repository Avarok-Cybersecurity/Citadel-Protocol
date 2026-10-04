//! The legacy check against each kind of account: an upgraded account refuses it, and a
//! password-protected one is never satisfied by passwordless credentials.

use super::*;
use crate::auth::pq::tests::register;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::prelude::ConnectionInfo;
use crate::server_misc_settings::ServerMiscSettings;
use citadel_crypt::argon::argon_container::ArgonSettings;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::{tokio, ErrorCode};

type Cnac = ClientNetworkAccount<StackedRatchet, StackedRatchet>;

async fn account(auth_store: DeclaredAuthenticationMode) -> Cnac {
    let info = ConnectionInfo {
        addr: "127.0.0.1:1".parse().unwrap(),
    };
    Cnac::new(77, false, info, auth_store, None).await.unwrap()
}

async fn legacy_credentials() -> ProposedCredentials {
    ProposedCredentials::new_register("Alice", "alice", "pw-123".into())
        .await
        .unwrap()
}

#[citadel_io::tokio::test]
async fn an_upgraded_account_refuses_a_legacy_login() {
    let (record, _) = register("pw-123").await;
    let cnac = account(DeclaredAuthenticationMode::PostQuantum {
        username: "alice".into(),
        full_name: "Alice".into(),
        side: PqAuthSide::Server(Box::new(record)),
    })
    .await;
    let refused = cnac.validate_credentials(legacy_credentials().await).await;
    assert!(matches!(refused, Err(err) if err.code == ErrorCode::PqSignInLegacyRefused));
    assert!(matches!(
        cnac.pq_account_state("alice"),
        PqAccountState::PostQuantum(_)
    ));
    assert!(matches!(
        cnac.pq_account_state("alicf"),
        PqAccountState::Unknown
    ));
}

#[citadel_io::tokio::test]
async fn passwordless_credentials_never_open_a_password_account() {
    let creds = legacy_credentials().await;
    let server_side = creds
        .clone()
        .derive_server_container(&ArgonSettings::default(), &ServerMiscSettings::default())
        .await
        .unwrap();
    let cnac = account(server_side).await;
    assert!(matches!(
        cnac.pq_account_state("alice"),
        PqAccountState::Legacy
    ));
    let bypass = cnac
        .validate_credentials(ProposedCredentials::transient("alice"))
        .await;
    assert!(
        bypass.is_err(),
        "a passwordless login opened a password account"
    );
    cnac.validate_credentials(creds).await.unwrap();
}
