//! Which accounts a login that ran no post-quantum exchange can open: only a transient one, by its
//! own name. A post-quantum account has no password hash such a login could be checked against.

use super::*;
use crate::auth::pq::tests::register;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::prelude::ConnectionInfo;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::{tokio, ErrorCode};

type Cnac = ClientNetworkAccount<StackedRatchet, StackedRatchet>;

async fn account(auth_store: DeclaredAuthenticationMode) -> Cnac {
    let info = ConnectionInfo {
        addr: "127.0.0.1:1".parse().unwrap(),
    };
    Cnac::new(77, false, info, auth_store, None).await.unwrap()
}

#[citadel_io::tokio::test]
async fn a_post_quantum_account_refuses_a_login_without_factors() {
    let (record, _) = register("pw-123").await;
    let cnac = account(DeclaredAuthenticationMode::PostQuantum {
        username: "alice".into(),
        full_name: "Alice".into(),
        side: PqAuthSide::Server(Box::new(record)),
    })
    .await;
    for creds in [
        ProposedCredentials::new_register("Alice", "alice"),
        ProposedCredentials::transient("alice"),
    ] {
        let refused = cnac.admits_without_factors(&creds).unwrap_err();
        assert_eq!(refused.code, ErrorCode::PqSignInLegacyRefused);
    }
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
async fn a_transient_account_admits_its_own_name_only() {
    let cnac = account(DeclaredAuthenticationMode::Transient {
        username: "bob".into(),
        full_name: "authless.client".into(),
    })
    .await;
    cnac.admits_without_factors(&ProposedCredentials::transient("bob"))
        .unwrap();
    let other = cnac.admits_without_factors(&ProposedCredentials::transient("bot"));
    assert!(other.is_err(), "another username opened the account");
    assert!(matches!(
        cnac.pq_account_state("bob"),
        PqAccountState::Unknown
    ));
}
