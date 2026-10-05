#![cfg(not(target_family = "wasm"))]
//! Admission: a server that requires a token (a Turnstile response) for each FRESH sign-in and
//! registration. The token travels inside the post-quantum channel; a missing one is refused as
//! `PqSignInAdmissionRequired`, a bad one as `PqSignInAdmissionFailed`, a good one admitted. A
//! recovery-code sign-in and a reconnect whose resume token the held session recognises are
//! not asked.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::half_open::{login_after_local_teardown, standard, SeveringProxy};
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::async_trait;
    use citadel_sdk::prelude::*;
    use citadel_user::auth::pq::admission::{
        AdmissionContext, AdmissionKind, AdmissionPolicy, AdmissionRefusal, AdmissionToken,
    };
    use std::sync::{Arc, Mutex};

    const GOOD: &str = "turnstile-ok";

    /// Admits `GOOD` for the action it was asked for, and records every call.
    #[derive(Default)]
    struct Turnstile {
        asked: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl AdmissionPolicy for Turnstile {
        async fn admit(&self, ctx: AdmissionContext) -> Result<(), AdmissionRefusal> {
            self.asked.lock().unwrap().push(ctx.kind.action());
            assert!(
                ctx.remote_addr.is_some(),
                "the hook was not given the address"
            );
            match ctx.token.as_ref().map(AdmissionToken::as_str) {
                None => Err(AdmissionRefusal::Required),
                Some(GOOD) => Ok(()),
                Some(_) => Err(AdmissionRefusal::Failed("invalid-input-response".into())),
            }
        }
    }

    impl Turnstile {
        fn asked(&self) -> Vec<&'static str> {
            self.asked.lock().unwrap().clone()
        }
    }

    fn guarded(policy: Arc<Turnstile>) -> ServerMiscSettings {
        ServerMiscSettings {
            admission: Some(policy),
            ..pq_settings()
        }
    }

    fn code<T>(result: &Result<T, NetworkError>) -> Option<ErrorCode> {
        result.as_ref().err().map(|err| err.code)
    }

    async fn register(
        remote: &NodeRemote<StackedRatchet>,
        addr: std::net::SocketAddr,
        user: &str,
        token: Option<&str>,
    ) -> Result<RegisterSuccess, NetworkError> {
        let admission = token.map(str::to_string);
        remote
            .register_admitted(
                addr,
                user,
                user,
                PASSWORD,
                Default::default(),
                None,
                admission,
            )
            .await
    }

    async fn sign_in(
        remote: &NodeRemote<StackedRatchet>,
        user: &str,
        factors: SignInFactors,
    ) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
        remote
            .connect_with_defaults(AuthenticationRequest::sign_in(user.to_string(), factors))
            .await
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_missing_token_and_a_bad_one_are_refused_and_a_good_one_admitted() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::default());
        let (server, addr, _) = server(guarded(policy.clone()), None);
        let user = username("adm");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            let missing = register(&remote, addr, &user, None).await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let bad = register(&remote, addr, &user, Some("forged")).await;
            assert_eq!(code(&bad), Some(ErrorCode::PqSignInAdmissionFailed));
            register(&remote, addr, &user, Some(GOOD)).await?;

            let missing = sign_in(&remote, &user, SignInFactors::password(PASSWORD)).await;
            assert_eq!(code(&missing), Some(ErrorCode::PqSignInAdmissionRequired));
            let factors = SignInFactors::password(PASSWORD).with_admission("forged");
            let bad = sign_in(&remote, &user, factors).await;
            assert_eq!(code(&bad), Some(ErrorCode::PqSignInAdmissionFailed));
            let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
            let conn = sign_in(&remote, &user, factors).await?;
            assert!(conn.rekey().await?.is_some());
            assert_eq!(
                seen.asked(),
                ["register", "register", "register", "sign-in", "sign-in", "sign-in"]
            );
            conn.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_recovery_code_sign_in_is_not_asked() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::default());
        let (server, addr, _) = server(guarded(policy.clone()), None);
        let user = username("admrec");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            let reg = register(&remote, addr, &user, Some(GOOD)).await?;
            let factors = SignInFactors::recovery_code(&reg.recovery_codes[0])?;
            let recovery = sign_in(&remote, &user, factors).await?;
            assert_eq!(seen.asked(), ["register"], "the recovery sign-in was asked");
            recovery.shutdown_kernel().await
        })
        .await;
    }

    /// The client's link dies without the server seeing it, so the server still holds the
    /// session; the reconnect presents that session's resume token and is not asked again.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_resume_token_reconnect_is_not_asked() {
        citadel_logging::setup_log();
        let policy = Arc::new(Turnstile::default());
        let (server, server_addr, _) = server(guarded(policy.clone()), None);
        let proxy = SeveringProxy::start(server_addr).await;
        let user = username("admres");
        let seen = policy.clone();
        run(server, move |remote, _| async move {
            register(&remote, proxy.addr, &user, Some(GOOD)).await?;
            let factors = SignInFactors::password(PASSWORD).with_admission(GOOD);
            let first = sign_in(&remote, &user, factors).await?;
            let cid = first.cid;
            proxy.sever();
            let again = login_after_local_teardown(&remote, &user, PASSWORD, standard(false))
                .await
                .map_err(|err| NetworkError::msg(format!("the reconnect was refused: {err}")))?;
            assert_eq!(again.cid, cid);
            assert_eq!(
                seen.asked(),
                ["register", "sign-in"],
                "the reconnect was asked"
            );
            again.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn without_a_policy_everyone_is_admitted() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), None);
        let user = username("admnone");
        run(server, move |remote, _| async move {
            register(&remote, addr, &user, None).await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            conn.shutdown_kernel().await
        })
        .await;
    }

    #[test]
    fn the_actions_are_sign_in_and_register() {
        assert_eq!(AdmissionKind::SignIn.action(), "sign-in");
        assert_eq!(AdmissionKind::Register.action(), "register");
    }
}
