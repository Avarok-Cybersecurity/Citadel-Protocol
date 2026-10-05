#![cfg(not(target_family = "wasm"))]
//! Security keys, recovery codes, policies and management, end to end. The "security key" is the
//! application's side of the key channel, answering with a fixed PRF output, as an agent relaying
//! a browser's WebAuthn ceremony would.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;

    const CRED: &[u8] = b"yubikey-5-credential";

    /// A key that answers every request with `prf` for `CRED`.
    fn key(prf: u8) -> SecurityKeyPrf {
        let (key, mut touches) = security_key_channel();
        drop(tokio::spawn(async move {
            while let Some(touch) = touches.recv().await {
                touch.answer(CRED.to_vec(), [prf; 32]);
            }
        }));
        key
    }

    fn password() -> SignInFactors {
        SignInFactors::password(PASSWORD)
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

    fn add_key() -> SignInManagementOp {
        SignInManagementOp::AddSecurityKey {
            credential_id: CRED.to_vec(),
            label: "YubiKey".into(),
        }
    }

    fn policy(policy: SignInPolicy) -> SignInManagementOp {
        SignInManagementOp::SetSignInPolicy { policy }
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_key_is_enrolled_and_then_required_and_the_wrong_key_is_refused() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), None);
        let user = username("key");
        run(server, move |remote, _| async move {
            let reg = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            assert_eq!(reg.recovery_codes.len(), 10);

            let conn = login(&remote, &user, PASSWORD).await?;
            let added = conn.manage_sign_in(add_key(), password().with_security_key(key(7)));
            assert!(matches!(
                added.await?,
                SignInManagementOutcome::Added { .. }
            ));
            let set = conn.manage_sign_in(
                policy(SignInPolicy::PasswordAndKey),
                password().with_security_key(key(7)),
            );
            assert_eq!(set.await?, SignInManagementOutcome::PolicySet);
            conn.disconnect().await?;

            assert!(
                login(&remote, &user, PASSWORD).await.is_err(),
                "the password alone"
            );
            let wrong = sign_in(&remote, &user, password().with_security_key(key(8))).await;
            assert!(wrong.is_err(), "another key's PRF signed in");
            let both = sign_in(&remote, &user, password().with_security_key(key(7))).await?;
            assert!(both.rekey().await?.is_some());
            let listed = both.manage_sign_in(
                SignInManagementOp::ListCredentials,
                password().with_security_key(key(7)),
            );
            assert!(matches!(
                listed.await?,
                SignInManagementOutcome::Credentials {
                    policy: SignInPolicy::PasswordAndKey,
                    ..
                }
            ));

            // Key-only, then: no password at all.
            let set = both.manage_sign_in(
                policy(SignInPolicy::KeyOnly),
                password().with_security_key(key(7)),
            );
            assert_eq!(set.await?, SignInManagementOutcome::PolicySet);
            both.disconnect().await?;
            let factors = SignInFactors::default().with_security_key(key(7));
            let key_only = sign_in(&remote, &user, factors).await?;
            assert!(key_only.rekey().await?.is_some());
            key_only.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_recovery_code_signs_in_once_to_a_session_that_can_only_add_a_key_and_set_policy() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), None);
        let user = username("rec");
        run(server, move |remote, _| async move {
            let reg = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            let code = &reg.recovery_codes[2];

            let recovery = sign_in(&remote, &user, SignInFactors::recovery_code(code)?).await?;
            let normal = recovery.get_local_group_peers(user.as_str(), None).await;
            assert!(normal.is_err(), "a recovery session ran a normal request");
            let list = recovery.manage_sign_in(
                SignInManagementOp::ListCredentials,
                SignInFactors::default(),
            );
            assert!(list.await.is_err(), "a recovery session listed credentials");
            let added = recovery.manage_sign_in(
                add_key(),
                SignInFactors::default().with_security_key(key(3)),
            );
            assert!(matches!(
                added.await?,
                SignInManagementOutcome::Added { .. }
            ));
            let set =
                recovery.manage_sign_in(policy(SignInPolicy::KeyOnly), SignInFactors::default());
            assert_eq!(set.await?, SignInManagementOutcome::PolicySet);
            recovery.disconnect().await?;

            let again = sign_in(&remote, &user, SignInFactors::recovery_code(code)?).await;
            assert!(again.is_err(), "a recovery code signed in twice");
            let factors = SignInFactors::default().with_security_key(key(3));
            let conn = sign_in(&remote, &user, factors).await?;
            assert!(conn.rekey().await?.is_some());
            conn.shutdown_kernel().await
        })
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn management_lists_renames_refuses_the_last_factor_and_regenerates_codes() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), None);
        let user = username("mgmt");
        run(server, move |remote, _| async move {
            let reg = remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;
            let conn = login(&remote, &user, PASSWORD).await?;
            let SignInManagementOutcome::Credentials {
                policy,
                credentials: list,
            } = conn
                .manage_sign_in(SignInManagementOp::ListCredentials, password())
                .await?
            else {
                panic!("not a list")
            };
            assert_eq!(list.len(), 11);
            assert_eq!(policy, SignInPolicy::Password);
            let pw = list
                .iter()
                .find(|c| c.kind == FactorKind::Password)
                .unwrap()
                .id;

            let wrong = SignInFactors::password("not the password");
            let refused = conn.manage_sign_in(SignInManagementOp::ListCredentials, wrong);
            assert!(refused.await.is_err(), "a step-up with the wrong password");
            let rename = SignInManagementOp::RenameCredential {
                id: pw,
                label: "Main password".into(),
            };
            assert_eq!(
                conn.manage_sign_in(rename, password()).await?,
                SignInManagementOutcome::Renamed
            );
            let remove = SignInManagementOp::RemoveCredential { id: pw };
            assert!(
                conn.manage_sign_in(remove, password()).await.is_err(),
                "removed the last factor"
            );

            let SignInManagementOutcome::RecoveryCodes(fresh) = conn
                .manage_sign_in(SignInManagementOp::RegenerateRecoveryCodes, password())
                .await?
            else {
                panic!("no codes")
            };
            assert_eq!(fresh.len(), 10);
            conn.disconnect().await?;
            let old = sign_in(
                &remote,
                &user,
                SignInFactors::recovery_code(&reg.recovery_codes[0])?,
            )
            .await;
            assert!(old.is_err(), "a replaced recovery code signed in");
            let new = sign_in(&remote, &user, SignInFactors::recovery_code(&fresh[0])?).await?;
            new.shutdown_kernel().await
        })
        .await;
    }
}
