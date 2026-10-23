#![cfg(not(target_family = "wasm"))]
//! A real security key, end to end: enrolment, `PasswordAndKey`, `KeyOnly`, and the same key
//! refused a second time. It needs a FIDO2 key with a PIN plugged into this machine, and a person
//! to touch it, so it runs only when asked for:
//!
//! ```bash
//! cargo test -p citadel_sdk --features localhost-testing,security-key \
//!     --test pq_sign_in_security_key -- --ignored --nocapture
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing", feature = "security-key"))]
mod tests {
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;

    /// Asks for the PIN and the touches on the terminal running the test.
    struct Terminal;

    impl SecurityKeyPrompt for Terminal {
        fn pin(&self, purpose: SecurityKeyPurpose, attempts_left: Option<u8>) -> Option<SecBuffer> {
            let prompt = match attempts_left {
                Some(left) => format!("Incorrect PIN, {left} attempts left. PIN ({purpose:?}): "),
                None => format!("Security key PIN ({purpose:?}): "),
            };
            let pin = rpassword::prompt_password(prompt).ok()?;
            Some(SecBuffer::from(pin.as_str()))
        }

        fn touch(&self, purpose: SecurityKeyPurpose) {
            println!(">>> Touch your security key ({purpose:?})");
        }
    }

    fn step(what: &str) {
        println!("\n=== {what}");
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
            label: "Security key".into(),
        }
    }

    fn policy(policy: SignInPolicy) -> SignInManagementOp {
        SignInManagementOp::SetSignInPolicy { policy }
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a security key with a PIN, and someone to touch it"]
    async fn a_real_key_enrols_signs_in_and_cannot_be_enrolled_twice() {
        citadel_logging::setup_log();
        let (server, addr, _) = server(pq_settings(), Some(poisoned_argon()), None);
        let user = username("hardware");
        run(server, move |remote, _| async move {
            let key = SecurityKey::new(Terminal);
            let password = || SignInFactors::password(PASSWORD);
            remote
                .register_with_defaults(addr, user.as_str(), user.as_str(), PASSWORD)
                .await?;

            step("Enrol the key: it is created, then evaluated (PIN once, two touches)");
            let conn = login(&remote, &user, PASSWORD).await?;
            let added = conn.manage_sign_in(add_key(), password().with_security_key(key.serve()));
            assert!(matches!(
                added.await?,
                SignInManagementOutcome::Added { .. }
            ));

            step("Enrol the same key again: it must be refused (touch it)");
            let again = conn.manage_sign_in(add_key(), password().with_security_key(key.serve()));
            let refused = again.await.expect_err("the same key was enrolled twice");
            assert_eq!(refused.code, ErrorCode::PqSignInSecurityKey);
            assert_eq!(
                refused.into_string(),
                "This security key is already enrolled on this account."
            );

            step("Require the password and the key");
            let set = conn.manage_sign_in(policy(SignInPolicy::PasswordAndKey), password());
            assert_eq!(set.await?, SignInManagementOutcome::PolicySet);
            conn.disconnect().await?;

            step("The password alone is refused");
            assert!(login(&remote, &user, PASSWORD).await.is_err());

            step("The password and the key sign in (PIN, touch)");
            let both = sign_in(&remote, &user, password().with_security_key(key.serve())).await?;

            step("Switch to the key alone (PIN, touch for the step-up)");
            let set = both.manage_sign_in(
                policy(SignInPolicy::KeyOnly),
                password().with_security_key(key.serve()),
            );
            assert_eq!(set.await?, SignInManagementOutcome::PolicySet);
            both.disconnect().await?;

            step("The key alone signs in (PIN, touch)");
            let factors = SignInFactors::default().with_security_key(key.serve());
            let key_only = sign_in(&remote, &user, factors).await?;
            assert!(key_only.rekey().await?.is_some());
            println!("\nAll steps passed.");
            key_only.shutdown_kernel().await
        })
        .await;
    }
}
