#![cfg(not(target_family = "wasm"))]
//! Resume credentials end to end: an account whose policy asks for a security key signs in again
//! with the credential its last full sign-in was given, with no password and no key, also after
//! its server restarted; and the server refuses, by name, a credential that has expired or that
//! predates a change to the account's sign-in.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::admission::{code, register, sign_in, Turnstile, GOOD};
    use crate::common::pq::*;
    use crate::common::pq_restart::{rebind, server_at, until_client_lost};
    use crate::sqlite_host::SqliteHost;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use std::sync::Arc;
    use std::time::Duration;

    const CRED: &[u8] = b"a-security-key";
    const DAY: Duration = Duration::from_secs(24 * 3_600);

    /// A key that answers every request, and counts them.
    fn key(touches: Arc<std::sync::atomic::AtomicUsize>) -> SecurityKeyPrf {
        let (key, mut asked) = security_key_channel();
        drop(tokio::spawn(async move {
            while let Some(touch) = asked.recv().await {
                let _ = touches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                touch.answer(CRED.to_vec(), [7; 32]);
            }
        }));
        key
    }

    /// Sign-in settings (one OPRF seed for every server made from them) honouring resume
    /// credentials for at most `max`, behind an admission check.
    fn resuming(misc: &ServerMiscSettings, max: Duration) -> ServerMiscSettings {
        let pq = misc.pq_sign_in.clone().expect("post-quantum settings");
        ServerMiscSettings {
            pq_sign_in: Some(pq.with_resume(ResumePolicy::new(max).unwrap())),
            admission: Some(Arc::new(Turnstile::with_grace(Duration::ZERO))),
            ..misc.clone()
        }
    }

    fn policy(policy: SignInPolicy) -> SignInManagementOp {
        SignInManagementOp::SetSignInPolicy { policy }
    }

    /// What happened, in order, for the assertions after the nodes have stopped.
    #[derive(Default)]
    struct Seen {
        touches_before_resume: usize,
        touches_after_resume: usize,
        granted_ms: u64,
        max_s: Option<u64>,
        resumed_after_restart: Option<ErrorCode>,
        resume_was_regranted: bool,
        old_after_change: Option<ErrorCode>,
        kept_after_change: Option<ErrorCode>,
        after_lowered_maximum: Option<ErrorCode>,
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_key_protected_account_resumes_without_its_key_until_expiry_or_a_change() {
        citadel_logging::setup_log();
        let backend = SqliteHost::handle();
        let misc = pq_settings();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (first, addr, first_slot) = server_at(listener, resuming(&misc, DAY), backend.clone());
        let (second_misc, third_misc) = (
            resuming(&misc, DAY),
            resuming(&misc, Duration::from_secs(1)),
        );
        let (stop, stopped) = tokio::sync::mpsc::channel::<()>(1);
        let (back, mut is_back) = tokio::sync::mpsc::channel::<()>(1);
        let servers = async move {
            let mut stopped = stopped;
            let mut running: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> =
                Box::pin(first);
            let mut slot = first_slot;
            for next in [second_misc, third_misc] {
                tokio::select! {
                    _ = &mut running => panic!("a server ended by itself"),
                    _ = stopped.recv() => {}
                }
                let remote = slot.lock().await.clone().expect("server remote loaded");
                let _ = remote.shutdown().await;
                drop(running);
                let (server, _, next_slot) = server_at(rebind(addr).await, next, backend.clone());
                running = Box::pin(server);
                slot = next_slot;
                back.send(()).await.unwrap();
            }
            running.await;
            panic!("the last server ended by itself");
        };
        let seen: Arc<std::sync::Mutex<Seen>> = Default::default();
        let recorded = seen.clone();
        let user = username("resume");
        let client = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(crate::common::group::GroupTestKernel::new(
                move |remote, _| async move {
                    let touches: Arc<std::sync::atomic::AtomicUsize> = Default::default();
                    let count = || touches.load(std::sync::atomic::Ordering::SeqCst);
                    let factors = || {
                        SignInFactors::password(PASSWORD).with_security_key(key(touches.clone()))
                    };
                    let _ = register(&remote, addr, &user, Some(GOOD)).await?;
                    let conn = sign_in(&remote, &user, factors().with_admission(GOOD)).await?;
                    let add = SignInManagementOp::AddSecurityKey {
                        label: "Key".into(),
                    };
                    let _ = conn.manage_sign_in(add, factors()).await?;
                    let both = policy(SignInPolicy::PasswordAndKey);
                    let _ = conn.manage_sign_in(both, factors()).await?;
                    conn.disconnect().await?;

                    // The full sign-in: password and key, asking for a week; the server allows a day.
                    let asking = factors().with_admission(GOOD).with_resume_lifetime(7 * DAY);
                    let conn = sign_in(&remote, &user, asking).await?;
                    let cid = conn.cid;
                    let credential = conn.resume.clone().expect("a credential was granted");
                    recorded.lock().unwrap().granted_ms =
                        credential.valid_until_utc() - credential.issued_at_utc();
                    recorded.lock().unwrap().max_s = conn.resume_max_lifetime_s;
                    recorded.lock().unwrap().touches_before_resume = count();

                    // The server restarts. No password, no key, no admission token.
                    stop.send(()).await.unwrap();
                    is_back.recv().await.expect("the server restarted");
                    until_client_lost(&remote, cid).await;
                    let resumed =
                        sign_in(&remote, &user, SignInFactors::resume(credential.clone()));
                    let resumed = resumed.await;
                    recorded.lock().unwrap().resumed_after_restart = code(&resumed);
                    let conn = resumed?;
                    assert_eq!(conn.cid, cid);
                    assert!(
                        conn.resume.is_none(),
                        "a resume is not given a new credential"
                    );
                    assert!(conn.rekey().await?.is_some());
                    recorded.lock().unwrap().touches_after_resume = count();

                    // The session changes its own sign-in and keeps its credential, re-bound.
                    let mut step_up = factors();
                    step_up.resume = Some(credential.clone());
                    let password_only = policy(SignInPolicy::Password);
                    let changed = conn.change_sign_in(password_only, None, step_up).await?;
                    let kept = changed.resume.expect("the credential was re-issued");
                    recorded.lock().unwrap().resume_was_regranted =
                        kept.valid_until_utc() == credential.valid_until_utc();
                    conn.disconnect().await?;
                    let old = sign_in(&remote, &user, SignInFactors::resume(credential)).await;
                    recorded.lock().unwrap().old_after_change = code(&old);
                    let again = sign_in(&remote, &user, SignInFactors::resume(kept.clone())).await;
                    recorded.lock().unwrap().kept_after_change = code(&again);
                    let cid = again?.cid;

                    // The server comes back allowing one second: the credential, which this client
                    // still believes has most of a day left, is past what the server honours.
                    stop.send(()).await.unwrap();
                    is_back.recv().await.expect("the server restarted again");
                    until_client_lost(&remote, cid).await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    assert!(!kept.expired_at(citadel_user::misc::now_ms()));
                    let late = sign_in(&remote, &user, SignInFactors::resume(kept)).await;
                    recorded.lock().unwrap().after_lowered_maximum = code(&late);
                    remote.shutdown().await
                },
            ))
            .unwrap();
        tokio::select! {
            _ = servers => unreachable!(),
            res = client => { res.unwrap(); }
        }
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.granted_ms,
            DAY.as_millis() as u64,
            "clamped to the maximum"
        );
        assert_eq!(seen.max_s, Some(DAY.as_secs()));
        assert_eq!(seen.resumed_after_restart, None);
        assert_eq!(
            seen.touches_after_resume, seen.touches_before_resume,
            "the key was asked for a resume"
        );
        assert!(
            seen.resume_was_regranted,
            "the re-issued credential's expiry moved"
        );
        assert_eq!(
            seen.old_after_change,
            Some(ErrorCode::ResumeCredentialRevoked)
        );
        assert_eq!(seen.kept_after_change, None);
        assert_eq!(
            seen.after_lowered_maximum,
            Some(ErrorCode::ResumeCredentialExpired)
        );
    }
}
