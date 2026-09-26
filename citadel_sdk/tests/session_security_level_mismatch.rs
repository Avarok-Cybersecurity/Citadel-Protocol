#![cfg(not(target_family = "wasm"))]
//! A login whose session security level differs from the account's registered
//! level must end cleanly, never in a panic.
//!
//! Registration fixes the static auxiliary ratchet's depth. A login then builds a
//! fresh session ratchet with `session_security_settings.security_level + 1`
//! layers. The pre-connect SYN is protected with the static ratchet's full
//! depth, and every later pre-connect packet used the level read back from that
//! header, i.e. the static depth, on the session ratchet. With the account above
//! the session level, `protect_message_packet(...).unwrap()` in
//! `pre_connect::craft_stage0` panicked and took the whole node with it.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// A node that panicked never answers; a bounded wait tells the two apart.
    const MUST_FINISH_WITHIN: Duration = Duration::from_secs(60);
    const PASSWORD: &str = "password123";

    fn settings_at(level: SecurityLevel) -> SessionSecuritySettings {
        SessionSecuritySettings {
            security_level: level,
            ..Default::default()
        }
    }

    async fn connect_at(
        remote: &NodeRemote<StackedRatchet>,
        username: &str,
        level: SecurityLevel,
    ) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
        remote
            .connect(
                AuthenticationRequest::credentialed(username.to_string(), PASSWORD),
                ConnectMode::default(),
                UdpMode::default(),
                None,
                settings_at(level),
                None,
            )
            .await
    }

    /// Registers at `registered`, logs in at `requested`, hands the outcome to
    /// `check`, then proves the node still serves a login at `registered`.
    async fn run(
        registered: SecurityLevel,
        requested: SecurityLevel,
        check: fn(&Result<CitadelClientServerConnection<StackedRatchet>, NetworkError>),
    ) {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                let channel = connection.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();
                while let Some(msg) = rx.next().await {
                    tx.send(msg).await?;
                }
                Ok(())
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let username = format!("lvl_{}", &uuid.to_string()[..8]);

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                remote
                    .register(
                        server_addr,
                        username.as_str(),
                        username.as_str(),
                        PASSWORD,
                        settings_at(registered),
                        None,
                    )
                    .await?;

                let outcome = connect_at(&remote, &username, requested).await;
                check(&outcome);

                // Either way the node must still carry traffic for the account:
                // over the accepted session, or over a fresh one after a refusal.
                let mut conn = match outcome {
                    Ok(conn) => conn,
                    Err(_) => connect_at(&remote, &username, registered).await?,
                };
                let (mut tx, mut rx) = conn.take_channel().unwrap().split();
                tx.send(SecBuffer::from(&b"still serving"[..])).await?;
                let echoed = rx.next().await.expect("echo channel closed");
                assert_eq!(echoed.as_ref(), b"still serving");
                conn.disconnect().await?;

                remote.shutdown().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let task = async move {
            citadel_io::tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = client => res,
            }
        };

        let result = citadel_io::tokio::time::timeout(MUST_FINISH_WITHIN, task)
            .await
            .expect("the login never finished: the node panicked or hung");
        assert!(result.is_ok(), "node failed: {result:?}");
    }

    /// The account is registered High; the user asks for a Standard session.
    /// The user's own choice is honoured: the session runs at Standard and
    /// carries traffic.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_login_below_the_registered_level_connects_at_the_requested_level() {
        run(SecurityLevel::High, SecurityLevel::Standard, |outcome| {
            let conn = outcome
                .as_ref()
                .expect("a login below the registered level must connect");
            assert_eq!(
                conn.session_security_settings.security_level.value(),
                SecurityLevel::Standard.value()
            );
        })
        .await;
    }

    /// The account is registered Standard; the user asks for High. There are
    /// no layers to give it, so the login is refused, naming both levels, and
    /// never silently downgraded.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_login_above_the_registered_level_is_refused_naming_the_level() {
        run(SecurityLevel::Standard, SecurityLevel::High, |outcome| {
            let err = outcome
                .as_ref()
                .err()
                .expect("a login above the registered level must be refused")
                .to_string();
            assert!(
                err.contains("High") && err.contains("Standard"),
                "the refusal must name the requested and registered levels, got: {err}"
            );
        })
        .await;
    }
}
