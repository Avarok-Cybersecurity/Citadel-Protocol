#![cfg(not(target_family = "wasm"))]
//! A file transfer the receiver never answers does not keep the sender's session alive.
//!
//! The sender's streaming task waits for the receiver's answer for as long as the receiver
//! takes. The session must still be free to end meanwhile: once it has, the sender holds
//! nothing for it, and once the receiver lets go of the offer, neither node runs anything for
//! it. Measured as in `a_session_releases_what_it_held`: both nodes' session footprints, and the
//! runtime's live task count against the count between sessions.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_crypt::scramble::streaming_crypt_scrambler::BytesSource;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;
    use uuid::Uuid;

    /// Teardown takes milliseconds; the bound leaves room for a loaded runner while staying
    /// below the 20 s login expiry, the first timer that would wake a task orphaned by a session.
    const RELEASED_WITHIN: Duration = Duration::from_secs(10);

    /// Keeps every file offer it receives, unanswered, until told to let go.
    struct HoldingServer {
        remote: Arc<OnceLock<NodeRemote<StackedRatchet>>>,
        offers: Arc<Mutex<Vec<ObjectTransferHandler>>>,
    }

    #[async_trait]
    impl NetKernel<StackedRatchet> for HoldingServer {
        fn load_remote(&mut self, remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
            let _ = self.remote.set(remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_node_event_received(
            &self,
            message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { handle, .. }) = message {
                self.offers.lock().unwrap().push(handle);
            }
            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    fn live_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    /// Polls `done` until it holds, failing at the deadline with `what`.
    async fn within(what: &str, done: impl Fn() -> bool) -> Result<(), NetworkError> {
        tokio::time::timeout(RELEASED_WITHIN, async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| NetworkError::msg(format!("{what} within {RELEASED_WITHIN:?}")))
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_unanswered_offer_does_not_hold_the_senders_session() {
        citadel_logging::setup_log();

        let server_remote = Arc::new(OnceLock::new());
        let offers = Arc::new(Mutex::new(Vec::new()));
        let (server, server_addr) = server_test_node(
            HoldingServer {
                remote: server_remote.clone(),
                offers: offers.clone(),
            },
            |_| {},
        );

        let username = format!("stl_{}", &Uuid::new_v4().to_string()[..8]);
        let password = "password123";
        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                let login = || AuthenticationRequest::credentialed(username.clone(), password);
                within("the server never started", || server_remote.get().is_some()).await?;
                let server: NodeRemote<StackedRatchet> = server_remote.get().cloned().unwrap();
                let nothing_held = || {
                    remote.session_footprint().sessions == 0
                        && server.session_footprint().sessions == 0
                };
                remote
                    .register_with_defaults(server_addr, &username, &username, password)
                    .await?;
                remote
                    .connect_with_defaults(login())
                    .await?
                    .disconnect()
                    .await?;
                within("the first sessions were not released", nothing_held).await?;
                let baseline = live_tasks();

                let connection = remote.connect_with_defaults(login()).await?;
                let sender = connection.remote.clone();
                let sending = tokio::spawn(async move {
                    let source = BytesSource {
                        inner: Some(vec![7u8; 64 * 1024].into()),
                    };
                    sender.send_file(source).await
                });
                within("the server never received the offer", || {
                    !offers.lock().unwrap().is_empty()
                })
                .await?;

                connection.disconnect().await?;
                within("the sender's session is still held after it ended", || {
                    remote.session_footprint().sessions == 0
                })
                .await?;
                let outcome = tokio::time::timeout(RELEASED_WITHIN, sending)
                    .await
                    .map_err(|_| NetworkError::msg("the sender's transfer never ended"))?;
                if matches!(outcome, Ok(Ok(()))) {
                    return Err(NetworkError::msg("a transfer nobody accepted completed"));
                }

                offers.lock().unwrap().clear();
                within(
                    "a node still holds the transfer after its offer was dropped",
                    || nothing_held() && live_tasks() <= baseline,
                )
                .await
                .map_err(|err| {
                    NetworkError::msg(format!(
                        "{err}: client {:?}, server {:?}, live tasks {} (baseline {baseline})",
                        remote.session_footprint(),
                        server.session_footprint(),
                        live_tasks()
                    ))
                })?;
                remote.shutdown().await
            },
        );

        let client = DefaultNodeBuilder::default()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(client_kernel)
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        })
        .await
        .expect("the test timed out");
        assert!(result.is_ok(), "{result:?}");
    }
}
