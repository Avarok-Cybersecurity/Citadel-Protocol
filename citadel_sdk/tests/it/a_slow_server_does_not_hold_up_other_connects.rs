//! One server that is slow to answer a connect does not hold up the node's other requests.
//!
//! The node's request loop used to run each C2S connect's handshake inline, so a connect to a
//! server that accepted TCP and then said nothing kept every request queued behind it waiting
//! until that handshake timed out. Here the first connect goes to such a server; the second, to a
//! working one, must succeed while the first is still waiting on its silent server.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::net::TcpListener;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_connect_to_a_silent_server_does_not_delay_the_next_connect() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();

        let client_kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _state: Arc<NodeState>| async move {
                let stalled_remote = remote.clone();
                let stalled = tokio::spawn(async move {
                    stalled_remote
                        .connect_with_defaults(
                            AuthenticationRequest::transient(Uuid::new_v4(), silent_addr),
                            CertVerification::SelfSignedAccepted,
                        )
                        .await
                        .map(|_| ())
                });
                // Accepted: the first connect is inside its handshake and will hear nothing.
                let (silent_link, _) = silent.accept().await.unwrap();

                let _connected = remote
                    .connect_with_defaults(
                        AuthenticationRequest::transient(Uuid::new_v4(), server_addr),
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;

                // The stalled connect closes its link when it gives up; it must not have yet.
                let mut probe = [0u8; 1];
                let still_waiting = matches!(
                    silent_link.try_read(&mut probe),
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock
                );
                assert!(
                    still_waiting && !stalled.is_finished(),
                    "the second connect waited for the first to give up on its silent server"
                );
                stalled.abort();
                remote.shutdown().await
            },
        );

        let client = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(client_kernel)
            .unwrap();
        // A hang guard, not a latency assertion.
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
