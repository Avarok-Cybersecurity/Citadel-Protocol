//! A registration whose caller stopped waiting is aborted like a connect (S-C1, §9.1): it holds
//! a provisional slot the same way, so its dropped future must release it the same way.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::link::{managed, saw, with_client, ManualClock, Plan, Seen};
    use citadel_io::tokio;
    use citadel_proto::constants::TCP_CONN_TIMEOUT;
    use citadel_sdk::prelude::*;
    use uuid::Uuid;

    /// Registration holds a provisional slot the same way, and is aborted the same way.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_registration_dropped_mid_handshake_closes_its_transport() {
        let plans = vec![Plan::Hold { release: None }, Plan::Forward];
        with_client(
            managed(ManualClock::new()),
            plans,
            |remote, addr, mut seen| async move {
                let name = Uuid::new_v4().to_string();
                let first = {
                    let (remote, name) = (remote.clone(), name.clone());
                    tokio::spawn(async move {
                        remote
                            .register_with_defaults(
                                addr,
                                &name,
                                &name,
                                "password123",
                                CertVerification::SelfSignedAccepted,
                            )
                            .await
                            .map(|_| ())
                    })
                };
                saw(&mut seen, Seen::ClientSpoke(0)).await;
                first.abort();
                assert!(first.await.unwrap_err().is_cancelled());
                tokio::time::timeout(TCP_CONN_TIMEOUT / 2, saw(&mut seen, Seen::ClientClosed(0)))
                    .await
                    .expect("the abandoned registration was left running");
                let again = remote
                    .register_with_defaults(
                        addr,
                        &name,
                        &name,
                        "password123",
                        CertVerification::SelfSignedAccepted,
                    )
                    .await
                    .map(|_| ());
                assert!(
                    again.is_ok(),
                    "the next registration was refused: {again:?}"
                );
                remote.shutdown().await
            },
        )
        .await;
    }
}
