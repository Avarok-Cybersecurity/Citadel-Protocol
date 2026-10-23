#![cfg(not(target_family = "wasm"))]
//! A client learns its server's path policy at connect: the policy the server was built with
//! arrives, validated, on the connection.
//!
//! ```text
//! server: built with localhost_path_policy()
//! A: register → connect; conn.path_policy == the server's policy
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{localhost_path_policy, server_info};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_client_receives_the_servers_path_policy_at_connect() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(1);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let name = format!("ppc_{}", &Uuid::new_v4().to_string()[..8]);
        let checked = Arc::new(AtomicBool::new(false));

        let client = {
            let checked = checked.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let _ = remote
                        .register_with_defaults(server_addr, &name, &name, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &name).await?;
                    assert_eq!(conn.path_policy, Some(localhost_path_policy()));
                    checked.store(true, Ordering::SeqCst);
                    conn.disconnect().await?;
                    remote.shutdown().await
                },
            )
        };

        let client = DefaultNodeBuilder::default()
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(client)
            .unwrap();
        let task = async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");
        assert!(checked.load(Ordering::SeqCst));
    }
}
