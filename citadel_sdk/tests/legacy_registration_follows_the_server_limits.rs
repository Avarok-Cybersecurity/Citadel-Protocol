#![cfg(not(target_family = "wasm"))]
//! A legacy registration, whose password the server hashes itself, is taken only as the server's
//! limits say: a server that refuses legacy registration answers it without hashing anything.
//!
//! The server's Argon2 parameters are ones every Argon2 call refuses, so a registration that
//! reached the hash fails with Argon2's error, and one that did not fails with the limit's.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use crate::common::pq::*;
    use citadel_io::{tokio, ErrorCode};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{localhost_server_limits, server_test_node};

    async fn legacy_registration_against(legacy: LegacyRegistration) -> String {
        let (node, addr) = server_test_node(
            GroupTestKernel::new(|_: NodeRemote<StackedRatchet>, _: Events| async { Ok(()) }),
            |builder| {
                let _ = builder
                    .with_server_argon_settings(poisoned_argon())
                    .with_server_limits(ServerLimits {
                        legacy_registration: legacy,
                        ..localhost_server_limits()
                    });
            },
        );
        let server = async move {
            let _ = node.await;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        run(server, move |remote, _| async move {
            let refused = register_legacy(&remote, addr, &username("legacy"))
                .await
                .err()
                .expect("a legacy registration hashed with refused parameters succeeded");
            let _ = tx.send(refused.into_string());
            remote.shutdown().await
        })
        .await;
        rx.await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_that_refuses_legacy_registration_hashes_nothing() {
        citadel_logging::setup_log();
        let refused = legacy_registration_against(LegacyRegistration::Refused).await;
        assert_eq!(
            refused,
            citadel_io::error!(ErrorCode::LegacyRegistrationRefused).into_string()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_that_takes_legacy_registration_hashes_it() {
        citadel_logging::setup_log();
        let concurrent_hashes = std::num::NonZeroUsize::new(1).unwrap();
        let hashed =
            legacy_registration_against(LegacyRegistration::Accepted { concurrent_hashes }).await;
        assert_eq!(
            hashed,
            citadel_io::error!(ErrorCode::PasswordHashFailed).into_string(),
            "the registration did not fail at the hash"
        );
    }
}
