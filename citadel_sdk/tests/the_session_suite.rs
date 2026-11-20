//! The suite a session runs on. With nothing named, both the client-server session and a P2P
//! connection run on ML-KEM-1024. A node whose application names ML-KEM-768 connects to one on the
//! default, and its own C2S session keeps the suite it asked for.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    /// What one peer's keys run on: its C2S account ratchet and its P2P connection's ratchet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Suites {
        c2s: KemAlgorithm,
        p2p: KemAlgorithm,
    }

    /// The settings an application names to offer ML-KEM-768.
    fn ml_kem_768() -> SessionSecuritySettings {
        SessionSecuritySettingsBuilder::default()
            .with_crypto_params(KemAlgorithm::MlKem768Fips203 + EncryptionAlgorithm::AES_GCM_256)
            .build()
            .unwrap()
    }

    fn defaults() -> SessionSecuritySettings {
        SessionSecuritySettingsBuilder::default().build().unwrap()
    }

    /// Connects two peers, peer `me` asking for `asks[me]` on both its sessions, exchanges one
    /// message each way, and returns what each peer's keys ran on.
    async fn run(asks: [SessionSecuritySettings; 2]) -> [Suites; 2] {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let seen: Arc<Mutex<[Option<Suites>; 2]>> = Arc::new(Mutex::new([None, None]));
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();
        for me in 0..2 {
            let setup = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(UdpMode::Disabled)
                .with_session_security_settings(asks[me]);
            let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(
                server_addr,
                uuids[me],
                CertVerification::SelfSignedAccepted,
            )
            .with_session_security_settings(asks[me])
            .build()
            .unwrap();
            let seen = seen.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, connection| async move {
                    let conn = results.recv().await.unwrap()?;
                    let account = connection
                        .remote()
                        .account_manager()
                        .get_client_by_cid(connection.cid)
                        .await?
                        .expect("the session's account is stored");
                    let c2s = account
                        .get_static_auxiliary_ratchet()
                        .get_scramble_pqc_and_entropy_bank()
                        .0
                        .params
                        .kem_algorithm;
                    let p2p = conn
                        .channel
                        .key_epoch()
                        .expect("a P2P channel has a key epoch")
                        .negotiated()
                        .expect("the connection has a usable ratchet")
                        .params()
                        .kem_algorithm;
                    seen.lock().unwrap()[me] = Some(Suites { c2s, p2p });

                    let (mut tx, mut rx) = conn.channel.split();
                    tx.send(SecBuffer::from(format!("from {me}").as_str()))
                        .await?;
                    let got = rx.next().await.expect("the channel stays open");
                    assert_eq!(got.as_ref(), format!("from {}", 1 - me).as_bytes());
                    wait_for_peers().await;
                    connection.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .build(kernel)
                .unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        // A hang guard for the whole pair, not a latency assertion.
        let result = tokio::time::timeout(
            Duration::from_secs(180),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        let seen = *seen.lock().unwrap();
        [
            seen[0].expect("peer 0 connected"),
            seen[1].expect("peer 1 connected"),
        ]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_built_from_defaults_run_on_ml_kem_1024() {
        let both = Suites {
            c2s: KemAlgorithm::MlKem1024Fips203,
            p2p: KemAlgorithm::MlKem1024Fips203,
        };
        assert_eq!(run([defaults(), defaults()]).await, [both, both]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_offering_ml_kem_768_connects_to_one_on_the_default() {
        let [named, default] = run([ml_kem_768(), defaults()]).await;
        assert_eq!(
            named.c2s,
            KemAlgorithm::MlKem768Fips203,
            "its own session keeps its suite"
        );
        assert_eq!(default.c2s, KemAlgorithm::MlKem1024Fips203);
        assert_eq!(
            named.p2p, default.p2p,
            "both ends of the connection agree on one suite"
        );
    }
}
