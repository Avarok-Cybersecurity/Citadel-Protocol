#![cfg(not(target_family = "wasm"))]
//! Each end of a P2P key exchange signs its stage with its account's identity key, and builds the
//! link only when the other's stage is signed by the key it pinned for that peer.
//!
//! Over a real server, with real ML-DSA-65 keys: both ends of a signed pair learn each other's
//! key; an end that pinned another key for the peer refuses the exchange, whichever stage it
//! reads, and the pair connects once that end accepts the presented key; and an account with no
//! identity key still connects, unsigned. Ordering is by barriers and events, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{channel_from, offer_put_to_kernel, settings};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use crate::kex_identity::{Key, Store};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{
        localhost_max_security_level, server_test_node, wait_for_peers, TestBarrier,
    };
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Scenario {
        /// Both accounts sign; nothing is pinned yet.
        Signed,
        /// The dialled end pinned another key for the dialler: it refuses the dialler's Stage0.
        ResponderPinnedAnother,
        /// The dialler pinned another key for the dialled end: it refuses the reply, Stage1.
        InitiatorPinnedAnother,
        /// The dialler is a legacy account, with no identity key.
        LegacyDialler,
    }

    /// One end: `a_…` dials, `b_…` accepts. Returns what the pair's channel proved about the peer.
    async fn one_end(
        scenario: Scenario,
        store: Arc<Store>,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<Option<PeerKexIdentity>, NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let is_a = me.starts_with("a_");
        let dial = || {
            target.connect_to_peer_custom(
                settings(SecurityLevel::Standard),
                UdpMode::Disabled,
                None,
            )
        };
        wait_for_peers().await;
        let refusing_end = match scenario {
            Scenario::ResponderPinnedAnother => Some(false),
            Scenario::InitiatorPinnedAnother => Some(true),
            _ => None,
        };
        if let Some(refuser_is_a) = refusing_end {
            if is_a {
                let refused = dial().await.expect_err("the exchange is refused");
                assert!(
                    refused.to_string().contains("identity key changed"),
                    "refused as: {refused}"
                );
            } else {
                let offer = offer_put_to_kernel(&mut events).await;
                citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            }
            wait_for_peers().await;
            if is_a == refuser_is_a {
                let changes = store.changes();
                assert_eq!(changes.len(), 1, "one change is reported: {changes:?}");
                store.accept(changes[0].0, changes[0].1.clone());
            }
            wait_for_peers().await;
        }
        let channel = if is_a {
            channel_from(Some(dial()), &mut events).await
        } else {
            let offer = offer_put_to_kernel(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            channel_from(None::<std::future::Pending<_>>, &mut events).await
        };
        let identity = channel.peer_kex_identity().cloned();
        let (mut tx, mut rx) = channel.split();
        tx.send(SecBuffer::from(me.as_bytes())).await?;
        let heard = tokio::time::timeout(crate::dials::DEADLINE, rx.next())
            .await
            .expect("the peer's message")
            .expect("open channel");
        assert_eq!(heard.as_ref(), peer.as_bytes());
        wait_for_peers().await;
        conn.shutdown_kernel().await?;
        Ok(identity)
    }

    async fn run(scenario: Scenario) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let (a_key, b_key) = (Key::new(1), Key::new(2));
        let (a_public, b_public) = (a_key.public(), b_key.public());
        let a_store = Arc::new(match scenario {
            Scenario::LegacyDialler => Store::legacy(),
            Scenario::InitiatorPinnedAnother => Store::pinned_to_another(a_key),
            _ => Store::new(a_key),
        });
        let b_store = Arc::new(match scenario {
            Scenario::ResponderPinnedAnother => Store::pinned_to_another(b_key),
            _ => Store::new(b_key),
        });
        let node = |me: String, peer: String, store: Arc<Store>| {
            let port: P2pKexIdentities = store.clone();
            citadel_sdk::test_common::node_builder()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(localhost_max_security_level())
                .with_p2p_kex_identity(port)
                .build(GroupTestKernel::new(move |remote, events| async move {
                    let identity = one_end(scenario, store.clone(), remote, events, addr, me, peer);
                    store.record_channel(identity.await?);
                    Ok(())
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(
            node(a, b.clone(), a_store.clone()),
            node(b, format!("a_{tag}"), b_store.clone()),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.unwrap_or_else(|err| panic!("{scenario:?}: {err}"));
        let signed = |key: &[u8]| {
            Some(PeerKexIdentity::Signed {
                identity_key: key.to_vec(),
            })
        };
        let b_saw = match scenario {
            Scenario::LegacyDialler => Some(PeerKexIdentity::Unsigned),
            _ => signed(&a_public),
        };
        assert_eq!(
            a_store.channel(),
            signed(&b_public),
            "{scenario:?}: the dialler's channel"
        );
        assert_eq!(
            b_store.channel(),
            b_saw,
            "{scenario:?}: the dialled end's channel"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn both_ends_of_a_signed_pair_learn_each_others_identity_key() {
        run(Scenario::Signed).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dialled_end_refuses_a_changed_key_until_it_is_accepted() {
        run(Scenario::ResponderPinnedAnother).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_dialler_refuses_a_changed_key_until_it_is_accepted() {
        run(Scenario::InitiatorPinnedAnother).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_legacy_account_connects_unsigned_and_still_checks_its_peer() {
        run(Scenario::LegacyDialler).await;
    }
}
