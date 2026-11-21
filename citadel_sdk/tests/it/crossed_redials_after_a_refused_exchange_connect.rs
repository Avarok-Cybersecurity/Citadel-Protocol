#![cfg(not(target_family = "wasm"))]
//! A refused key exchange leaves the pair free to connect again: two dials that cross right after
//! the refusing end accepts the peer's new key are merged by the server and connect.
//!
//! The dialled end has pinned another key for the dialler, so it refuses the first exchange and
//! reports the presented key; it accepts that key, and then both ends dial each other. The
//! higher CID dials first and the lower dials once that offer reaches it, so neither end's
//! client tiebreak can answer the crossing: only the server's merge connects the pair.
//! Ordering is by barriers and events, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{channel_from, next_offer, offer_put_to_kernel, settings};
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

    /// `a_…` dials first and `b_…` refuses it; then the two dial each other.
    async fn one_end(
        store: Arc<Store>,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let peer_cid = target
            .try_as_peer_connection()
            .await?
            .get_original_target_cid();
        let dial = || {
            target.connect_to_peer_custom(
                settings(SecurityLevel::Standard),
                UdpMode::Disabled,
                None,
            )
        };
        wait_for_peers().await;
        if me.starts_with("a_") {
            let refused = dial().await.expect_err("the exchange is refused");
            assert!(
                refused.to_string().contains("identity key changed"),
                "refused as: {refused}"
            );
            wait_for_peers().await;
        } else {
            let offer = offer_put_to_kernel(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            wait_for_peers().await;
            let changes = store.changes();
            assert_eq!(changes.len(), 1, "one change is reported: {changes:?}");
            store.accept(changes[0].0, changes[0].1.clone());
        }
        wait_for_peers().await;

        let channel = if conn.cid > peer_cid {
            channel_from(Some(dial()), &mut events).await
        } else {
            let _crossing = next_offer(&mut events).await;
            channel_from(Some(dial()), &mut events).await
        };
        let (mut tx, mut rx) = channel.split();
        tx.send(SecBuffer::from(me.as_bytes())).await?;
        let heard = tokio::time::timeout(crate::dials::DEADLINE, rx.next())
            .await
            .expect("the peer's message")
            .expect("open channel");
        assert_eq!(heard.as_ref(), peer.as_bytes());
        wait_for_peers().await;
        conn.shutdown_kernel().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn crossed_redials_after_an_accepted_key_change_connect() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let a_store = Arc::new(Store::new(Key::new(1)));
        let b_store = Arc::new(Store::pinned_to_another(Key::new(2)));
        let node = |me: String, peer: String, store: Arc<Store>| {
            let port: P2pKexIdentities = store.clone();
            citadel_sdk::test_common::node_builder()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(localhost_max_security_level())
                .with_p2p_kex_identity(port)
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(store, remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients =
            futures::future::try_join(node(a.clone(), b.clone(), a_store), node(b, a, b_store));
        let outcome = citadel_io::time::runnable_timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.unwrap_or_else(|err| panic!("{err}"));
    }
}
