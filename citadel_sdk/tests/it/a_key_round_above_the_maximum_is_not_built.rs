#![cfg(not(target_family = "wasm"))]
//! A live link can raise its key profile in band, one steered ratchet round adding layers. The
//! node's maximum security level bounds that round on both ends, whatever a negotiator agreed:
//! the receiving end (maximum High) refuses a round building Ultra even though its gate's
//! admitter says build, and the sending end refuses to start a round above its own maximum.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{channel_from, next_offer, settings};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_negotiation::ports::KeyExchange;
    use citadel_negotiation::settings::KeyProfile;
    use citadel_negotiation::{Epoch, KeyExchangeOutcome, NegotiationPolicy, RoundAdmission};
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::negotiation::key_epoch::{KeyEpochPort, RoundAdmitter};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{localhost_max_security_level, server_test_node};
    use citadel_sdk::test_common::{wait_for_peers, TestBarrier};
    use std::sync::Arc;
    use std::time::Duration;

    /// Test rationale (PCND): one round on loopback ends well within 30 s; the bound only has
    /// to end a round the receiver never answers.
    const POLICY: NegotiationPolicy = NegotiationPolicy {
        proposal_deadline: Duration::from_secs(30),
        apply_deadline: Duration::from_secs(30),
        max_apply_attempts: 1,
        udp_retire_grace: None,
    };

    /// An admitter that agrees to every round: only the node's maximum stands in the way.
    struct AlwaysBuild;

    impl RoundAdmitter for AlwaysBuild {
        fn admit_key_round(&self, _epoch: Epoch, _profile: &KeyProfile) -> RoundAdmission {
            RoundAdmission::Build
        }
    }

    async fn one_end(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        wait_for_peers().await;
        let start = settings(SecurityLevel::Reinforced);
        let channel = if me.starts_with("a_") {
            let dial = target.connect_to_peer_custom(start, UdpMode::Disabled, None);
            channel_from(Some(dial), &mut events).await
        } else {
            let offer = next_offer(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            channel_from(None::<std::future::Pending<_>>, &mut events).await
        };
        let handle = channel
            .key_epoch()
            .expect("a P2P channel has a key-epoch handle");
        let port = KeyEpochPort::new(handle.clone(), &POLICY);
        let _rounds = port.install_gate(Arc::new(AlwaysBuild), Arc::new(Default::default()));
        wait_for_peers().await;
        let ultra = KeyProfile::new(SecurityLevel::Ultra, start.crypto_params);
        let outcome = port.apply(handle.connection_id(), Epoch(1), ultra).await;
        if me.starts_with("a_") {
            assert!(
                matches!(
                    outcome,
                    KeyExchangeOutcome::Refused(_) | KeyExchangeOutcome::Failed(_)
                ),
                "the receiver built a round above its maximum: {outcome:?}"
            );
        } else {
            let KeyExchangeOutcome::Failed(reason) = outcome else {
                panic!("a round above this side's maximum was started: {outcome:?}");
            };
            assert!(reason.contains("above this node's maximum"), "{reason}");
        }
        let level = handle.negotiated().expect("a profile").level();
        assert_eq!(
            level.value(),
            SecurityLevel::Reinforced.value(),
            "{me} stayed"
        );
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_key_round_above_the_maximum_is_not_built() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String, max: MaxSecurityLevel| {
            citadel_sdk::test_common::node_builder()
                .with_link_manager(citadel_sdk::prelude::LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .with_max_security_level(max)
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let high = MaxSecurityLevel::new(SecurityLevel::High).unwrap();
        let clients = futures::future::try_join(
            node(a.clone(), b.clone(), localhost_max_security_level()),
            node(b, a, high),
        );
        let outcome = tokio::time::timeout(Duration::from_secs(150), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("neither end builds above its maximum");
    }
}
