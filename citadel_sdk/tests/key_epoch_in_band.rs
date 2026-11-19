#![cfg(not(target_family = "wasm"))]
//! A live P2P link changes its key profile in band: one steered ratchet round, no drop.
//!
//! Each end runs N0's negotiator in a test shell (`common/negotiation_shell.rs`) over its real
//! `PeerChannel`; the SDK's `KeyEpochPort` carries the agreed profile out. The links start at
//! Reinforced. Ordering is by events and barriers, never by sleeps. NEGOTIATION-LAYER.md §9.2.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/dials.rs"]
#[allow(dead_code)]
mod dials;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/negotiation_shell.rs"]
mod shell;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/negotiation_shell_parts.rs"]
mod shell_parts;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/key_epoch_log.rs"]
mod key_epoch_log;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/key_epoch_steps.rs"]
mod steps;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::{channel_from, next_offer, settings, DEADLINE};
    use crate::group::{register_connect_and_befriend, Events, GroupTestKernel};
    use crate::key_epoch_log::AeadFailures;
    use crate::shell::Shell;
    use crate::steps::{
        applied, assert_stayed_in_band, crossing_hook, floor_refuses_below_the_agreed_level,
        profile, receive_numbered, send_numbered, Scenario,
    };
    use citadel_io::tokio;
    use citadel_negotiation::{NegotiationState, RejectReason};
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers, TestBarrier};
    use std::time::Duration;

    const START: SecurityLevel = SecurityLevel::Reinforced;

    async fn one_end(
        scenario: Scenario,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?.into_owned();
        let link = target.try_as_peer_connection().await?;
        let leads = conn.cid < link.get_original_target_cid();
        let is_a = me.starts_with("a_");
        wait_for_peers().await;
        let dial = target.connect_to_peer_custom(settings(START), UdpMode::Disabled, None);
        let channel = if is_a {
            channel_from(Some(dial), &mut events).await
        } else {
            let _offer = next_offer(&mut events).await;
            channel_from(Some(dial), &mut events).await
        };
        let connection = channel.connection_id();
        let (hook, mut crossing_rekey) = match scenario {
            Scenario::Crossing if !leads => {
                let (hook, done) = crossing_hook(target.clone());
                (Some(hook), Some(done))
            }
            _ => (None, None),
        };
        let mut shell = Shell::start(channel, profile(SecurityLevel::Standard), hook);
        let mut seen = Vec::new();
        let tag = if is_a { "a" } else { "b" };
        let peer_tag = if is_a { "b" } else { "a" };
        wait_for_peers().await;

        let target_level = match scenario {
            Scenario::Glare { a, b } => {
                shell.hold_inbound();
                send_numbered(&shell, tag, 0, 100).await;
                shell.request(profile(if is_a { a } else { b }));
                shell
                    .until(&mut seen, |s| {
                        matches!(s, NegotiationState::Proposed { by_us: true, .. }).then_some(())
                    })
                    .await;
                wait_for_peers().await;
                shell.release_inbound();
                send_numbered(&shell, tag, 100, 100).await;
                receive_numbered(&mut shell, peer_tag, 200).await;
                SecurityLevel::from(a.value().max(b.value()))
            }
            Scenario::Cutover | Scenario::Floor => {
                send_numbered(&shell, tag, 0, 100).await;
                if is_a {
                    shell.request(profile(SecurityLevel::Extreme));
                }
                send_numbered(&shell, tag, 100, 100).await;
                SecurityLevel::Extreme
            }
            Scenario::Crossing => {
                send_numbered(&shell, tag, 0, 50).await;
                if !leads {
                    // The Accept is held back, so the Leader's steered round can reach this side
                    // before it has seen the Accept: the gate must hold that round for the
                    // later step, not refuse it.
                    shell.hold_inbound();
                    shell.request(profile(SecurityLevel::Extreme));
                }
                send_numbered(&shell, tag, 50, 50).await;
                if let Some(done) = crossing_rekey.take() {
                    // Released once the Leader's round is held here, or once the plain rekey
                    // won the crossing and resolved (its round then supersedes the Leader's).
                    let mut held = shell.held.clone();
                    tokio::select! {
                        res = held.wait_for(|n| *n > 0) => { res.expect("the shell is running"); }
                        res = done => { res.expect("the plain rekey resolves"); }
                    }
                    shell.release_inbound();
                }
                SecurityLevel::Extreme
            }
        };
        let agreed = tokio::time::timeout(DEADLINE, shell.until(&mut seen, applied))
            .await
            .expect("the epoch applies in band");
        assert_eq!(
            agreed.level().value(),
            target_level.value(),
            "{me} applied {agreed:?}"
        );
        let sent_after = match scenario {
            Scenario::Glare { .. } => 0,
            Scenario::Cutover | Scenario::Floor => {
                send_numbered(&shell, tag, 200, 100).await;
                receive_numbered(&mut shell, peer_tag, 300).await;
                300
            }
            Scenario::Crossing => {
                receive_numbered(&mut shell, peer_tag, 100).await;
                100
            }
        };

        if let (Scenario::Glare { a, b }, false) = (scenario, is_a) {
            if b.value() < a.value() {
                assert!(
                    seen.iter().any(|s| matches!(
                        s,
                        NegotiationState::Rejected {
                            reason: RejectReason::Superseded,
                            ..
                        }
                    )),
                    "{me}'s lower request reports Superseded: {seen:?}"
                );
            }
        }
        if let Scenario::Floor = scenario {
            floor_refuses_below_the_agreed_level(&mut shell, is_a, peer_tag, sent_after).await;
        }

        assert_stayed_in_band(
            &shell,
            &me,
            leads,
            target_level,
            connection,
            &mut events,
            &seen,
        );
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    async fn run(scenario: Scenario) {
        let aead = AeadFailures::install();
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
        let node = |me: String, peer: String| {
            DefaultNodeBuilder::default()
                .with_link_manager(LinkManagerMode::Legacy)
                .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
                .build(GroupTestKernel::new(move |remote, events| {
                    one_end(scenario, remote, events, addr, me, peer)
                }))
                .unwrap()
        };
        let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
        let outcome = tokio::time::timeout(Duration::from_secs(240), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = clients => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("both ends change the profile in band");
        assert_eq!(
            aead.count(),
            0,
            "no frame failed authentication across the cutover"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn both_raise_at_once_in_band() {
        run(Scenario::Glare {
            a: SecurityLevel::Extreme,
            b: SecurityLevel::Extreme,
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn one_raises_one_lowers_in_band() {
        run(Scenario::Glare {
            a: SecurityLevel::Extreme,
            b: SecurityLevel::Standard,
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn messages_cross_the_cutover_intact() {
        run(Scenario::Cutover).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn floor_refuses_old_version_and_low_level() {
        run(Scenario::Floor).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_plain_rekey_crossing_the_epoch_round() {
        run(Scenario::Crossing).await;
    }
}
