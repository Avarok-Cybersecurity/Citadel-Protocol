#![cfg(not(target_family = "wasm"))]
//! A connection closed on purpose is reported with its reason; one that is simply lost, without.
//!
//! A deliberate drop and a lost link used to reach the peer the same way, so a peer could only
//! redial. Here the same pair opens two links. The first is closed with
//! `NegotiationLane::close_with_reason`: the peer reports its end with that reason. The second
//! ends because the closing node shuts down: the peer reports that end with no reason.
//!
//! Ordering is by events and barriers, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/dials.rs"]
#[allow(dead_code)]
mod dials;

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/lane.rs"]
#[allow(dead_code)]
mod lane;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::DEADLINE;
    use crate::group::{register_connect_and_befriend, Events};
    use crate::lane::{first_end_of, hello, open_link, reason_for_end_of, run_pair};
    use citadel_io::tokio;
    use citadel_sdk::citadel_negotiation::{RenegotiationReason, SettingId};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;

    const REASON: DisconnectReason = DisconnectReason::Renegotiation {
        setting: SettingId::KEY_PROFILE,
        reason: RenegotiationReason::HandshakeRequired(SettingId::KEY_PROFILE),
    };

    async fn one_end(
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let closer = me.starts_with("a_");
        wait_for_peers().await;

        let mut first =
            open_link(&remote, &target, &mut events, &me, SecurityLevel::Standard).await?;
        let first_id = first
            .connection_id()
            .expect("a P2P channel names its connection");
        let lane = first.open_negotiation(hello(&[]))?;
        let halves = first.split();
        wait_for_peers().await;
        if closer {
            lane.close_with_reason(REASON, DEADLINE).await?;
        } else {
            let reason = reason_for_end_of(&mut events, first_id).await;
            assert_eq!(
                reason,
                Some(REASON),
                "a deliberate drop reaches the peer with its reason"
            );
        }
        wait_for_peers().await;
        drop(halves);

        let second = open_link(&remote, &target, &mut events, &me, SecurityLevel::Standard).await?;
        let second_id = second
            .connection_id()
            .expect("a P2P channel names its connection");
        let _halves = second.split();
        wait_for_peers().await;
        if closer {
            return conn.shutdown_kernel().await;
        }
        let reason = first_end_of(&mut events, second_id).await;
        assert_eq!(reason, None, "a link that is lost carries no reason");
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn deliberate_drop_is_not_a_lost_link() {
        run_pair(one_end).await;
    }
}
