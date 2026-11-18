#![cfg(not(target_family = "wasm"))]
//! Toward a peer that does not negotiate the key profile in band, a raise falls back to a
//! deliberate drop and a redial -- and the peer is told why, so only one side redials.
//!
//! `b` offers nothing in band (it splits its channel without opening the lane, so its Hello is
//! empty: a legacy peer for every setting). `a` asks its negotiator for Extreme. The negotiator
//! falls back (`PeerLegacy`) and says `a` redials. `a` closes the link with that reason and
//! dials again at Extreme. `b` plays its supervisor's part: it redials only after a drop it was
//! given no reason for; given one, it waits to be dialled and accepts. Both ends then hold a
//! link at Extreme.
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
    use crate::dials::{channel_from, next_offer, settings, DEADLINE};
    use crate::group::{register_connect_and_befriend, Events};
    use crate::lane::{first_end_of, hello, open_link, run_pair, POLICY};
    use citadel_io::tokio;
    use citadel_sdk::citadel_negotiation::settings::KeyProfile;
    use citadel_sdk::citadel_negotiation::{
        Command, Input, Millis, NegotiationState, Negotiator, NegotiatorConfig,
        RenegotiationReason, SettingId,
    };
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;

    /// What `a`'s negotiator decides for a raise toward `peer_support`: the drop's reason, the
    /// value to redial at, and whether `a` redials.
    fn fall_back(
        channel: &PeerChannel<StackedRatchet>,
        peer: &citadel_sdk::citadel_negotiation::Hello,
    ) -> (DisconnectReason, KeyProfile, bool) {
        let opened = KeyProfile::of(&channel.session_security_settings());
        let mut negotiator = Negotiator::new(NegotiatorConfig {
            local: channel.get_session_cid(),
            peer: channel.get_peer_cid(),
            initial: opened,
            minimum: opened,
            bound: channel
                .key_epoch()
                .expect("a P2P channel has a key-epoch handle")
                .max_security_level(),
            support: peer.support_for(SettingId::KEY_PROFILE),
            policy: POLICY,
        })
        .expect("a valid negotiator");
        let raise = KeyProfile::new(SecurityLevel::Extreme, opened.params());
        let commands = negotiator.step(Millis(0), Input::Request(raise));
        let we_redial = commands.iter().find_map(|command| match command {
            Command::Report(event) => match &event.state {
                NegotiationState::FellBack { we_redial, .. } => Some(*we_redial),
                _ => None,
            },
            _ => None,
        });
        let drop = commands.into_iter().find_map(|command| match command {
            Command::Drop { reason, next } => Some((reason, next)),
            _ => None,
        });
        let (reason, next) = drop.expect("a raise toward a legacy peer is a deliberate drop");
        assert_eq!(reason, RenegotiationReason::PeerLegacy);
        let reason = DisconnectReason::Renegotiation {
            setting: SettingId::KEY_PROFILE,
            reason,
        };
        (reason, next, we_redial.expect("the fallback is reported"))
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
        let mut first =
            open_link(&remote, &target, &mut events, &me, SecurityLevel::Standard).await?;
        let first_id = first
            .connection_id()
            .expect("a P2P channel names its connection");
        let relinked = if me.starts_with("a_") {
            let lane = first.open_negotiation(hello(&[SettingId::KEY_PROFILE]))?;
            let peer_hello = lane.peer_hello().await?;
            let (reason, next, we_redial) = fall_back(&first, &peer_hello);
            assert!(we_redial, "toward a legacy peer, the requester redials");
            let _halves = first.split();
            lane.close_with_reason(reason, DEADLINE).await?;
            let dial =
                target.connect_to_peer_custom(settings(next.level()), UdpMode::Disabled, None);
            channel_from(Some(dial), &mut events).await
        } else {
            let _halves = first.split();
            let reason = first_end_of(&mut events, first_id).await;
            assert!(
                matches!(reason, Some(DisconnectReason::Renegotiation { .. })),
                "b was given no reason, so it would redial too: {reason:?}"
            );
            let offer = next_offer(&mut events).await;
            citadel_sdk::responses::peer_connect(offer, true, &remote, None).await?;
            channel_from(None::<std::future::Pending<_>>, &mut events).await
        };
        assert_eq!(
            relinked.session_security_settings().security_level.value(),
            SecurityLevel::Extreme.value(),
            "{me}'s redialled link is at the agreed level"
        );
        wait_for_peers().await;
        drop(relinked);
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn legacy_peer_falls_back_with_a_reason() {
        run_pair(one_end).await;
    }
}
