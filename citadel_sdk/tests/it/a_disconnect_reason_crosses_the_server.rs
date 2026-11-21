#![cfg(not(target_family = "wasm"))]
//! A deliberate drop's reason reaches the peer whichever server is between them.
//!
//! The server does not relay a peer's `PeerSignal::Disconnect` as bytes: it decodes the signal
//! and builds the ones it sends from the fields it knows. So the appended `reason` survives only
//! a server that copies it (one at `NEGOTIATION_SINCE` or later), and an older server delivers
//! the signal without it. The connection's own lane carries the reason past such a server.
//!
//! - `a_server_copies_the_reason_into_the_signal_it_builds`: no lane frame is sent; the reason
//!   reaches the peer only because this server copies it.
//! - `the_lane_carries_the_reason_past_a_server_that_drops_it`: the reason goes over the lane,
//!   and the `Disconnect` that follows carries none -- exactly what an older server delivers.
//!
//! Ordering is by events and barriers, never by sleeps.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::dials::DEADLINE;
    use crate::group::{register_connect_and_befriend, Events};
    use crate::lane::{disconnect_without_reason, hello, open_link, reason_for_end_of, run_pair};
    use citadel_io::tokio;
    use citadel_sdk::citadel_negotiation::{RenegotiationReason, SettingId};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;

    const REASON: DisconnectReason = DisconnectReason::Renegotiation {
        setting: SettingId::KEY_PROFILE,
        reason: RenegotiationReason::ApplyFailed(SettingId::KEY_PROFILE),
    };

    #[derive(Clone, Copy)]
    enum Route {
        /// The reason rides only in the signal.
        Signal,
        /// The reason rides only on the lane.
        Lane,
    }

    async fn one_end(
        route: Route,
        remote: NodeRemote<StackedRatchet>,
        mut events: Events,
        addr: std::net::SocketAddr,
        me: String,
        peer: String,
    ) -> Result<(), NetworkError> {
        let conn = register_connect_and_befriend(&remote, addr, &me, &peer).await?;
        let target = conn.find_target(conn.cid, peer.clone()).await?;
        let link = target.try_as_peer_connection().await?;
        wait_for_peers().await;
        let mut channel =
            open_link(&remote, &target, &mut events, &me, SecurityLevel::Standard).await?;
        let connection = channel
            .connection_id()
            .expect("a P2P channel names its connection");
        let lane = channel.open_negotiation(hello(&[]))?;
        let _halves = channel.split();
        wait_for_peers().await;
        if me.starts_with("a_") {
            match route {
                Route::Signal => {
                    let command = NodeRequest::PeerCommand(PeerCommand {
                        session_cid: conn.cid,
                        command: PeerSignal::Disconnect {
                            peer_conn_type: link,
                            disconnect_response: None,
                            disconnect_token: None,
                            reason: Some(REASON),
                        },
                    });
                    remote.send(command).await?;
                }
                Route::Lane => {
                    lane.announce_closing(REASON, DEADLINE).await?;
                    disconnect_without_reason(&remote, conn.cid, link).await?;
                }
            }
        } else {
            let reason = reason_for_end_of(&mut events, connection).await;
            assert_eq!(
                reason,
                Some(REASON),
                "the peer reports the end with its reason"
            );
        }
        wait_for_peers().await;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_server_copies_the_reason_into_the_signal_it_builds() {
        run_pair(|remote, events, addr, me, peer| {
            one_end(Route::Signal, remote, events, addr, me, peer)
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn the_lane_carries_the_reason_past_a_server_that_drops_it() {
        run_pair(|remote, events, addr, me, peer| {
            one_end(Route::Lane, remote, events, addr, me, peer)
        })
        .await;
    }
}
