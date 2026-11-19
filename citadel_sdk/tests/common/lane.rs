//! Helpers for tests of a P2P connection's negotiation lane and of deliberate drops.

use crate::dials::{channel_from, next_offer, settings, DEADLINE};
use crate::group::Events;
use citadel_io::tokio;
use citadel_sdk::citadel_negotiation::{CapabilityBits, Hello, NegotiationPolicy, SettingId};
use citadel_sdk::prelude::*;
use std::time::Duration;

/// Test bound (PCND): generous for a loaded CI runner. A peer answers on receipt, so in a
/// passing run nothing waits on these.
pub const POLICY: NegotiationPolicy = NegotiationPolicy {
    proposal_deadline: Duration::from_secs(30),
    apply_deadline: Duration::from_secs(30),
    max_apply_attempts: 1,
    udp_retire_grace: None,
};

/// A Hello offering `settings` in band.
pub fn hello(settings: &[SettingId]) -> Hello {
    Hello {
        protocol: *citadel_proto::constants::PROTOCOL_VERSION,
        settings: settings
            .iter()
            .map(|id| (*id, CapabilityBits::IN_BAND))
            .collect(),
    }
}

/// Opens a P2P link at `level`: the end whose name starts with `a_` dials, the other accepts.
pub async fn open_link(
    remote: &NodeRemote<StackedRatchet>,
    target: &SymmetricIdentifierHandleRef<'_, StackedRatchet>,
    events: &mut Events,
    me: &str,
    level: SecurityLevel,
) -> Result<PeerChannel<StackedRatchet>, NetworkError> {
    if me.starts_with("a_") {
        let dial = target.connect_to_peer_custom(settings(level), UdpMode::Disabled, None);
        Ok(channel_from(Some(dial), events).await)
    } else {
        let offer = next_offer(events).await;
        citadel_sdk::responses::peer_connect(offer, true, remote, None).await?;
        Ok(channel_from(None::<std::future::Pending<_>>, events).await)
    }
}

/// The reason of the first `Disconnect` this end hears that ends `connection`: one naming it, or
/// the server's notice (naming no connection) that the peer's whole session ended.
pub async fn first_end_of(events: &mut Events, connection: Ticket) -> Option<DisconnectReason> {
    let wait = async {
        while let Some(event) = events.recv().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::Disconnect {
                        disconnect_token,
                        reason,
                        ..
                    },
                ..
            }) = event
            {
                if disconnect_token.is_none_or(|token| token.connection_id == connection) {
                    return reason;
                }
            }
        }
        panic!("the event stream ended before the connection's end");
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the connection's end is reported")
}

/// The reason any report of `connection`'s end carries, or `None` if none carries one within
/// the deadline (each end of a connection may be reported more than once: by the server and by
/// the direct route).
pub async fn reason_for_end_of(
    events: &mut Events,
    connection: Ticket,
) -> Option<DisconnectReason> {
    let wait = async {
        while let Some(event) = events.recv().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::Disconnect {
                        disconnect_token: Some(token),
                        reason: Some(reason),
                        ..
                    },
                ..
            }) = event
            {
                if token.connection_id == connection {
                    return reason;
                }
            }
        }
        panic!("the event stream ended before a reasoned end");
    };
    tokio::time::timeout(DEADLINE, wait).await.ok()
}

/// A `Disconnect` with no reason: what a server below `NEGOTIATION_SINCE` delivers whatever the
/// sender gave, sent here by the closing end itself.
pub async fn disconnect_without_reason(
    remote: &NodeRemote<StackedRatchet>,
    channel_cid: u64,
    link: PeerConnectionType,
) -> Result<(), NetworkError> {
    let command = NodeRequest::PeerCommand(PeerCommand {
        session_cid: channel_cid,
        command: PeerSignal::Disconnect {
            peer_conn_type: link,
            disconnect_response: None,
            disconnect_token: None,
            reason: None,
        },
    });
    remote.send(command).await.map(|_| ())
}

/// Runs `one_end` on two clients (`a_…` and `b_…`) of one in-process server.
pub async fn run_pair<F, Fut>(one_end: F)
where
    F: Fn(NodeRemote<StackedRatchet>, Events, std::net::SocketAddr, String, String) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: std::future::Future<Output = Result<(), NetworkError>> + Send + 'static,
{
    use crate::group::GroupTestKernel;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::test_common::{server_test_node, TestBarrier};
    citadel_logging::setup_log();
    TestBarrier::setup(2);
    let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |_| {});
    let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (a, b) = (format!("a_{tag}"), format!("b_{tag}"));
    let node = |me: String, peer: String| {
        let one_end = one_end.clone();
        DefaultNodeBuilder::default()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .build(GroupTestKernel::new(move |remote, events| {
                one_end(remote, events, addr, me, peer)
            }))
            .unwrap()
    };
    let clients = futures::future::try_join(node(a.clone(), b.clone()), node(b, a));
    let outcome = tokio::time::timeout(Duration::from_secs(150), async move {
        tokio::select! {
            res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
            res = clients => res.map(|_| ()),
        }
    })
    .await
    .expect("test timed out");
    outcome.expect("both ends finish");
}
