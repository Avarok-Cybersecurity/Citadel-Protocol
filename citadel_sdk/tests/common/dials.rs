//! Dialling helpers for tests that read the settings a P2P link was established with.

use crate::group::Events;
use citadel_io::tokio;
use citadel_sdk::prelude::*;
use citadel_sdk::remote_ext::results::PeerConnectSuccess;
use std::time::Duration;

pub const DEADLINE: Duration = Duration::from_secs(30);

pub fn settings(level: SecurityLevel) -> SessionSecuritySettings {
    SessionSecuritySettingsBuilder::default()
        .with_security_level(level)
        .build()
        .expect("valid settings")
}

pub fn post_connect(peer: PeerConnectionType, level: SecurityLevel) -> PeerSignal {
    PeerSignal::PostConnect {
        peer_conn_type: peer,
        ticket_opt: None,
        invitee_response: None,
        session_security_settings: settings(level),
        udp_mode: UdpMode::Disabled,
        session_password: None,
    }
}

/// The next inbound connect offer, left unanswered.
pub async fn next_offer(events: &mut Events) -> PeerSignal {
    while let Some(event) = events.recv().await {
        if let NodeResult::PeerEvent(PeerEvent {
            event:
                offer @ PeerSignal::PostConnect {
                    invitee_response: None,
                    ..
                },
            ..
        }) = event
        {
            return offer;
        }
    }
    panic!("the event stream ended before an offer arrived");
}

/// The next inbound connect offer, which must reach this end's kernel before any channel does:
/// a channel first means the protocol answered the offer without asking.
pub async fn offer_put_to_kernel(events: &mut Events) -> PeerSignal {
    let wait = async {
        while let Some(event) = events.recv().await {
            match event {
                NodeResult::PeerEvent(PeerEvent {
                    event:
                        offer @ PeerSignal::PostConnect {
                            invitee_response: None,
                            ..
                        },
                    ..
                }) => return offer,
                NodeResult::PeerChannelCreated(_) => {
                    panic!("a channel opened without the offer being put to this end's kernel")
                }
                _ => {}
            }
        }
        panic!("the event stream ended before an offer arrived");
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the offer reaches this end's kernel")
}

/// Runs `dial` (if any) until this end holds a channel, from the dial or from the events.
pub async fn channel_from(
    dial: Option<
        impl std::future::Future<Output = Result<PeerConnectSuccess<StackedRatchet>, NetworkError>>,
    >,
    events: &mut Events,
) -> PeerChannel<StackedRatchet> {
    let dial = async move {
        match dial {
            Some(dial) => dial.await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(dial);
    let wait = async {
        loop {
            tokio::select! {
                result = &mut dial => {
                    let success = result.expect("dial succeeds");
                    let negotiated = success.negotiated_security_settings().security_level;
                    let channel = success.channel;
                    assert_eq!(negotiated.value(), channel.session_security_settings().security_level.value());
                    return channel;
                }
                event = events.recv() => match event {
                    Some(NodeResult::PeerChannelCreated(created)) => return *created.channel,
                    Some(_) => {}
                    None => panic!("the event stream ended before a channel"),
                },
            }
        }
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("a channel within the deadline")
}
