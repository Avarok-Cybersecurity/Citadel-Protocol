//! Media transport agreed in band: the endpoint is the negotiation shell for one setting,
//! [`MediaTransport`], over the connection's negotiation lane.
//!
//! Each side asks for its own transport -- unreliable (UDP) if it holds the session's UDP
//! channel, reliable otherwise -- before it reads anything the peer sent for the setting. So the
//! two requests always cross, and both ends take the same merge of the pair: reliable when either
//! asked for it. Neither end decides from its own timer alone.

use super::config::MediaTransportConfig;
use super::transport::MediaTransportKind;
use citadel_io::time::{sleep_until, Instant};
use citadel_io::ErrorCode;
use citadel_negotiation::settings::MediaTransport;
use citadel_negotiation::{CapabilityBits, Hello};
use citadel_negotiation::{
    Command, Input, Millis, NegotiationState, Negotiator, NegotiatorConfig, PeerSupport, SettingId,
};
use citadel_proto::constants::{
    protocol_version_at_least, MEDIA_TRANSPORT_OFFER_SINCE, PROTOCOL_VERSION,
};
use citadel_proto::prelude::{NegotiationLane, NetworkError, PeerChannel, Ratchet, SettingLane};

/// How the two ends of a media session agreed on its transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaAgreement {
    /// Over the negotiation lane; `epoch` is the setting's agreed epoch.
    InBand { epoch: u32 },
    /// By the transport offers each side sends first on the reliable channel (a peer, or a lane,
    /// that does not negotiate media in band).
    Offers,
    /// The peer predates transport offers: reliable, without asking.
    PeerPredatesOffers,
}

/// The setting this module negotiates, as both sides' Hello must list it.
pub(super) const SETTING: SettingId = SettingId::MEDIA_TRANSPORT;

/// The channel's negotiation lane for media: the one the application opened, or one this
/// endpoint opens offering media alone. `None` on a client-server channel.
pub(super) fn lane_of<R: Ratchet>(channel: &mut PeerChannel<R>) -> Option<NegotiationLane<R>> {
    if let Some(lane) = channel.negotiation_lane() {
        return Some(lane);
    }
    let hello = Hello {
        protocol: *PROTOCOL_VERSION,
        settings: vec![(SETTING, CapabilityBits::IN_BAND)],
    };
    channel.open_negotiation(hello).ok()
}

/// The agreement the transport offers give, by the peer's version.
pub(super) fn agreement_by_offers(peer_protocol_version: Option<u32>) -> MediaAgreement {
    if protocol_version_at_least(peer_protocol_version, MEDIA_TRANSPORT_OFFER_SINCE) {
        MediaAgreement::Offers
    } else {
        MediaAgreement::PeerPredatesOffers
    }
}

/// Whether media is negotiated in band on this lane: both Hellos must offer it.
pub(super) async fn negotiates_in_band<R: Ratchet>(
    lane: &NegotiationLane<R>,
) -> Result<bool, NetworkError> {
    let peer = lane.peer_hello().await?;
    Ok(lane.local_offers(SETTING) && peer.support_for(SETTING) == PeerSupport::InBand)
}

/// Runs the negotiation to its end and returns the agreed transport and epoch.
pub(super) async fn agree<R: Ratchet>(
    lane: &NegotiationLane<R>,
    setting: SettingLane,
    cids: (u64, u64),
    local_udp: bool,
    cfg: &MediaTransportConfig,
) -> Result<(MediaTransportKind, u32), NetworkError> {
    let failed = |what: String| citadel_io::error!(ErrorCode::MediaControlDecode, what);
    let lowest = MediaTransport {
        kind: MediaTransportKind::Unreliable,
    };
    let mut negotiator = Negotiator::new(NegotiatorConfig {
        local: cids.0,
        peer: cids.1,
        initial: lowest,
        minimum: lowest,
        support: PeerSupport::InBand,
        policy: cfg.negotiation,
    })
    .map_err(|err| failed(format!("media negotiator: {err:?}")))?;
    let start = Instant::now();
    let now = || Millis(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
    let wanted = MediaTransport {
        kind: if local_udp {
            MediaTransportKind::Unreliable
        } else {
            MediaTransportKind::Reliable
        },
    };
    let SettingLane { port, mut frames } = setting;
    let mut pending = negotiator.step(now(), Input::Request(wanted));
    loop {
        let mut next = Vec::new();
        for command in pending.drain(..) {
            match command {
                Command::Send(envelope) => {
                    if port.post(lane.connection(), envelope).is_err() {
                        next.push(Input::SendFailed);
                    }
                }
                Command::ApplyLocal { epoch, .. } => next.push(Input::LocalOutcome {
                    epoch,
                    result: Ok(()),
                }),
                Command::Report(event) => match event.state {
                    NegotiationState::Applied { agreed, .. } => {
                        return Ok((agreed.kind, event.epoch.0));
                    }
                    NegotiationState::FellBack { reason, .. } => {
                        return Err(failed(format!(
                            "media transport negotiation fell back: {reason:?}"
                        )));
                    }
                    other => log::trace!(target: "citadel", "media negotiation: {other:?}"),
                },
                Command::Drop { reason, .. } => {
                    return Err(failed(format!(
                        "media transport negotiation dropped: {reason:?}"
                    )));
                }
                Command::ApplyKeyEpoch { .. } | Command::RaiseFloor { .. } => {}
            }
        }
        for input in next {
            pending.extend(negotiator.step(now(), input));
        }
        if !pending.is_empty() {
            continue;
        }
        let wake = negotiator
            .next_wake()
            .map(|at| start + std::time::Duration::from_millis(at.0));
        let input = citadel_io::tokio::select! {
            frame = frames.recv() => match frame {
                Some(envelope) => Input::Recv(envelope),
                None => return Err(citadel_io::error!(
                    ErrorCode::MediaTransportClosed,
                    "the connection ended during the media transport negotiation"
                )),
            },
            _ = async {
                match wake {
                    Some(at) => sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => Input::Tick,
        };
        pending = negotiator.step(now(), input);
    }
}
