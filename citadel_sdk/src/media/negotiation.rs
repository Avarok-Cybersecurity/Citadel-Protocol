//! The transport offer exchange that makes both ends of a media session agree
//! on UDP or the reliable lane.
use super::error::MediaResultExt;
use super::transport::{BoxedSource, MediaDatagramSink};
use bytes::BytesMut;
use citadel_io::ErrorCode;
use citadel_media::wire::{self, encode_control, WireMessage};
use citadel_media::ControlMessage;
use citadel_proto::constants::{protocol_version_at_least, MEDIA_TRANSPORT_OFFER_SINCE};
use citadel_proto::prelude::NetworkError;
use futures::StreamExt;

/// Whether media uses UDP: only if this side holds it and the peer's offer
/// says it does too. A peer whose protocol version predates transport offers,
/// or is unknown, sends none and reads none, so it is sent none and never
/// waited on: the answer is reliable.
pub(super) async fn agree_on_udp(
    peer_protocol_version: Option<u32>,
    local_udp: bool,
    sink: &mut dyn MediaDatagramSink,
    src: &mut BoxedSource,
) -> Result<bool, NetworkError> {
    if !protocol_version_at_least(peer_protocol_version, MEDIA_TRANSPORT_OFFER_SINCE) {
        log::warn!(target: "citadel", "media: peer protocol version {peer_protocol_version:?} predates transport offers; using reliable transport");
        return Ok(false);
    }
    let peer_udp = exchange_transport_offer(sink, src, local_udp).await?;
    Ok(local_udp && peer_udp)
}

/// Sends this side's transport offer as the first reliable message and reads
/// the peer's, which is likewise the first message on the ordered lane.
/// Returns whether the peer holds UDP. Each side's own UDP decision is local
/// and timer-bound, so only the pair of offers yields an agreed transport.
async fn exchange_transport_offer(
    sink: &mut dyn MediaDatagramSink,
    src: &mut BoxedSource,
    local_udp: bool,
) -> Result<bool, NetworkError> {
    let body = ControlMessage::TransportOffer { udp: local_udp }
        .encode()
        .net()?;
    sink.send_datagram(BytesMut::from(encode_control(&body).as_slice()))?;
    let reply = src.next().await.ok_or_else(|| {
        citadel_io::error!(
            ErrorCode::MediaTransportClosed,
            "reliable channel closed before the peer's transport offer"
        )
    })?;
    let malformed = |err| citadel_io::error!(ErrorCode::MediaControlDecode, err);
    match wire::parse(reply.as_ref()).map_err(malformed)? {
        WireMessage::Control(body) => match ControlMessage::decode(body).map_err(malformed)? {
            ControlMessage::TransportOffer { udp } => Ok(udp),
            other => Err(citadel_io::error!(
                ErrorCode::MediaControlDecode,
                format!("expected the peer's transport offer, got {other:?}")
            )),
        },
        WireMessage::Fragment { .. } => Err(citadel_io::error!(
            ErrorCode::MediaControlDecode,
            "expected the peer's transport offer, got a media fragment"
        )),
    }
}
