//! The transport agreement over the production `ReliableSink` pair: which
//! peers are sent an offer and waited on, and what the pair of offers yields.
use super::super::negotiation::agree_on_udp;
use super::{descriptor, run, source};
use crate::media::transport::{BoxedSource, ReliableSink};
use bytes::BytesMut;
use citadel_io::ErrorCode;
use citadel_media::wire::encode_control;
use citadel_media::ControlMessage;
use citadel_proto::constants::PROTOCOL_VERSION;
use citadel_proto::prelude::NetworkError;
use embedded_semver::Semver;

/// `0.10.0`: the last protocol version before transport offers.
fn pre_offer_version() -> Option<u32> {
    Some(Semver::new(0, 10, 0).to_u32().unwrap())
}

fn control(msg: ControlMessage) -> BytesMut {
    BytesMut::from(encode_control(&msg.encode().unwrap()).as_slice())
}

/// Runs the agreement with `peer_first` as the first message the peer puts on
/// the reliable lane, and returns the outcome with everything this side sent.
fn agree(
    peer_version: Option<u32>,
    local_udp: bool,
    peer_first: ControlMessage,
) -> (Result<bool, NetworkError>, Vec<ControlMessage>) {
    let mut outcome = None;
    let mut sent = Vec::new();
    run(async {
        let (mut sink, mut sent_rx) = ReliableSink::pair();
        let (mut peer, peer_rx) = ReliableSink::pair();
        use crate::media::transport::MediaDatagramSink;
        peer.send_datagram(control(peer_first)).unwrap();
        let mut src: BoxedSource = source(peer_rx);
        outcome = Some(agree_on_udp(peer_version, local_udp, &mut sink, &mut src).await);
        drop(sink);
        while let Some(datagram) = sent_rx.recv().await {
            match citadel_media::wire::parse(&datagram).unwrap() {
                citadel_media::WireMessage::Control(body) => {
                    sent.push(ControlMessage::decode(body).unwrap())
                }
                other => panic!("sent a non-control datagram: {other:?}"),
            }
        }
    });
    (outcome.unwrap(), sent)
}

fn old_peer_first_message() -> ControlMessage {
    ControlMessage::AnnounceTracks(vec![descriptor()])
}

/// A peer that predates offers never sends one; its first reliable message is
/// ordinary media control. It must not be read as a malformed offer.
#[test]
fn a_peer_that_predates_offers_gets_reliable_without_an_exchange() {
    let (outcome, sent) = agree(pre_offer_version(), true, old_peer_first_message());
    assert!(
        matches!(outcome, Ok(false)),
        "an older peer must fall back to reliable, not fail: {outcome:?}"
    );
    assert!(
        sent.is_empty(),
        "an older peer must be sent no offer: {sent:?}"
    );
}

/// Unknown: the peer, or a server relaying its key exchange, predates
/// carrying the version.
#[test]
fn a_peer_of_unknown_version_gets_reliable_without_an_exchange() {
    let (outcome, sent) = agree(None, true, old_peer_first_message());
    assert!(matches!(outcome, Ok(false)), "{outcome:?}");
    assert!(sent.is_empty(), "{sent:?}");
}

#[test]
fn udp_only_when_both_offers_say_so() {
    let current = Some(*PROTOCOL_VERSION);
    for (local, peer, expected) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        let (outcome, sent) = agree(current, local, ControlMessage::TransportOffer { udp: peer });
        assert_eq!(outcome.unwrap(), expected, "local={local} peer={peer}");
        assert_eq!(sent, vec![ControlMessage::TransportOffer { udp: local }]);
    }
}

/// A current peer's first message must be its offer.
#[test]
fn a_current_peer_without_an_offer_is_a_decode_error() {
    let (outcome, _) = agree(Some(*PROTOCOL_VERSION), true, old_peer_first_message());
    let err = outcome.expect_err("a current peer must lead with its offer");
    assert_eq!(err.code, ErrorCode::MediaControlDecode, "{err:?}");
}
