//! The transport agreement over the production `ReliableSink` pair: which
//! peers are sent an offer and waited on, and what the pair of offers yields.
use super::super::negotiation::agree_on_udp;
use super::{descriptor, run, source};
use crate::media::transport::{BoxedSource, ReliableSink};
use bytes::BytesMut;
use citadel_io::ErrorCode;
use citadel_media::wire::encode_control;
use citadel_media::ControlMessage;
use citadel_proto::prelude::NetworkError;

fn control(msg: ControlMessage) -> BytesMut {
    BytesMut::from(encode_control(&msg.encode().unwrap()).as_slice())
}

/// Runs the agreement with `peer_first` as the first message the peer puts on
/// the reliable lane, and returns the outcome with everything this side sent.
fn agree(
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
        outcome = Some(agree_on_udp(local_udp, &mut sink, &mut src).await);
        drop(sink);
        while let Some(datagram) = sent_rx.recv().await {
            match citadel_media::wire::parse(&datagram.buf).unwrap() {
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

#[test]
fn udp_only_when_both_offers_say_so() {
    for (local, peer, expected) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        let (outcome, sent) = agree(local, ControlMessage::TransportOffer { udp: peer });
        assert_eq!(outcome.unwrap(), expected, "local={local} peer={peer}");
        assert_eq!(sent, vec![ControlMessage::TransportOffer { udp: local }]);
    }
}

/// A peer's first message must be its offer: one that leads with ordinary media control (as a
/// peer before transport offers did) is refused, not read as "reliable".
/// `udp_only_when_both_offers_say_so` is the control.
#[test]
fn a_peer_without_an_offer_is_refused_as_a_decode_error() {
    let (outcome, _) = agree(true, old_peer_first_message());
    let err = outcome.expect_err("a current peer must lead with its offer");
    assert_eq!(err.code, ErrorCode::MediaControlDecode, "{err:?}");
}
