use super::*;
use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::traffic::ByteCount;
use bytes::BytesMut;
use zerocopy::byteorder::big_endian::U64;
use zerocopy::{AsBytes, FromZeroes};

fn packet(cmd: (u8, u8), session_cid: u64, target_cid: u64, payload: usize) -> BytesMut {
    let mut header = HdpHeader::new_zeroed();
    header.cmd_primary = cmd.0;
    header.cmd_aux = cmd.1;
    header.session_cid = U64::new(session_cid);
    header.target_cid = U64::new(target_cid);
    let mut packet = BytesMut::from(header.as_bytes());
    packet.extend_from_slice(&vec![0xAB; payload]);
    packet
}

const GROUP: (u8, u8) = (
    packet_flags::cmd::primary::PEER_CMD,
    packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST,
);
const SIGNAL: (u8, u8) = (
    packet_flags::cmd::primary::PEER_CMD,
    packet_flags::cmd::aux::peer_cmd::SIGNAL,
);
const DATA: (u8, u8) = (packet_flags::cmd::primary::GROUP_PACKET, 0);

#[test]
fn a_route_counts_everything_on_its_path() {
    let node = NodeTraffic::default();
    for (route, path) in [
        (P2pRoute::Direct, P2pPath::Direct),
        (P2pRoute::Turn { relayed_both: true }, P2pPath::Turn),
    ] {
        let connection = Arc::new(PathBytes::default());
        let meter = StreamMeter::Route(RouteMeter::new(connection.clone(), node.clone(), route));
        meter.sent(&OutboundPacket::Contiguous(packet(DATA, 1, 2, 50)));
        meter.received(&packet(DATA, 2, 1, 20));
        let len = |payload| (HDP_HEADER_BYTE_LEN + payload) as u64;
        let expected = ByteCount {
            tx: len(50),
            rx: len(20),
        };
        assert_eq!(connection.snapshot().on(path), expected);
        assert_eq!(node.snapshot().on(path), expected);
        assert_eq!(connection.snapshot().server_relay, ByteCount::default());
    }
}

#[test]
fn a_client_attributes_relayed_packets_to_their_connection() {
    let node = NodeTraffic::default();
    let index = RelayIndex::new();
    let to_peer_9 = Arc::new(PathBytes::default());
    index.register(9, &to_peer_9);
    let meter = StreamMeter::ClientServer(C2sMeter::new(node.clone(), Some(index)));

    let out = packet(DATA, 5, 9, 30);
    let inbound = packet(DATA, 9, 5, 10);
    meter.sent(&OutboundPacket::Contiguous(out.clone()));
    meter.received(&inbound);
    meter.sent(&OutboundPacket::Contiguous(packet(SIGNAL, 5, 0, 7)));
    meter.received(&packet(GROUP, 5, 0, 3));

    let relayed = ByteCount {
        tx: out.len() as u64,
        rx: inbound.len() as u64,
    };
    assert_eq!(to_peer_9.snapshot().server_relay, relayed);
    let s = node.snapshot();
    assert_eq!(s.relayed_p2p, relayed);
    assert_eq!(s.client_server.tx, (HDP_HEADER_BYTE_LEN + 7) as u64);
    assert_eq!(s.group_broadcast.rx, (HDP_HEADER_BYTE_LEN + 3) as u64);
    assert_eq!(
        (s.direct, s.turn),
        (ByteCount::default(), ByteCount::default())
    );
}

#[test]
fn a_server_counts_what_it_relays_by_class() {
    let node = NodeTraffic::default();
    let meter = StreamMeter::ClientServer(C2sMeter::new(node.clone(), None));
    let forwarded = packet(DATA, 5, 9, 100);
    meter.received(&forwarded);
    meter.sent(&OutboundPacket::Split {
        header: BytesMut::from(&forwarded[..HDP_HEADER_BYTE_LEN]),
        payload: forwarded[HDP_HEADER_BYTE_LEN..].to_vec().into(),
    });
    meter.sent(&OutboundPacket::Contiguous(packet(GROUP, 3, 0, 40)));
    meter.received(&packet(SIGNAL, 3, 0, 1));
    let s = node.snapshot();
    let len = forwarded.len() as u64;
    assert_eq!(s.relayed_p2p, ByteCount { tx: len, rx: len });
    assert_eq!(s.group_broadcast.tx, (HDP_HEADER_BYTE_LEN + 40) as u64);
    assert_eq!(s.client_server.rx, (HDP_HEADER_BYTE_LEN + 1) as u64);
}

#[test]
fn flushes_and_headerless_fragments_are_not_traffic() {
    let node = NodeTraffic::default();
    let meter = StreamMeter::ClientServer(C2sMeter::new(node.clone(), None));
    let (ack, _) = citadel_io::tokio::sync::oneshot::channel();
    meter.sent(&OutboundPacket::Flush(ack));
    meter.received(&[1, 2, 3]);
    assert_eq!(node.snapshot(), Default::default());
}

#[test]
fn a_new_connection_to_a_peer_takes_over_its_relayed_bytes() {
    let index = RelayIndex::new();
    let first = Arc::new(PathBytes::default());
    index.register(9, &first);
    assert!(Arc::ptr_eq(&index.lookup(9).unwrap(), &first));
    assert!(Arc::ptr_eq(&index.lookup(9).unwrap(), &first), "cached");
    let second = Arc::new(PathBytes::default());
    index.register(9, &second);
    assert!(Arc::ptr_eq(&index.lookup(9).unwrap(), &second));
    assert!(index.lookup(10).is_none());
    drop(second);
    assert!(
        index.lookup(9).is_none(),
        "a closed connection counts nothing"
    );
}

#[test]
fn indexes_of_different_sessions_do_not_share_entries() {
    let (a, b) = (RelayIndex::new(), RelayIndex::new());
    let bytes = Arc::new(PathBytes::default());
    a.register(9, &bytes);
    assert!(a.lookup(9).is_some());
    assert!(b.lookup(9).is_none());
}
