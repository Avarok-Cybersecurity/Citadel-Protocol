use super::*;
use std::thread;

#[test]
fn counters_only_grow_and_keep_directions_apart() {
    let counter = ByteCounter::default();
    let mut last = counter.read();
    for (tx, rx) in [(10, 0), (0, 7), (3, 4), (0, 0)] {
        counter.sent(tx);
        counter.received(rx);
        let now = counter.read();
        assert!(
            now.tx >= last.tx && now.rx >= last.rx,
            "{now:?} after {last:?}"
        );
        assert_eq!((now.tx - last.tx, now.rx - last.rx), (tx as u64, rx as u64));
        last = now;
    }
    assert_eq!(last, ByteCount { tx: 13, rx: 11 });
}

#[test]
fn a_connection_attributes_bytes_to_the_path_that_carried_them() {
    let bytes = PathBytes::default();
    bytes.on(P2pPath::Direct).sent(100);
    bytes.on(P2pPath::Turn).received(40);
    bytes.on(P2pPath::ServerRelay).sent(5);
    bytes.on(P2pPath::ServerRelay).received(6);
    let snapshot = bytes.snapshot();
    assert_eq!(snapshot.direct, ByteCount { tx: 100, rx: 0 });
    assert_eq!(snapshot.turn, ByteCount { tx: 0, rx: 40 });
    assert_eq!(snapshot.server_relay, ByteCount { tx: 5, rx: 6 });
    for path in [P2pPath::Direct, P2pPath::Turn, P2pPath::ServerRelay] {
        assert_eq!(snapshot.on(path), bytes.on(path).read());
    }
}

#[test]
fn a_node_counts_each_class_apart() {
    let node = NodeTraffic::default();
    let classes = [
        TrafficClass::Direct,
        TrafficClass::Turn,
        TrafficClass::RelayedP2p,
        TrafficClass::ClientServer,
        TrafficClass::GroupBroadcast,
    ];
    for (i, class) in classes.into_iter().enumerate() {
        node.class(class).sent(i + 1);
    }
    let s = node.snapshot();
    let got = [
        s.direct,
        s.turn,
        s.relayed_p2p,
        s.client_server,
        s.group_broadcast,
    ];
    for (i, count) in got.into_iter().enumerate() {
        assert_eq!(
            count,
            ByteCount {
                tx: i as u64 + 1,
                rx: 0
            }
        );
    }
    assert_eq!(s.on(P2pPath::ServerRelay), s.relayed_p2p);
    let clone = node.clone();
    clone.class(TrafficClass::Direct).received(9);
    assert_eq!(
        node.snapshot().direct.rx,
        9,
        "clones share one set of counters"
    );
}

#[test]
fn concurrent_increments_are_all_counted() {
    const THREADS: usize = 8;
    const ROUNDS: usize = 10_000;
    let bytes = Arc::new(PathBytes::default());
    let node = NodeTraffic::default();
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let (bytes, node) = (bytes.clone(), node.clone());
            thread::spawn(move || {
                for _ in 0..ROUNDS {
                    bytes.on(P2pPath::Direct).sent(3);
                    bytes.on(P2pPath::Direct).received(2);
                    node.class(TrafficClass::RelayedP2p).sent(1);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let total = (THREADS * ROUNDS) as u64;
    assert_eq!(
        bytes.snapshot().direct,
        ByteCount {
            tx: 3 * total,
            rx: 2 * total
        }
    );
    assert_eq!(node.snapshot().relayed_p2p.tx, total);
}
