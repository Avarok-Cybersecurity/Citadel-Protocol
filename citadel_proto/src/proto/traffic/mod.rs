//! Byte counters by network path and traffic class.
//!
//! Every peer connection counts the bytes it sends and receives on each path it has used
//! ([`PathBytes`], read with `PeerChannel::path_bytes`), and every node counts its traffic by
//! class ([`NodeTraffic`], read with `NodeRemote::traffic`): direct and TURN P2P traffic, P2P
//! traffic relayed through the Citadel server, client-server traffic, and group broadcasts.
//! A node acting as the server counts what it relays in the same classes.
//!
//! Counted are Citadel packet bytes (header plus ciphertext) as they enter or leave a stream,
//! not the QUIC, TCP, UDP or TURN framing around them. Packets are classified by their header's
//! command and target, never by their content. Counters only grow; increments are relaxed
//! atomic additions, with no lock on the packet path.

pub(crate) mod meter;
pub(crate) mod relay_index;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::proto::peer::p2p_path::P2pPath;

/// Bytes sent and received, as read at one moment.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ByteCount {
    pub tx: u64,
    pub rx: u64,
}

/// A monotonic pair of byte counters.
#[derive(Debug, Default)]
pub(crate) struct ByteCounter {
    tx: AtomicU64,
    rx: AtomicU64,
}

impl ByteCounter {
    pub(crate) fn sent(&self, bytes: usize) {
        self.tx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn received(&self, bytes: usize) {
        self.rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn read(&self) -> ByteCount {
        ByteCount {
            tx: self.tx.load(Ordering::Relaxed),
            rx: self.rx.load(Ordering::Relaxed),
        }
    }
}

/// One peer connection's bytes on each path, across every route it has had.
#[derive(Debug, Default)]
pub(crate) struct PathBytes {
    direct: ByteCounter,
    turn: ByteCounter,
    server_relay: ByteCounter,
}

impl PathBytes {
    pub(crate) fn on(&self, path: P2pPath) -> &ByteCounter {
        match path {
            P2pPath::Direct => &self.direct,
            P2pPath::Turn => &self.turn,
            P2pPath::ServerRelay => &self.server_relay,
        }
    }

    pub(crate) fn snapshot(&self) -> PathBytesSnapshot {
        PathBytesSnapshot {
            direct: self.direct.read(),
            turn: self.turn.read(),
            server_relay: self.server_relay.read(),
        }
    }
}

/// A peer connection's bytes on each path, as read at one moment.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PathBytesSnapshot {
    /// Over hole-punched QUIC: the reliable stream and the UDP channel's datagrams.
    pub direct: ByteCount,
    /// Over QUIC through a TURN relay (once per packet, even when both peers relay).
    pub turn: ByteCount,
    /// Through the Citadel server.
    pub server_relay: ByteCount,
}

impl PathBytesSnapshot {
    pub fn on(&self, path: P2pPath) -> ByteCount {
        match path {
            P2pPath::Direct => self.direct,
            P2pPath::Turn => self.turn,
            P2pPath::ServerRelay => self.server_relay,
        }
    }
}

/// What a packet is, for counting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrafficClass {
    Direct,
    Turn,
    RelayedP2p,
    ClientServer,
    GroupBroadcast,
}

/// A node's traffic by class, shared by all its sessions. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct NodeTraffic(Arc<NodeTrafficInner>);

#[derive(Debug, Default)]
struct NodeTrafficInner {
    direct: ByteCounter,
    turn: ByteCounter,
    relayed_p2p: ByteCounter,
    client_server: ByteCounter,
    group_broadcast: ByteCounter,
}

impl NodeTraffic {
    pub(crate) fn class(&self, class: TrafficClass) -> &ByteCounter {
        let inner = &*self.0;
        match class {
            TrafficClass::Direct => &inner.direct,
            TrafficClass::Turn => &inner.turn,
            TrafficClass::RelayedP2p => &inner.relayed_p2p,
            TrafficClass::ClientServer => &inner.client_server,
            TrafficClass::GroupBroadcast => &inner.group_broadcast,
        }
    }

    /// Every class, as read at one moment.
    pub fn snapshot(&self) -> NodeTrafficSnapshot {
        let inner = &*self.0;
        NodeTrafficSnapshot {
            direct: inner.direct.read(),
            turn: inner.turn.read(),
            relayed_p2p: inner.relayed_p2p.read(),
            client_server: inner.client_server.read(),
            group_broadcast: inner.group_broadcast.read(),
        }
    }
}

/// A node's traffic by class, as read at one moment.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NodeTrafficSnapshot {
    /// This node's P2P traffic over hole-punched QUIC.
    pub direct: ByteCount,
    /// This node's P2P traffic through TURN relays.
    pub turn: ByteCount,
    /// P2P packets crossing the Citadel server: on a client, its own P2P traffic relayed by the
    /// server; on the server, the packets it relays between peers (received from the sender,
    /// sent to the target).
    pub relayed_p2p: ByteCount,
    /// Client-server traffic other than group broadcasts.
    pub client_server: ByteCount,
    /// Group broadcast packets: on a client, its group traffic to and from the server; on the
    /// server, the broadcasts it receives and the fan-out it sends to members.
    pub group_broadcast: ByteCount,
}

impl NodeTrafficSnapshot {
    /// This node's P2P traffic on `path`, over all its connections.
    pub fn on(&self, path: P2pPath) -> ByteCount {
        match path {
            P2pPath::Direct => self.direct,
            P2pPath::Turn => self.turn,
            P2pPath::ServerRelay => self.relayed_p2p,
        }
    }
}

#[cfg(test)]
#[path = "traffic_tests.rs"]
mod tests;
