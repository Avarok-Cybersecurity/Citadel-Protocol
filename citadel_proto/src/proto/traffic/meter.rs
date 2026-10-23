//! The meters streams count their packets with. A P2P route's stream carries one connection's
//! traffic on one path; a client-server stream carries several classes, told apart by each
//! packet's header (its command and target CID, never its payload).

use std::sync::Arc;

use zerocopy::Ref;

use super::relay_index::RelayIndex;
use super::{NodeTraffic, PathBytes, TrafficClass};
use crate::proto::outbound_sender::OutboundPacket;
use crate::proto::packet::{packet_flags, HdpHeader};
use crate::proto::peer::p2p_path::{P2pPath, P2pRoute};

/// Counts a P2P route's packets: all of them are its connection's traffic on its path.
#[derive(Clone, Debug)]
pub(crate) struct RouteMeter {
    connection: Arc<PathBytes>,
    node: NodeTraffic,
    path: P2pPath,
    class: TrafficClass,
}

impl RouteMeter {
    pub(crate) fn new(connection: Arc<PathBytes>, node: NodeTraffic, route: P2pRoute) -> Self {
        let (path, class) = match route {
            P2pRoute::Direct => (P2pPath::Direct, TrafficClass::Direct),
            P2pRoute::Turn { .. } => (P2pPath::Turn, TrafficClass::Turn),
        };
        Self {
            connection,
            node,
            path,
            class,
        }
    }

    pub(crate) fn sent(&self, bytes: usize) {
        self.connection.on(self.path).sent(bytes);
        self.node.class(self.class).sent(bytes);
    }

    pub(crate) fn received(&self, bytes: usize) {
        self.connection.on(self.path).received(bytes);
        self.node.class(self.class).received(bytes);
    }
}

/// Counts a client-server stream's packets by class. On a client, the P2P packets the server
/// relays are also counted on their connection's [`P2pPath::ServerRelay`] counters.
#[derive(Clone, Debug)]
pub(crate) struct C2sMeter {
    node: NodeTraffic,
    /// `None` on the server, which relays P2P packets but owns none of their connections.
    connections: Option<RelayIndex>,
}

impl C2sMeter {
    pub(crate) fn new(node: NodeTraffic, connections: Option<RelayIndex>) -> Self {
        Self { node, connections }
    }

    fn count(&self, header: &[u8], bytes: usize, outbound: bool) {
        let Some((class, peer)) = classify(header, outbound) else {
            return;
        };
        let counter = self.node.class(class);
        let peer_counters = peer
            .zip(self.connections.as_ref())
            .and_then(|(peer, index)| index.lookup(peer));
        let on_connection = peer_counters.as_deref().map(|c| c.on(P2pPath::ServerRelay));
        if outbound {
            counter.sent(bytes);
            on_connection.inspect(|c| c.sent(bytes));
        } else {
            counter.received(bytes);
            on_connection.inspect(|c| c.received(bytes));
        }
    }
}

/// How a stream counts its packets.
#[derive(Clone, Debug)]
pub(crate) enum StreamMeter {
    Route(RouteMeter),
    ClientServer(C2sMeter),
}

impl StreamMeter {
    pub(crate) fn sent(&self, packet: &OutboundPacket) {
        let (header, bytes) = match packet {
            OutboundPacket::Contiguous(buf) => (&buf[..], buf.len()),
            OutboundPacket::Split { header, payload } => {
                (&header[..], header.len() + payload.len())
            }
            OutboundPacket::Flush(_) => return,
        };
        match self {
            Self::Route(route) => route.sent(bytes),
            Self::ClientServer(c2s) => c2s.count(header, bytes, true),
        }
    }

    /// `packet` with its header already de-obfuscated.
    pub(crate) fn received(&self, packet: &[u8]) {
        match self {
            Self::Route(route) => route.received(packet.len()),
            Self::ClientServer(c2s) => c2s.count(packet, packet.len(), false),
        }
    }
}

/// A client-server packet's class, and for a relayed P2P packet the peer at the other end (its
/// target when sent, its sender when received). `None` for a packet too short to have a header.
fn classify(packet: &[u8], outbound: bool) -> Option<(TrafficClass, Option<u64>)> {
    let (header, _) = Ref::<_, HdpHeader>::new_from_prefix(packet)?;
    let target_cid = header.target_cid.get();
    if target_cid != 0 {
        let peer = if outbound {
            target_cid
        } else {
            header.session_cid.get()
        };
        return Some((TrafficClass::RelayedP2p, Some(peer)));
    }
    let group = header.cmd_primary == packet_flags::cmd::primary::PEER_CMD
        && header.cmd_aux == packet_flags::cmd::aux::peer_cmd::GROUP_BROADCAST;
    let class = if group {
        TrafficClass::GroupBroadcast
    } else {
        TrafficClass::ClientServer
    };
    Some((class, None))
}

#[cfg(test)]
#[path = "meter_tests.rs"]
mod tests;
