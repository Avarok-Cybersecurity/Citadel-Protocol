//! The identities a link speaks in: which kind of link, which incarnation of it, which route.

pub use citadel_negotiation::{Cid, ConnectionId, Epoch, Millis, Role, SettingId};

/// The kernel's request ticket (`citadel_proto::remote::Ticket`), carried through the outbox so
/// an undelivered payload is returned with the ticket the kernel sent it under. The adapter
/// converts at the boundary; this crate never mints one.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(pub u128);

/// What a link connects: this node to its server (C2S) or to one peer (P2P).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// Client to server. The client always acts first: it is the only side that can dial.
    Server,
    /// Peer to peer. The lower CID leads (owner decision D2, [`Role::for_pair`]).
    Peer { local_cid: Cid, peer_cid: Cid },
}

impl LinkKind {
    /// Who acts first on this link: always the client for C2S; the lower CID for a peer pair.
    /// `None` for a pair whose two ends have the same CID (no order exists).
    pub fn role(self) -> Option<Role> {
        match self {
            LinkKind::Server => Some(Role::Leader),
            LinkKind::Peer {
                local_cid,
                peer_cid,
            } => Role::for_pair(local_cid, peer_cid),
        }
    }

    /// The CID a path outcome names: the peer's, or 0 (`C2S_IDENTITY_CID`) for the server.
    pub fn reported_cid(self) -> Cid {
        match self {
            LinkKind::Server => 0,
            LinkKind::Peer { peer_cid, .. } => peer_cid,
        }
    }
}

/// One sealed session of a link. `n` starts at 1 with the first seal and bumps on every new seal
/// (a heal with a fresh handshake, a reseal for a settings change); a reattach keeps it, because
/// the seal is the same. The connection id stays the same for the link's life.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Incarnation {
    pub connection: ConnectionId,
    pub n: u32,
}

impl Incarnation {
    /// The first incarnation of a connection.
    pub fn first(connection: ConnectionId) -> Self {
        Incarnation { connection, n: 1 }
    }

    /// The incarnation after this one; `None` once the counter is exhausted.
    pub fn next(self) -> Option<Self> {
        self.n.checked_add(1).map(|n| Incarnation {
            connection: self.connection,
            n,
        })
    }
}

/// One concrete path a link ran over (a punched socket, a TURN allocation, a TCP stream). The
/// adapter assigns it; the core only compares them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteId(pub u64);
