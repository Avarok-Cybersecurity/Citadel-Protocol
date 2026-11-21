//! What one path attempt ran and what it attached. Moved here from `citadel_proto`'s
//! `p2p_outcome` (lane L3 re-exports these from the protocol, so there is one definition) and
//! extended to C2S: a dial is a stage too.

use std::time::Duration;

pub use citadel_types::proto::NatClass;

use crate::kind::RouteId;

/// A stage of a path attempt, in the order an attempt runs them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PathStage {
    /// C2S: the transport dial to the server (TCP, TLS, QUIC, WebSocket).
    Dial,
    /// P2P: the peers meeting over the server relay before a punch (the rendezvous).
    Coordination,
    /// P2P: the UDP hole punch and the QUIC handshake over it (a WebRTC DataChannel on WASM).
    Direct,
    /// P2P: the QUIC connection through a TURN relay.
    Turn,
    /// P2P: the Citadel server's packet relay, the fallback every pair has while the server is up.
    Relay,
}

/// Why a stage did not connect. Paired with its [`PathStage`], which says where.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StageFailure {
    /// Not tried: both NATs are unpredictable, so a hole punch cannot work.
    NatIncompatible,
    /// Not tried: the TURN policy is relay-only.
    SkippedByPolicy,
    /// Not tried: no TURN config was supplied for this connection.
    NotConfigured,
    /// The hole punch found no working pair of addresses.
    PunchFailed,
    /// No TURN server granted this node an allocation.
    AllocationFailed,
    /// The peer had no TURN allocation to offer.
    PeerUnavailable,
    /// A TURN permission or channel binding was refused.
    PermissionFailed,
    /// Probes through the relay went unanswered.
    ProbeFailed,
    /// Coordinating with the peer over the server relay failed (an endpoint, a message or a sync).
    Signalling,
    /// The QUIC handshake over the punched or relayed path failed.
    HandshakeFailed,
    /// A connection was made but could not become the connection's route.
    AttachFailed,
    /// A local socket could not be opened.
    LocalSocket,
    /// The stage ran out of time.
    Timeout,
    /// The session ended during the stage.
    SessionGone,
    /// This platform cannot run the stage.
    Unsupported,
    /// C2S: the server could not be reached at all.
    Unreachable,
    /// P2P: the peer is not online (the server answered `PeerConnectTargetOffline`).
    PeerOffline,
}

/// How one stage of an attempt ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StageOutcome {
    pub stage: PathStage,
    pub result: Result<(), StageFailure>,
    /// Zero for a stage that was not tried.
    pub elapsed: Duration,
}

/// Which paths an attempt was planned to try.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathPlanKind {
    DirectOnly,
    DirectThenTurn,
    TurnOnly,
    ServerOnly,
    /// A server's path policy put TURN before the hole punch.
    TurnThenDirect,
    /// C2S: one transport dial to the server.
    ServerDial,
}

/// The C2S transports a dial can produce.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServerTransport {
    Tcp,
    Tls,
    Quic,
    WebSocket,
    /// A browser `WebSocket` (no timeout of its own in the protocol).
    BrowserWebSocket,
}

/// The kind of route a path is. Address-free by construction (§6.4 privacy).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// A hole-punched QUIC connection between the peers.
    Direct,
    /// QUIC through TURN; `relayed_both` when each peer relays through its own allocation.
    Turn { relayed_both: bool },
    /// The Citadel server's packet relay.
    ServerRelay,
    /// A browser WebRTC data channel; `via_turn` from the selected ICE pair, `None` when the
    /// browser did not say.
    WebRtc { via_turn: Option<bool> },
    /// C2S: a stream to the server.
    Server(ServerTransport),
}

impl RouteKind {
    /// Whether the route is the server's packet relay standing in for a P2P path.
    pub fn is_relay(self) -> bool {
        self == RouteKind::ServerRelay
    }

    /// Whether the peer's protocol layer acknowledges what this route carried
    /// (`GroupHeaderAck`, the direct journal's meaning of "delivered"). Every end-to-end P2P
    /// route does; the server stream and the server relay only flush.
    pub fn acknowledges(self) -> bool {
        matches!(
            self,
            RouteKind::Direct | RouteKind::Turn { .. } | RouteKind::WebRtc { .. }
        )
    }
}

/// What an adapter reports when a path opened: everything the outcome needs that only the
/// adapter can know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathReport {
    pub kind: RouteKind,
    pub route: RouteId,
    /// QUIC client role on a socket this node owns: `Transport::rebind` can migrate it.
    pub migratable: bool,
    /// The stages the attempt ran, beyond the one the core asked for (a direct stage that tried
    /// TURN inside its own budget, for instance). Usually empty.
    pub extra_stages: Vec<StageOutcome>,
    /// Whether the adapter reused the previous socket (it may refuse to when the socket died).
    pub reused_socket: bool,
    pub local_nat: NatClass,
    pub peer_nat: Option<NatClass>,
}
