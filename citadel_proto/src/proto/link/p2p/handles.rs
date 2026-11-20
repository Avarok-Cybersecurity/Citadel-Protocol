//! The establisher's associated types: the target, the opened path, the seal and the kernel's
//! stable handle. Each holds its I/O value behind a lock taken exactly once, by the step that
//! consumes it (seal takes the path's stream, deliver takes the seal's wrapped route).

use citadel_crypt::ratchets::Ratchet;
use citadel_io::Mutex;
use citadel_link::{
    ConnectionId, Incarnation, KernelChannel, LinkSettings, NatClass, PathHandle, RouteId,
    RouteKind, SealedSession,
};
use citadel_types::proto::UdpMode;

use super::attach::attach_p2p_stream;
use super::context::P2pLinkContext;
use super::direct::DirectPath;
use super::wrap::{RouteFacts, WrappedP2pStream};
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::p2p_conn_handler::next_route_id;
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::peer::turn_p2p::RelayedPath;

/// The peer a P2P link connects to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct P2pTarget {
    pub(crate) peer_cid: u64,
}

/// What one stage opened.
pub(crate) enum OpenedRoute {
    Direct(DirectPath),
    Turn(RelayedPath),
    /// The server relay: the connection's keys already ride it.
    Relay,
}

impl OpenedRoute {
    fn kind(&self) -> RouteKind {
        match self {
            OpenedRoute::Direct(_) => RouteKind::Direct,
            OpenedRoute::Turn(relayed) => RouteKind::Turn {
                relayed_both: relayed.route == (P2pRoute::Turn { relayed_both: true }),
            },
            OpenedRoute::Relay => RouteKind::ServerRelay,
        }
    }

    fn accepted(&self) -> bool {
        match self {
            OpenedRoute::Direct(direct) => direct.from_listener,
            OpenedRoute::Turn(relayed) => relayed.from_listener,
            OpenedRoute::Relay => false,
        }
    }

    /// The stream and the facts its seal binds (`None` for the relay).
    pub(crate) fn into_facts<R: Ratchet, T: PlatformOps>(
        self,
        route_id: RouteId,
        ctx: &P2pLinkContext<R, T>,
        udp_mode: UdpMode,
    ) -> Option<(GenericNetworkStream, RouteFacts)> {
        let (stream, addr, from_listener, path) = match self {
            OpenedRoute::Direct(d) => (d.stream, d.addr, d.from_listener, P2pRoute::Direct),
            OpenedRoute::Turn(t) => (t.stream, t.addr, t.from_listener, t.route),
            OpenedRoute::Relay => return None,
        };
        let facts = RouteFacts {
            route_id: route_id.0,
            from_listener,
            v_conn: ctx.peer_connection_type.as_virtual_connection(),
            hole_punched_addr: addr,
            ticket: ctx.ticket,
            udp_mode,
            session_security_settings: ctx.security,
            path,
        };
        Some((stream, facts))
    }
}

/// An opened path: its facts, and the route until the seal takes it.
pub(crate) struct P2pPath {
    kind: RouteKind,
    route: RouteId,
    migratable: bool,
    local_nat: NatClass,
    peer_nat: NatClass,
    opened: Mutex<Option<OpenedRoute>>,
}

impl P2pPath {
    pub(crate) fn new(opened: OpenedRoute, local_nat: NatClass, peer_nat: NatClass) -> Self {
        let kind = opened.kind();
        // Only this connection's client can migrate, and not through its own TURN allocation.
        let migratable = matches!(
            kind,
            RouteKind::Direct
                | RouteKind::Turn {
                    relayed_both: false
                }
        ) && !opened.accepted();
        let route = match kind {
            RouteKind::ServerRelay => RouteId::RELAY,
            _ => RouteId(next_route_id()),
        };
        P2pPath {
            kind,
            route,
            migratable,
            local_nat,
            peer_nat,
            opened: Mutex::new(Some(opened)),
        }
    }

    pub(crate) fn take_route(&self) -> Option<OpenedRoute> {
        self.opened.lock().take()
    }
}

impl PathHandle for P2pPath {
    fn kind(&self) -> RouteKind {
        self.kind
    }
    fn route_id(&self) -> RouteId {
        self.route
    }
    fn migratable(&self) -> bool {
        self.migratable
    }
    fn local_nat(&self) -> NatClass {
        self.local_nat
    }
    fn peer_nat(&self) -> Option<NatClass> {
        Some(self.peer_nat)
    }
}

/// A sealed route, until delivered.
pub(crate) struct P2pSeal<R: Ratchet, T: PlatformOps> {
    settings: LinkSettings,
    connection: ConnectionId,
    version: u32,
    wrapped: Mutex<Option<WrappedP2pStream<R, T>>>,
}

impl<R: Ratchet, T: PlatformOps> P2pSeal<R, T> {
    pub(crate) fn new(
        settings: LinkSettings,
        connection: ConnectionId,
        version: u32,
        wrapped: Option<WrappedP2pStream<R, T>>,
    ) -> Self {
        P2pSeal {
            settings,
            connection,
            version,
            wrapped: Mutex::new(wrapped),
        }
    }

    /// Attaches the wrapped route, once. `false` when the connection it was bound to is gone
    /// (the route is then closed, and nothing of it remains).
    pub(crate) fn attach(&self, peer_cid: u64) -> bool {
        let Some(wrapped) = self.wrapped.lock().take() else {
            return true;
        };
        match attach_p2p_stream(wrapped) {
            Ok(()) => true,
            Err(err) => {
                log::warn!(target: "citadel", "The route to peer {peer_cid} could not attach: {err}");
                false
            }
        }
    }
}

impl<R: Ratchet, T: PlatformOps> SealedSession for P2pSeal<R, T> {
    fn settings(&self) -> LinkSettings {
        self.settings
    }
    fn connection_id(&self) -> ConnectionId {
        self.connection
    }
    fn latest_version(&self) -> u32 {
        self.version
    }
}

/// The kernel's handle on a P2P link. The kernel holds the `PeerChannel` from registration on
/// (the campaign's release, unchanged): the relay carries it, and every route the manager
/// delivers is an upgrade beneath that one channel (the stable handle, §3.4, fact 7).
pub(crate) struct P2pChannel<R: Ratchet>(std::marker::PhantomData<fn() -> R>);

impl<R: Ratchet> P2pChannel<R> {
    pub(crate) fn held_by_the_kernel() -> Self {
        P2pChannel(std::marker::PhantomData)
    }
}

impl<R: Ratchet> KernelChannel for P2pChannel<R> {
    fn attach(&self, incarnation: Incarnation) {
        log::trace!(target: "citadel", "P2P route of {incarnation:?} attached beneath the kernel's channel");
    }
}
