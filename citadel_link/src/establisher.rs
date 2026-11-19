//! The establisher contract (§2.2): one trait per kind of link, whose associated types carry
//! everything this crate must not name (sockets, streams, packets), and the handles the core
//! needs from them. Implemented by `citadel_proto`'s adapters (lanes L1, L2).

use std::future::Future;
use std::pin::Pin;

use crate::decision::{LinkSettings, SealParams};
use crate::kind::{ConnectionId, Incarnation, Millis, RouteId};
use crate::outbox::{Payload, Undelivered};
use crate::path::{NatClass, RouteKind};
use crate::plan::{PathTrigger, PunchReuse, TimedStage};
use crate::typestate::{
    Delivered, Link, PathFailure, Pathed, RetireReason, SealFailure, Sealed, Unpathed,
};

/// `Send` where futures cross threads; nothing on `wasm32-unknown-unknown`, where the browser's
/// handles are single-threaded (a `BrowserP2pEstablisher` holds JS values).
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Sync` where futures cross threads; nothing on `wasm32-unknown-unknown`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// The future every establisher step returns.
#[cfg(not(target_arch = "wasm32"))]
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// The future every establisher step returns.
#[cfg(target_arch = "wasm32")]
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A raw path, as the core needs to know it.
pub trait PathHandle: MaybeSend + MaybeSync + 'static {
    fn kind(&self) -> RouteKind;
    fn route_id(&self) -> RouteId;
    /// QUIC client role on a socket this node owns.
    fn migratable(&self) -> bool;
    fn local_nat(&self) -> NatClass;
    fn peer_nat(&self) -> Option<NatClass>;
}

/// A sealed session, as the core needs to know it.
pub trait SealedSession: MaybeSend + MaybeSync + 'static {
    fn settings(&self) -> LinkSettings;
    fn connection_id(&self) -> ConnectionId;
    fn latest_version(&self) -> u32;
}

/// What the kernel owns for the life of the link: the send half writes into the link's outbox,
/// which the manager points at the current incarnation.
pub trait KernelChannel: MaybeSend + MaybeSync + 'static {
    fn attach(&self, incarnation: Incarnation);
}

/// The handle given to the kernel once and never replaced for the link's life (§3.4).
pub struct StableHandle<C: KernelChannel> {
    channel: C,
}

impl<C: KernelChannel> StableHandle<C> {
    pub fn new(channel: C) -> Self {
        StableHandle { channel }
    }

    pub fn channel(&self) -> &C {
        &self.channel
    }
}

/// The establishment of one kind of link (C2S, P2P, browser P2P), in order (§2.2).
pub trait LinkEstablisher: MaybeSend + MaybeSync + Sized + 'static {
    /// Who the link connects to.
    type Target: Clone + MaybeSend + MaybeSync;
    /// A raw path with no session on it.
    type Path: PathHandle;
    /// The path carrying a session.
    type Seal: SealedSession;
    /// What the kernel owns across every incarnation.
    type Channel: KernelChannel;
    /// What the application sends.
    type Payload: Payload + MaybeSend;

    /// (1) Path or hole: one stage of the plan (the core steps through them, §3.2), bounded by
    /// `deadline`, for the incarnation the seal that follows will take.
    fn open_path<'a>(
        &'a self,
        target: &'a Self::Target,
        stage: TimedStage,
        trigger: PathTrigger,
        reuse: PunchReuse,
        incarnation: Incarnation,
        deadline: Millis,
    ) -> Fut<'a, Result<Link<Self, Pathed>, PathFailure>>;

    /// (2) Wrap: run the handshake on the path and bind the session's keys to it.
    fn seal<'a>(
        &'a self,
        link: Link<Self, Pathed>,
        params: &'a SealParams,
        deadline: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>>;

    /// (3) Deliver: attach the sealed incarnation to the kernel's stable handle. Infallible:
    /// everything that can fail happened in (1) or (2).
    fn deliver(
        &self,
        link: Link<Self, Sealed>,
        handle: &StableHandle<Self::Channel>,
    ) -> Link<Self, Delivered>;

    /// Same path, new seal: a second session multiplexed on the live path (§4 `ResealOnPath`).
    fn fork_path(&self, live: &Link<Self, Delivered>) -> Result<Link<Self, Pathed>, PathFailure>;

    /// New path, same seal (`LINK_REATTACH_SINCE`, §5.2).
    fn reattach<'a>(
        &'a self,
        held: Link<Self, Unpathed>,
        path: Link<Self, Pathed>,
        deadline: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>>;

    /// Retire an incarnation, returning what its own queues still held and did not deliver.
    fn retire(
        &self,
        old: Link<Self, Delivered>,
        reason: RetireReason,
    ) -> Fut<'_, Vec<Undelivered<Self::Payload>>>;
}
