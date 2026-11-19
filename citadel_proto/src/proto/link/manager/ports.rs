//! The shell's ports besides the establisher (§2.4): the rendezvous, the QUIC rebind, the probe
//! and where the core's events and buffer mode go. One implementation per kind of link; the
//! tests drive the shell through scripted ones.

use citadel_link::{
    BufferMode, Fut, LinkEvent, MaybeSend, MaybeSync, PathPlan, RendezvousVia, RouteId,
    StageFailure,
};

/// Everything the core asks of the world that is not one of the establisher's steps.
pub(crate) trait LinkPorts: MaybeSend + MaybeSync + 'static {
    /// Meets the peer (P2P) and returns the pair's plan.
    fn rendezvous(
        &self,
        attempt: u32,
        via: RendezvousVia,
    ) -> Fut<'_, Result<PathPlan, StageFailure>>;
    /// Migrates the route's QUIC connection to a fresh local socket.
    fn rebind(&self, route: RouteId) -> Fut<'_, bool>;
    /// Asks the far end whether the link still carries traffic.
    fn probe(&self) -> Fut<'_, bool>;
    /// The direct route is gone; traffic moves onto the server relay.
    fn fall_back_to_relay(&self);
    /// One event for the kernel (a path outcome, a degradation, the close).
    fn report(&self, event: LinkEvent);
    /// Whether the stable handle carries sends to the live incarnation or holds them.
    fn buffer(&self, mode: BufferMode);
}
