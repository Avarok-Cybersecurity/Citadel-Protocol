//! The P2P link under `LinkManagerMode::Managed`: the pair's `RobustConnectionManager`, its
//! ports, and the watch that tells it when its direct route or its connection ended.
//!
//! The rendezvous of the first attempt is the key exchange that already happened through the
//! server: its stamped plan is the plan. Every later attempt meets the peer on the coordination
//! endpoint first (`RETRY_RENDEZVOUS`), as the campaign's retries do, so both ends punch in step.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc;
use citadel_link::{
    BufferMode, Clock, Fut, LinkCore, LinkEvent, LinkInput, LossCause, PathPlan, RendezvousVia,
    RouteId, ShutdownReason, StableHandle, StageFailure,
};

use super::establisher::P2pEstablisher;
use super::handles::{P2pChannel, P2pTarget};
use crate::proto::link::manager::ports::LinkPorts;
use crate::proto::link::manager::{RobustConnectionManager, ShellInput};
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::coordination::RETRY_RENDEZVOUS;
use crate::proto::peer::p2p_path::{P2pPath, P2pPathCell};
use netbeam::sync::network_endpoint::NetworkEndpoint;

/// The pair's ports.
pub(crate) struct P2pPorts {
    app: NetworkEndpoint,
    plan: PathPlan,
    met_once: AtomicBool,
    peer_cid: u64,
    rebinder: crate::proto::misc::local_rebind::LocalRebinder,
}

impl LinkPorts for P2pPorts {
    fn rendezvous(
        &self,
        attempt: u32,
        _via: RendezvousVia,
    ) -> Fut<'_, Result<PathPlan, StageFailure>> {
        Box::pin(async move {
            // The first attempt's rendezvous was the key exchange.
            if !self.met_once.swap(true, Ordering::SeqCst) {
                return Ok(self.plan.clone());
            }
            log::trace!(target: "citadel", "P2P link to {}: attempt {attempt} meets the peer", self.peer_cid);
            self.app
                .on(RETRY_RENDEZVOUS)
                .sync()
                .await
                .map(|_| self.plan.clone())
                .map_err(|_| StageFailure::Signalling)
        })
    }

    fn rebind(&self, _route: RouteId) -> Fut<'_, bool> {
        // Every client-role QUIC endpoint moves to a fresh socket (`quic_rebind`).
        // A route rebound when something moved and nothing failed to.
        let rebound = self
            .rebinder
            .rebind_local()
            .is_ok_and(|report| !report.rebound.is_empty() && report.failed.is_empty());
        Box::pin(async move { rebound })
    }

    fn probe(&self) -> Fut<'_, bool> {
        // A P2P link carries no probe of its own: the relay lives while C2S does.
        Box::pin(async { true })
    }

    fn fall_back_to_relay(&self) {
        // The route's own end already moved the connection onto the relay
        // (`fall_back_to_server_relay`, `link::p2p::stream_end`); the core learnt of it from there.
    }

    fn report(&self, event: LinkEvent) {
        // Lane L3 maps these onto `NodeResult::PeerPathOutcome` / `LinkDegraded`.
        log::info!(target: "citadel", "P2P link to {}: {event:?}", self.peer_cid);
    }

    fn buffer(&self, _mode: BufferMode) {
        // The relay carries the channel whenever no P2P route does: nothing is held (the outbox
        // that makes Hold meaningful is lane L4's).
    }
}

/// Tells the manager what the connection's path cell shows: a lost P2P route, or the end of
/// the connection.
async fn watch<E: citadel_link::LinkEstablisher>(
    cell: P2pPathCell,
    inbox: mpsc::UnboundedSender<ShellInput<E>>,
) {
    let mut rx = cell.subscribe();
    let mut was_p2p = false;
    loop {
        let status = *rx.borrow_and_update();
        if status.closed {
            break;
        }
        let p2p = status.path != P2pPath::ServerRelay;
        if was_p2p
            && !p2p
            && inbox
                .send(ShellInput::LiveLost(LossCause::RouteLost))
                .is_err()
        {
            return;
        }
        was_p2p = p2p;
        if rx.changed().await.is_err() {
            break;
        }
    }
    let _ = inbox.send(ShellInput::Core(LinkInput::Shutdown {
        reason: ShutdownReason::Shutdown,
    }));
}

/// Runs the pair's manager until the connection ends.
pub(crate) async fn run_managed<R: Ratchet, T: PlatformOps>(
    core: LinkCore,
    establisher: P2pEstablisher<R, T>,
    ports: P2pPorts,
    clock: Arc<dyn Clock>,
    channel: P2pChannel<R>,
    cell: P2pPathCell,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let peer_cid = establisher.ctx.peer_cid;
    let handle = Arc::new(StableHandle::new(channel));
    let manager = RobustConnectionManager::new(
        core,
        Arc::new(establisher),
        Arc::new(ports),
        clock,
        P2pTarget { peer_cid },
        handle,
        rx,
    );
    spawn!(watch(cell, tx));
    let _ = manager.run().await;
    log::trace!(target: "citadel", "P2P link manager for peer {peer_cid} ended");
}

impl P2pPorts {
    pub(crate) fn new(
        app: NetworkEndpoint,
        plan: PathPlan,
        peer_cid: u64,
        rebinder: crate::proto::misc::local_rebind::LocalRebinder,
    ) -> Self {
        P2pPorts {
            app,
            plan,
            met_once: AtomicBool::new(false),
            peer_cid,
            rebinder,
        }
    }
}
