//! Which network path a P2P connection runs over, and the per-attempt decision of which paths to
//! try.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use citadel_io::tokio::sync::watch;
use citadel_io::{error, ErrorCode, NetworkError};
use citadel_wire::udp_traversal::turn_relay::{TurnPolicy, TurnRelayConfig};

/// The path carrying a P2P connection's traffic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum P2pPath {
    /// A direct (hole-punched) QUIC connection between the peers.
    Direct,
    /// A QUIC connection through a TURN relay: the reliable channel and the UDP channel both
    /// cross the relay, never the Citadel server.
    Turn,
    /// No P2P connection: the reliable channel is relayed through the Citadel server and no UDP
    /// channel exists.
    ServerRelay,
}

/// How an established P2P connection is carried; recorded into a [`P2pPathCell`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum P2pRoute {
    Direct,
    /// `relayed_both`: each peer sends through its own allocation (relay-to-relay), so every
    /// packet egresses two TURN servers.
    Turn {
        relayed_both: bool,
    },
}

/// A snapshot of a virtual connection's path and of its background upgrade campaign.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct P2pPathStatus {
    /// The path traffic takes right now.
    pub path: P2pPath,
    /// On a [`P2pPath::Turn`] path, whether both peers relay through their own allocation.
    pub relayed_both: bool,
    /// Whether a background campaign may still move this connection off the server relay (a hole
    /// punch or TURN attempt is running, or a retry after a fall-back is scheduled). `false` once
    /// the campaign has ended; while it reads `false` on [`P2pPath::ServerRelay`], the path stays
    /// relayed for the life of the connection. Always `false` on a P2P path.
    pub upgrading: bool,
    /// The connection is gone; nothing about its path will change again.
    pub closed: bool,
}

impl P2pPathStatus {
    /// Whether traffic has left the Citadel server relay for a P2P connection (hole-punched or
    /// TURN).
    pub fn is_p2p(&self) -> bool {
        self.path != P2pPath::ServerRelay
    }
}

/// Shared, live view of a virtual connection's [`P2pPath`], read by the application's channel and
/// written when a P2P connection is established, lost, or given up on. Every change is published,
/// so an application can [`subscribe`](Self::subscribe) instead of polling.
#[derive(Clone, Debug)]
pub struct P2pPathCell(Arc<PathShared>);

#[derive(Debug)]
struct PathShared {
    status: watch::Sender<P2pPathStatus>,
    /// Whether a campaign task is alive for this connection. Read and written only inside the
    /// watch's modify closure, so a fall-back and a campaign exit cannot interleave into a stale
    /// `upgrading = true`.
    campaign_alive: AtomicBool,
    /// An upgrade the application asked for (`PeerChannel::upgrade`), for the campaign.
    rearm: super::p2p_rearm::RearmSlot,
}

impl P2pPathCell {
    /// Every virtual connection starts server-relayed: the channel exists, and is usable, before
    /// any P2P attempt. `upgrading` turns on when a campaign starts ([`CampaignEndGuard::start`]).
    pub(crate) fn server_relayed() -> Self {
        let (status, _) = watch::channel(P2pPathStatus {
            path: P2pPath::ServerRelay,
            relayed_both: false,
            upgrading: false,
            closed: false,
        });
        Self(Arc::new(PathShared {
            status,
            campaign_alive: AtomicBool::new(false),
            rearm: Default::default(),
        }))
    }

    pub fn get(&self) -> P2pPath {
        self.0.status.borrow().path
    }

    /// True when the path is [`P2pPath::Turn`] through two allocations (both peers relayed), for
    /// accounting double TURN egress.
    pub fn relayed_both(&self) -> bool {
        self.0.status.borrow().relayed_both
    }

    /// The current path and campaign state.
    pub fn status(&self) -> P2pPathStatus {
        *self.0.status.borrow()
    }

    /// A receiver that wakes on every path or campaign change.
    pub fn subscribe(&self) -> watch::Receiver<P2pPathStatus> {
        self.0.status.subscribe()
    }

    /// Resolves `Ok` with the path once traffic runs over a P2P connection (hole-punched
    /// [`P2pPath::Direct`], or [`P2pPath::Turn`] when a TURN config was supplied), and `Err` once
    /// the background campaign has ended without one: every attempt failed, the NATs are
    /// incompatible and no TURN config was supplied, or the connection closed. It has no timeout
    /// of its own; it follows the campaign. After a P2P path is lost the connection falls back to
    /// the server relay and a bounded retry is scheduled, so a new call waits for that retry.
    pub fn ensure_direct(
        &self,
    ) -> impl std::future::Future<Output = Result<P2pPath, NetworkError>> + Send + 'static {
        let mut rx = self.subscribe();
        async move {
            loop {
                let status = *rx.borrow_and_update();
                if status.is_p2p() {
                    return Ok(status.path);
                }
                if status.closed {
                    return Err(error!(
                        ErrorCode::P2pDirectPathUnavailable,
                        "the connection closed"
                    ));
                }
                if !status.upgrading {
                    return Err(error!(
                        ErrorCode::P2pDirectPathUnavailable,
                        "the background P2P campaign ended without one"
                    ));
                }
                if rx.changed().await.is_err() {
                    return Err(error!(
                        ErrorCode::P2pDirectPathUnavailable,
                        "the connection closed"
                    ));
                }
            }
        }
    }

    pub(crate) fn set(&self, route: P2pRoute) {
        let (path, relayed_both) = match route {
            P2pRoute::Direct => (P2pPath::Direct, false),
            P2pRoute::Turn { relayed_both } => (P2pPath::Turn, relayed_both),
        };
        self.publish(|_, status| {
            if !status.closed {
                status.path = path;
                status.relayed_both = relayed_both;
                status.upgrading = false;
            }
        });
    }

    /// The P2P connection was lost: traffic is back on the server relay, and the campaign (if it
    /// is still alive) decides whether to try again.
    pub(crate) fn fall_back_to_server_relay(&self) {
        self.publish(|shared, status| {
            status.path = P2pPath::ServerRelay;
            status.relayed_both = false;
            status.upgrading = shared.campaign_alive.load(Ordering::Acquire) && !status.closed;
        });
    }

    /// The campaign gave up upgrading (its retry budget is spent) but may still be alive.
    pub(crate) fn stop_upgrading(&self) {
        self.publish(|_, status| status.upgrading = false);
    }

    /// The campaign is about to retry after a fall-back.
    pub(crate) fn resume_upgrading(&self) {
        self.publish(|shared, status| {
            status.upgrading = shared.campaign_alive.load(Ordering::Acquire) && !status.closed;
        });
    }

    /// The virtual connection is gone: no path, and nothing will upgrade it.
    pub(crate) fn close(&self) {
        self.publish(|_, status| {
            status.closed = true;
            status.path = P2pPath::ServerRelay;
            status.relayed_both = false;
            status.upgrading = false;
        });
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.0.status.borrow().closed
    }

    pub(crate) fn campaign_alive(&self) -> bool {
        self.0.campaign_alive.load(Ordering::Acquire)
    }

    pub(crate) fn rearm(&self) -> &super::p2p_rearm::RearmSlot {
        &self.0.rearm
    }

    fn publish(&self, change: impl FnOnce(&PathShared, &mut P2pPathStatus)) {
        let shared = &*self.0;
        shared.status.send_if_modified(|status| {
            let before = *status;
            change(shared, status);
            *status != before
        });
    }
}

/// Holds a connection's campaign open: `upgrading` reads `true` from [`Self::start`] until this is
/// dropped, however the campaign task exits (completion, cancellation, or abort), so
/// [`P2pPathCell::ensure_direct`] can never wait on a campaign that is gone.
pub(crate) struct CampaignEndGuard(P2pPathCell);

impl CampaignEndGuard {
    pub(crate) fn start(cell: P2pPathCell) -> Self {
        cell.publish(|shared, status| {
            shared.campaign_alive.store(true, Ordering::Release);
            status.upgrading = !status.closed && !status.is_p2p();
        });
        Self(cell)
    }

    pub(crate) fn cell(&self) -> &P2pPathCell {
        &self.0
    }
}

impl Drop for CampaignEndGuard {
    fn drop(&mut self) {
        self.0.publish(|shared, status| {
            shared.campaign_alive.store(false, Ordering::Release);
            status.upgrading = false;
        });
    }
}

/// What to try for one P2P attempt, decided identically on both peers from their own TURN config
/// and the (symmetric) NAT-compatibility verdict.
#[derive(Clone, Debug)]
pub(crate) enum P2pPlan {
    /// Hole punch; nothing to fall back to.
    DirectOnly,
    /// Hole punch; on failure, relay through TURN.
    DirectThenRelay(TurnRelayConfig),
    /// Skip the hole punch and relay through TURN.
    RelayOnly(TurnRelayConfig),
    /// No P2P attempt: the NATs are incompatible and no TURN config was supplied.
    ServerOnly,
}

pub(crate) fn plan_p2p(direct_impossible: bool, turn: Option<TurnRelayConfig>) -> P2pPlan {
    match turn {
        None if direct_impossible => P2pPlan::ServerOnly,
        None => P2pPlan::DirectOnly,
        Some(cfg) if direct_impossible || cfg.policy == TurnPolicy::RelayOnly => {
            P2pPlan::RelayOnly(cfg)
        }
        Some(cfg) => P2pPlan::DirectThenRelay(cfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(policy: TurnPolicy) -> TurnRelayConfig {
        TurnRelayConfig::new(vec![], policy)
    }

    #[test]
    fn plans_follow_policy_and_nat_verdict() {
        assert!(matches!(plan_p2p(false, None), P2pPlan::DirectOnly));
        assert!(matches!(plan_p2p(true, None), P2pPlan::ServerOnly));
        assert!(matches!(
            plan_p2p(false, Some(cfg(TurnPolicy::Fallback))),
            P2pPlan::DirectThenRelay(_)
        ));
        assert!(matches!(
            plan_p2p(true, Some(cfg(TurnPolicy::Fallback))),
            P2pPlan::RelayOnly(_)
        ));
        assert!(matches!(
            plan_p2p(false, Some(cfg(TurnPolicy::RelayOnly))),
            P2pPlan::RelayOnly(_)
        ));
    }

    fn poll_once<F: std::future::Future>(fut: std::pin::Pin<&mut F>) -> Option<F::Output> {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match fut.poll(&mut cx) {
            std::task::Poll::Ready(out) => Some(out),
            std::task::Poll::Pending => None,
        }
    }

    #[test]
    fn ensure_direct_waits_for_the_campaign_and_follows_its_outcome() {
        let cell = P2pPathCell::server_relayed();
        let guard = CampaignEndGuard::start(cell.clone());
        let waiting = cell.ensure_direct();
        futures::pin_mut!(waiting);
        assert!(
            poll_once(waiting.as_mut()).is_none(),
            "relayed + upgrading must wait"
        );
        cell.set(P2pRoute::Direct);
        assert_eq!(
            poll_once(waiting.as_mut()).unwrap().unwrap(),
            P2pPath::Direct
        );

        // Lost while the campaign lives: back on the relay, a retry pending, so a new call waits.
        cell.fall_back_to_server_relay();
        assert_eq!(
            cell.status(),
            P2pPathStatus {
                path: P2pPath::ServerRelay,
                relayed_both: false,
                upgrading: true,
                closed: false,
            }
        );
        let retry = cell.ensure_direct();
        futures::pin_mut!(retry);
        assert!(poll_once(retry.as_mut()).is_none());
        // The campaign ends without a route: the waiter gets an error rather than hanging.
        drop(guard);
        assert!(poll_once(retry.as_mut()).unwrap().is_err());
    }

    #[test]
    fn a_fall_back_with_no_live_campaign_does_not_claim_an_upgrade() {
        let cell = P2pPathCell::server_relayed();
        drop(CampaignEndGuard::start(cell.clone()));
        cell.set(P2pRoute::Direct);
        cell.fall_back_to_server_relay();
        assert!(!cell.status().upgrading);
        let fut = cell.ensure_direct();
        futures::pin_mut!(fut);
        assert!(poll_once(fut).unwrap().is_err());
    }

    #[test]
    fn closing_the_connection_ends_every_wait() {
        let cell = P2pPathCell::server_relayed();
        let _guard = CampaignEndGuard::start(cell.clone());
        let fut = cell.ensure_direct();
        futures::pin_mut!(fut);
        assert!(poll_once(fut.as_mut()).is_none());
        cell.close();
        assert!(poll_once(fut.as_mut()).unwrap().is_err());
        cell.set(P2pRoute::Direct);
        assert_eq!(
            cell.get(),
            P2pPath::ServerRelay,
            "a closed connection gains no route"
        );
    }

    #[test]
    fn path_cell_round_trips() {
        let cell = P2pPathCell::server_relayed();
        let view = cell.clone();
        assert_eq!(
            (view.get(), view.relayed_both()),
            (P2pPath::ServerRelay, false)
        );
        for (route, path, both) in [
            (P2pRoute::Direct, P2pPath::Direct, false),
            (
                P2pRoute::Turn {
                    relayed_both: false,
                },
                P2pPath::Turn,
                false,
            ),
            (P2pRoute::Turn { relayed_both: true }, P2pPath::Turn, true),
        ] {
            cell.set(route);
            assert_eq!((view.get(), view.relayed_both()), (path, both));
        }
    }
}
