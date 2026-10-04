//! The background campaign that moves a peer connection off the server relay.
//!
//! A peer connection is usable the moment both peers hold the keys: its traffic rides the
//! Citadel server relay, end-to-end encrypted, from the first message. The application gets its
//! `PeerChannel` then, and never waits for NAT traversal. This campaign runs beside it: it hole
//! punches (and tries TURN when configured), and when a P2P route attaches, the channel upgrades
//! in place — routing is decided per packet, and both routes feed one ordered channel.
//!
//! **Releasing the channel.** A message the initiator sends right after its channel exists can
//! overtake the receiver's key-exchange stage on the way through the server; the receiver, with
//! no virtual connection yet, would drop it, and the ordered channel would wait for it forever.
//! So the receiver (whose peer already has its virtual connection) releases at once, and the
//! initiator releases on proof that the receiver's exists: the receiver's registration greeting on
//! the relayed coordination endpoint, which it sends only after creating it.
//!
//! **Losing the route.** When a P2P route ends while the connection is live, traffic falls back to
//! the relay (see `fall_back_to_server_relay`) and the campaign retries, bounded: at most
//! [`RECOVERY_ATTEMPTS`] attempts, waiting [`RECOVERY_BACKOFF`] before the first and doubling up
//! to [`RECOVERY_BACKOFF_MAX`]. That wait is the hysteresis: a path that keeps failing is retried
//! ever less often and then left on the relay. A route that stayed up for [`STABLE_ROUTE`] earns a
//! fresh budget. Both peers run the same schedule and meet on the coordination endpoint before
//! each retry; a peer that does not arrive within [`RENDEZVOUS_TIMEOUT`] ends the campaign.
//!
//! **Giving up is not for life** with a peer at `PATH_REARM_SINCE`: out of retries (or after a
//! first attempt that failed), the campaign parks on the coordination endpoint until either
//! application calls `PeerChannel::upgrade`, then retries with a fresh budget. The two peers agree
//! on every retry at its rendezvous (see `p2p_rearm`), so they give up, park and re-arm together.
//!
//! The campaign's state is published on the connection's [`P2pPathCell`], which is what
//! `PeerChannel::ensure_direct` follows.

use std::time::Duration;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_io::tokio::sync::oneshot;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::RelativeNodeType;

use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::NodeResult;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::p2p_path::{CampaignEndGuard, P2pPlan};
use crate::proto::peer::p2p_rearm;
use crate::proto::peer::p2p_retry::{wait_for_fall_back, Retry, RetryEnd, Schedule};
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;

/// How long the initiator waits for the receiver's registration greeting before releasing its
/// channel anyway (the receiver never registered: it lost a dual-connect race, or runs an older
/// protocol). The channel then works as it always did; only the campaign is skipped.
pub(crate) const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
/// Retries after a P2P route is lost, before the connection stays on the relay.
pub(crate) const RECOVERY_ATTEMPTS: u32 = 3;
/// Wait before the first retry; doubles per retry.
pub(crate) const RECOVERY_BACKOFF: Duration = Duration::from_secs(2);
pub(crate) const RECOVERY_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A route that stayed up this long resets the retry budget and backoff.
pub(crate) const STABLE_ROUTE: Duration = Duration::from_secs(300);
/// How long a retry waits for the peer to meet it on the coordination endpoint.
pub(crate) const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct Campaign<R: Ratchet, T: PlatformOps> {
    pub(crate) session: CitadelSession<R, T>,
    pub(crate) peer_connection_type: PeerConnectionType,
    pub(crate) ticket: Ticket,
    pub(crate) peer_nat_info: PeerNatInfo,
    pub(crate) channel_signal: NodeResult<R>,
    pub(crate) hole_punch_compat_stream: ReliableOrderedCompatStream<R>,
    pub(crate) endpoint_ratchet: R,
    pub(crate) peer_cid: u64,
    pub(crate) sync_instant: Instant,
    pub(crate) node_type: RelativeNodeType,
    pub(crate) udp_mode: UdpMode,
    pub(crate) session_security_settings: SessionSecuritySettings,
    /// Fires (by being dropped) when the connection attempt this campaign belongs to is
    /// superseded or the session shuts down.
    pub(crate) cancel_rx: oneshot::Receiver<()>,
    pub(crate) plan: P2pPlan,
    pub(crate) guard: CampaignEndGuard,
}

/// Starts the campaign on its own task: the inbound packet processor that forged the connection
/// must not wait on NAT traversal.
pub(crate) fn spawn<R: Ratchet, T: PlatformOps>(campaign: Campaign<R, T>) {
    spawn!(run(campaign));
}

async fn run<R: Ratchet, T: PlatformOps>(campaign: Campaign<R, T>) {
    let Campaign {
        session,
        peer_connection_type,
        ticket,
        peer_nat_info,
        channel_signal,
        hole_punch_compat_stream,
        endpoint_ratchet,
        peer_cid,
        sync_instant,
        node_type,
        udp_mode,
        session_security_settings,
        cancel_rx,
        plan,
        guard,
    } = campaign;
    let cell = guard.cell().clone();
    let rearmable = match &channel_signal {
        NodeResult::PeerChannelCreated(created) => {
            p2p_rearm::peer_parks(created.channel.peer_protocol_version())
        }
        _ => false,
    };
    let weak_session = session.as_weak();
    let kernel_tx = session.kernel_tx.clone();
    drop(session);

    let body = async {
        let release = |signal: NodeResult<R>| {
            if kernel_tx.unbounded_send(signal).is_err() {
                log::warn!(target: "citadel", "Kernel gone before the channel to peer {peer_cid} could be delivered");
            }
        };
        let register = citadel_io::time::timeout(
            REGISTER_TIMEOUT,
            NetworkEndpoint::register(node_type, hole_punch_compat_stream),
        );
        let app = match node_type {
            RelativeNodeType::Receiver => {
                release(channel_signal);
                register.await
            }
            RelativeNodeType::Initiator => {
                let registered = register.await;
                release(channel_signal);
                registered
            }
        };
        let app = match app {
            Ok(Ok(app)) => app,
            Ok(Err(err)) => {
                log::warn!(target: "citadel", "Coordination endpoint for peer {peer_cid} failed to register ({err}); staying on the server relay");
                return;
            }
            Err(_) => {
                log::warn!(target: "citadel", "Coordination endpoint for peer {peer_cid} did not register within {REGISTER_TIMEOUT:?}; staying on the server relay");
                return;
            }
        };
        if matches!(plan, P2pPlan::ServerOnly) {
            log::warn!(target: "citadel", "The P2P connection to {peer_cid} requires TURN, and no TURN config was supplied: staying server-relayed");
            return;
        }

        let attempt = |sync_instant: Instant, udp_mode: UdpMode| {
            let session = CitadelSession::upgrade_weak(&weak_session);
            let app = app.clone();
            let plan = plan.clone();
            let peer_nat_info = peer_nat_info.clone();
            let endpoint_ratchet = endpoint_ratchet.clone();
            async move {
                let Some(session) = session else {
                    return false;
                };
                T::p2p_hole_punch(
                    session,
                    peer_connection_type,
                    ticket,
                    peer_nat_info,
                    app,
                    endpoint_ratchet,
                    peer_cid,
                    sync_instant,
                    node_type,
                    udp_mode,
                    session_security_settings,
                    plan,
                )
                .await
            }
        };

        let slot = cell.rearm();
        let retry = Retry {
            cell: &cell,
            app: &app,
            slot,
            rearmable,
            udp_mode,
            peer_cid,
        };
        let mut attached = attempt(sync_instant, udp_mode).await;
        let mut schedule = Schedule::fresh(true);
        loop {
            if attached {
                let attached_at = Instant::now();
                if !wait_for_fall_back(&cell).await {
                    return;
                }
                if attached_at.elapsed() >= STABLE_ROUTE {
                    schedule = Schedule::fresh(true);
                }
                schedule.wait_first = true;
            } else {
                // Out of attempts: stay on the relay. A peer that parks waits to be re-armed.
                cell.stop_upgrading();
                if !rearmable || !p2p_rearm::park(&app, slot).await {
                    return;
                }
                log::info!(target: "citadel", "P2P campaign for peer {peer_cid} re-armed");
                schedule = Schedule::fresh(false);
            }
            match retry.run(&mut schedule, &attempt).await {
                RetryEnd::Attached => attached = true,
                RetryEnd::Exhausted => attached = false,
                RetryEnd::Ended => return,
            }
        }
    };

    citadel_io::tokio::select! {
        _ = body => {}
        _ = cancel_rx => {
            log::trace!(target: "citadel", "P2P campaign for peer {peer_cid} cancelled");
        }
    }
    drop(guard);
}
