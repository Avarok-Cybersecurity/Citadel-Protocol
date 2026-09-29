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
use crate::proto::peer::p2p_path::{CampaignEndGuard, P2pPath, P2pPathCell, P2pPlan};
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

        let mut attached = attempt(sync_instant, udp_mode).await;
        let mut budget = RECOVERY_ATTEMPTS;
        let mut backoff = RECOVERY_BACKOFF;
        while attached {
            let attached_at = Instant::now();
            if !wait_for_fall_back(&cell).await {
                return;
            }
            if attached_at.elapsed() >= STABLE_ROUTE {
                budget = RECOVERY_ATTEMPTS;
                backoff = RECOVERY_BACKOFF;
            }
            loop {
                if budget == 0 {
                    log::info!(target: "citadel", "P2P route to peer {peer_cid} lost with no retries left; staying on the server relay");
                    cell.stop_upgrading();
                    return;
                }
                budget -= 1;
                cell.resume_upgrading();
                citadel_io::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECOVERY_BACKOFF_MAX);
                if cell.is_closed() {
                    return;
                }
                match citadel_io::time::timeout(RENDEZVOUS_TIMEOUT, app.sync()).await {
                    Ok(Ok(())) => {}
                    _ => {
                        log::info!(target: "citadel", "Peer {peer_cid} did not meet the P2P retry; staying on the server relay");
                        return;
                    }
                }
                // The UDP channel belonged to the lost route; a retry restores the reliable path.
                attached = attempt(Instant::now(), UdpMode::Disabled).await;
                if attached {
                    log::info!(target: "citadel", "P2P route to peer {peer_cid} restored");
                    break;
                }
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

/// Waits until the connection's P2P route is lost. `false` when the connection closed instead,
/// or when no campaign can retry.
async fn wait_for_fall_back(cell: &P2pPathCell) -> bool {
    let mut rx = cell.subscribe();
    loop {
        let status = *rx.borrow_and_update();
        if status.path == P2pPath::ServerRelay {
            return status.upgrading && !cell.is_closed();
        }
        if rx.changed().await.is_err() {
            return false;
        }
    }
}
