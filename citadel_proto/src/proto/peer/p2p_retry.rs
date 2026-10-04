//! One recovery cycle of a P2P path campaign: retries, each after its backoff and a rendezvous
//! with the peer, until a route attaches, both peers are out of retries, or the campaign must end.

use super::p2p_campaign::{
    RECOVERY_ATTEMPTS, RECOVERY_BACKOFF, RECOVERY_BACKOFF_MAX, RENDEZVOUS_TIMEOUT,
};
use super::p2p_path::{P2pPath, P2pPathCell};
use super::p2p_rearm::{self, RearmSlot};
use citadel_io::time::{Duration, Instant};
use citadel_types::proto::UdpMode;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use std::future::Future;

/// Where a campaign's retries stand.
pub(crate) struct Schedule {
    pub budget: u32,
    pub backoff: Duration,
    /// Whether the next retry waits its backoff first: after a fall-back it does (hysteresis),
    /// right after a re-arm it does not (the application asked now).
    pub wait_first: bool,
}

impl Schedule {
    pub(crate) fn fresh(wait_first: bool) -> Self {
        Self {
            budget: RECOVERY_ATTEMPTS,
            backoff: RECOVERY_BACKOFF,
            wait_first,
        }
    }
}

pub(crate) enum RetryEnd {
    Attached,
    /// Out of retries; the campaign gives up (and parks, with a peer that does).
    Exhausted,
    /// The connection closed, or the peer did not meet a retry: the campaign ends.
    Ended,
}

pub(crate) struct Retry<'a> {
    pub cell: &'a P2pPathCell,
    pub app: &'a NetworkEndpoint,
    pub slot: &'a RearmSlot,
    pub rearmable: bool,
    /// The UDP mode the connection began with.
    pub udp_mode: UdpMode,
    pub peer_cid: u64,
}

impl Retry<'_> {
    pub(crate) async fn run<F, Fut>(&self, schedule: &mut Schedule, attempt: &F) -> RetryEnd
    where
        F: Fn(Instant, UdpMode) -> Fut,
        Fut: Future<Output = bool>,
    {
        let peer_cid = self.peer_cid;
        loop {
            if schedule.budget == 0 && !self.rearmable {
                log::info!(target: "citadel", "P2P route to peer {peer_cid} not restored with no retries left; staying on the server relay");
                return RetryEnd::Exhausted;
            }
            // A side out of retries goes straight to the rendezvous, where both agree to park
            // (or, if either was asked to upgrade, to a fresh budget).
            if schedule.budget > 0 {
                self.cell.resume_upgrading();
                if schedule.wait_first {
                    citadel_io::time::sleep(schedule.backoff).await;
                    schedule.backoff = (schedule.backoff * 2).min(RECOVERY_BACKOFF_MAX);
                }
            }
            schedule.wait_first = true;
            if self.cell.is_closed() {
                return RetryEnd::Ended;
            }
            let meet = p2p_rearm::rendezvous(
                self.app,
                self.rearmable,
                self.slot,
                self.udp_mode,
                schedule.budget,
            );
            let retry = match citadel_io::time::timeout(RENDEZVOUS_TIMEOUT, meet).await {
                Ok(Ok(retry)) => retry,
                _ => {
                    log::info!(target: "citadel", "Peer {peer_cid} did not meet the P2P retry; staying on the server relay");
                    return RetryEnd::Ended;
                }
            };
            if retry.budget == 0 {
                log::info!(target: "citadel", "P2P route to peer {peer_cid} not restored with no retries left; staying on the server relay");
                return RetryEnd::Exhausted;
            }
            schedule.budget = retry.budget - 1;
            self.cell.resume_upgrading();
            // The UDP channel belonged to the lost route; a retry restores it only when asked.
            if attempt(Instant::now(), retry.udp_mode).await {
                log::info!(target: "citadel", "P2P route to peer {peer_cid} restored");
                return RetryEnd::Attached;
            }
        }
    }
}

/// Waits until the connection's P2P route is lost. `false` when the connection closed instead,
/// or when no campaign can retry.
pub(crate) async fn wait_for_fall_back(cell: &P2pPathCell) -> bool {
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
