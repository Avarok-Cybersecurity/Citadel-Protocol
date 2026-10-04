//! Re-arming a P2P path campaign that gave up (`PeerChannel::upgrade`).
//!
//! A campaign whose retry budget is spent, or whose first attempt failed, used to end, leaving the
//! connection on the server relay for life. With a peer at [`PATH_REARM_SINCE`] it parks instead:
//! both peers wait in one `net_select` on the coordination endpoint, each side's future being "my
//! application asked for an upgrade". Whichever side asks first wakes both, the budget and backoff
//! start afresh, and the campaign retries as it does after a fall-back. Either side may ask, and
//! the other need not.
//!
//! Before every retry the two peers exchange whether they want the UDP channel back
//! ([`rendezvous`]). A retry restores it when either asked and this connection began with one;
//! otherwise retries keep the reliable path only, as before. A restored UDP channel reaches the
//! application on `PeerChannel::take_restored_udp`, on both peers.
//!
//! [`PATH_REARM_SINCE`]: crate::constants::PATH_REARM_SINCE

use crate::constants::{protocol_version_at_least, PATH_REARM_SINCE};
use crate::proto::peer::p2p_campaign::RECOVERY_ATTEMPTS;
use crate::proto::peer::p2p_path::P2pPathCell;
use citadel_io::tokio::sync::Notify;
use citadel_io::{error, ErrorCode, NetworkError};
use citadel_types::proto::UdpMode;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use serde::{Deserialize, Serialize};

/// The upgrade an application asked for and the campaign has not yet taken up.
#[derive(Default)]
pub(crate) struct RearmSlot {
    /// `Some(restore_udp)` while a request is pending; several merge (`restore_udp` OR-ed).
    pending: citadel_io::Mutex<Option<bool>>,
    asked: Notify,
}

impl std::fmt::Debug for RearmSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RearmSlot")
            .field("pending", &*self.pending.lock())
            .finish()
    }
}

impl RearmSlot {
    pub(crate) fn request(&self, restore_udp: bool) {
        let mut pending = self.pending.lock();
        *pending = Some(pending.unwrap_or(false) || restore_udp);
        self.asked.notify_one();
    }

    /// Resolves once a request is pending, leaving it for [`Self::take`].
    pub(crate) async fn requested(&self) {
        loop {
            if self.pending.lock().is_some() {
                return;
            }
            self.asked.notified().await;
        }
    }

    /// Takes the pending request, if any: `Some(restore_udp)`.
    pub(crate) fn take(&self) -> Option<bool> {
        self.pending.lock().take()
    }
}

/// Whether the peer parks its campaign rather than ending it.
pub(crate) fn peer_parks(peer_protocol_version: Option<u32>) -> bool {
    protocol_version_at_least(peer_protocol_version, PATH_REARM_SINCE)
}

/// Waits, parked, until either peer asks for an upgrade. `false` when the coordination endpoint
/// failed, which ends the campaign.
pub(crate) async fn park(app: &NetworkEndpoint, slot: &RearmSlot) -> bool {
    match app.net_select(slot.requested()).await {
        Ok(_) => true,
        Err(err) => {
            log::warn!(target: "citadel", "P2P campaign could not stay parked: {err}");
            false
        }
    }
}

/// What each peer brings to a retry's rendezvous.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Terms {
    /// The application asked for an upgrade since the last rendezvous.
    pub requested: bool,
    pub restore_udp: bool,
    /// Retries this side has left, counting the one about to be made.
    pub budget: u32,
}

/// What both peers agree a retry is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Retry {
    pub udp_mode: UdpMode,
    /// Retries left, counting this one; 0 means none is made and both peers park.
    pub budget: u32,
}

/// The agreement both peers compute alike: a request from either side earns a fresh budget,
/// otherwise the smaller budget holds (so both give up together and park together), and UDP is
/// restored when either asked and the connection began with it.
pub(crate) fn agree(mine: Terms, theirs: Terms, original: UdpMode) -> Retry {
    let requested = mine.requested || theirs.requested;
    let restore = (mine.restore_udp || theirs.restore_udp) && original == UdpMode::Enabled;
    Retry {
        udp_mode: if restore {
            UdpMode::Enabled
        } else {
            UdpMode::Disabled
        },
        budget: if requested {
            RECOVERY_ATTEMPTS
        } else {
            mine.budget.min(theirs.budget)
        },
    }
}

/// Meets the peer before a retry and agrees on it (see [`agree`]). With a peer that does not
/// park this only syncs, keeping the reliable path and this side's budget, as before.
pub(crate) async fn rendezvous(
    app: &NetworkEndpoint,
    rearmable: bool,
    slot: &RearmSlot,
    original: UdpMode,
    budget: u32,
) -> Result<Retry, anyhow::Error> {
    if !rearmable {
        app.sync().await?;
        return Ok(Retry {
            udp_mode: UdpMode::Disabled,
            budget,
        });
    }
    let request = slot.take();
    let mine = Terms {
        requested: request.is_some(),
        restore_udp: request.unwrap_or(false),
        budget,
    };
    let theirs = app.sync_exchange_payload(mine).await?;
    Ok(agree(mine, theirs, original))
}

/// Asks a connection's P2P campaign to try again (see the module docs). It outlives
/// `PeerChannel::split`, as [`P2pPathCell`] does.
#[derive(Clone, Debug)]
pub struct PathControl {
    cell: P2pPathCell,
    peer_protocol_version: Option<u32>,
}

impl PathControl {
    pub(crate) fn new(cell: P2pPathCell, peer_protocol_version: Option<u32>) -> Self {
        Self {
            cell,
            peer_protocol_version,
        }
    }

    /// Re-arms the campaign: a fresh retry budget, as after a fall-back, whether it gave up or
    /// is still retrying. `restore_udp` asks for the UDP channel back; a connection that began
    /// with one then gets a new one, delivered on `PeerChannel::take_restored_udp`. Progress shows
    /// on the path cell as always (`upgrading`, then the path or `upgrading = false` again).
    /// Nothing to do on a P2P path. Refused when the peer predates protocol 0.12.1, when the
    /// campaign has ended, or when the connection closed.
    pub fn upgrade(&self, restore_udp: bool) -> Result<(), NetworkError> {
        let status = self.cell.status();
        if let Some(err) = refuse_upgrade(
            self.peer_protocol_version,
            status.closed,
            self.cell.campaign_alive(),
        ) {
            return Err(err);
        }
        if !status.is_p2p() {
            self.cell.rearm().request(restore_udp);
        }
        Ok(())
    }
}

/// Why an upgrade cannot be asked for, checked before the request is recorded.
pub(crate) fn refuse_upgrade(
    peer_protocol_version: Option<u32>,
    closed: bool,
    campaign_alive: bool,
) -> Option<NetworkError> {
    if closed {
        return Some(error!(
            ErrorCode::P2pUpgradeUnavailable,
            "the connection closed"
        ));
    }
    if !peer_parks(peer_protocol_version) {
        return Some(error!(ErrorCode::P2pUpgradeUnsupported));
    }
    if !campaign_alive {
        return Some(error!(
            ErrorCode::P2pUpgradeUnavailable,
            "the campaign ended (its peer never met it, or the connection was superseded)"
        ));
    }
    None
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "p2p_rearm_tests.rs"]
mod tests;
