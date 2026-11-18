//! The `Disconnect` a link reports exactly once, on a true close (§7.3).

use citadel_types::proto::ObjectId;

use super::media::{MediaLedger, MediaLoss};
use super::{Drained, Undelivered};
use crate::event::CloseSummary;
use crate::kind::Ticket;

/// A file or group transfer that did not finish: its id and progress, never its bytes (owner
/// Q10: the bytes are on disk at the sender).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UndeliveredTransfer {
    pub object_id: ObjectId,
    pub ticket: Ticket,
    pub bytes_acked: u64,
    pub bytes_total: u64,
}

/// What was dropped by contract and only counted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DroppedCounts {
    /// Bytes of sends refused because the outbound budget was spent (each refused at once).
    pub over_budget_bytes: u64,
    pub udp_datagrams: u64,
    /// The sum of every stream's `MediaLoss::dropped`.
    pub media_frames: u64,
    pub control_frames: u64,
}

/// The kernel-facing close event: the core's summary plus everything the link never delivered.
/// Every payload in it was moved out of the outbox; none was copied.
#[derive(Debug)]
pub struct LinkDisconnect<P> {
    pub summary: CloseSummary,
    /// In send order.
    pub undelivered: Vec<Undelivered<P>>,
    /// Flushed to a route with no acknowledgement at this layer.
    pub possibly_delivered: Vec<Ticket>,
    pub undelivered_transfers: Vec<UndeliveredTransfer>,
    /// One record per media stream the link carried.
    pub media: Vec<MediaLoss>,
    pub dropped: DroppedCounts,
}

impl<P> LinkDisconnect<P> {
    /// The one assembly of a close event, from the core's summary and the outbox's drain (SSOT):
    /// what the retired incarnations' own queues returned joins the outbox's undelivered in send
    /// order, and the media counts come from the ledger alone.
    pub fn assemble(
        summary: CloseSummary,
        drained: Drained<P>,
        retired: Vec<Undelivered<P>>,
        media: &mut MediaLedger,
        undelivered_transfers: Vec<UndeliveredTransfer>,
        lossy: LossyCounts,
    ) -> Self {
        let mut undelivered = drained.undelivered;
        undelivered.extend(retired);
        undelivered.sort_by_key(|u| u.seq);
        let media = media.close();
        let media_frames = media.iter().map(|m| m.dropped).sum();
        LinkDisconnect {
            summary,
            undelivered,
            possibly_delivered: drained.possibly_delivered,
            undelivered_transfers,
            media,
            dropped: DroppedCounts {
                over_budget_bytes: drained.over_budget_bytes,
                udp_datagrams: lossy.udp_datagrams,
                media_frames,
                control_frames: lossy.control_frames,
            },
        }
    }
}

/// The counts of the queues the outbox does not own (UDP, negotiation lane), from the shell.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LossyCounts {
    pub udp_datagrams: u64,
    pub control_frames: u64,
}
