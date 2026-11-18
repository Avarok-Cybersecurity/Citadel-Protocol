//! The `Disconnect` a link reports exactly once, on a true close (§7.3).

use citadel_types::proto::ObjectId;

use super::media::MediaLoss;
use super::Undelivered;
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
