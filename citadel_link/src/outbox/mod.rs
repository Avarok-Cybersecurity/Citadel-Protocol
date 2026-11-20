//! The `LinkOutbox` (§7, Q15): every application payload a link accepted and has not yet seen
//! delivered, in send order, across every incarnation. It generalises the direct-route journal
//! to C2S and the relay. On a heal it replays onto the new incarnation; on a true close it hands
//! back, by move, exactly what was never delivered. Pure: the adapter owns the lock around it.

mod disconnect;
mod media;
mod ring;

pub use disconnect::{DroppedCounts, LinkDisconnect, LossyCounts, UndeliveredTransfer};
pub use media::{FramePoint, MediaLedger, MediaLoss, MediaStream};

use std::collections::VecDeque;

use crate::kind::{Incarnation, Ticket};

/// A payload the outbox can hold. There is deliberately no `Clone` bound: the outbox cannot
/// copy what it holds, so a payload is either still inside it or moved out exactly once.
pub trait Payload {
    /// The bytes charged to the outbound budget.
    fn byte_len(&self) -> usize;
    /// Overwrites the plaintext. Called on every payload the outbox discards (flushed with no
    /// acknowledgement to wait for, or acknowledged), before it is dropped.
    fn wipe(&mut self);
}

/// Which lane a payload was sent on.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PayloadLane {
    Message,
    /// A group (CGKA) message, named by its group key.
    Group {
        owner: u64,
        mgid: u128,
    },
}

/// A payload's place in the outbox's send order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub u64);

/// Where one held payload stands (§7.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Grade {
    /// Not handed to any live incarnation yet (or its incarnation was lost before it was
    /// acknowledged): it will be written on the next `Live`.
    Queued,
    /// Handed to this incarnation's transport; the flush has not completed.
    Written(Incarnation),
    /// Flushed on a route whose peer acknowledges; kept until the acknowledgement.
    Flushed(Incarnation),
}

/// A payload still held, never seen delivered, returned on a true close in send order.
#[derive(Debug)]
pub struct Undelivered<P> {
    pub ticket: Ticket,
    pub lane: PayloadLane,
    pub seq: Seq,
    pub payload: P,
    /// It was written to a path at least once, so the peer may have it.
    pub possibly_seen: bool,
}

/// A send the outbox refused because the budget is spent: the payload goes back to the caller at
/// once (`OutboundRequestRejected`), never silently dropped.
#[derive(Debug)]
pub struct Refused<P> {
    pub ticket: Ticket,
    pub payload: P,
}

/// What a true close takes out of the outbox.
#[derive(Debug)]
pub struct Drained<P> {
    /// In send order.
    pub undelivered: Vec<Undelivered<P>>,
    /// Flushed to a route whose peer does not acknowledge: no ack exists at this layer.
    pub possibly_delivered: Vec<Ticket>,
    pub acked: u64,
    pub over_budget_bytes: u64,
}

#[derive(Debug)]
struct Entry<P> {
    ticket: Ticket,
    lane: PayloadLane,
    seq: Seq,
    payload: P,
    grade: Grade,
    possibly_seen: bool,
}

/// The outbox. Its byte budget is required (PCND): the shell charges it to the session's
/// `OutboundBudget`.
#[derive(Debug)]
pub struct LinkOutbox<P: Payload> {
    entries: VecDeque<Entry<P>>,
    budget_bytes: u64,
    used_bytes: u64,
    next_seq: u64,
    /// Whether the current route acknowledges (`RouteKind::acknowledges`).
    acknowledging: bool,
    possibly_delivered: Vec<Ticket>,
    acked: u64,
    over_budget_bytes: u64,
}
