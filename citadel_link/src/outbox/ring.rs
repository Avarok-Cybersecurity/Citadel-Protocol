//! The outbox's operations. Every payload moves: in through `push`, out through exactly one of
//! `drain` (undelivered), a discarding `flushed` (possibly delivered) or `acked`, and never twice.

use std::collections::VecDeque;

use super::{Drained, Entry, Grade, LinkOutbox, Payload, PayloadLane, Refused, Seq, Undelivered};
use crate::kind::{Incarnation, Ticket};

fn byte_len<P: Payload>(payload: &P) -> u64 {
    u64::try_from(payload.byte_len()).unwrap_or(u64::MAX)
}

impl<P: Payload> LinkOutbox<P> {
    /// An empty outbox charged against `budget_bytes` of plaintext. `acknowledging` is whether
    /// the route it starts on acknowledges (`RouteKind::acknowledges`).
    pub fn new(budget_bytes: u64, acknowledging: bool) -> Self {
        LinkOutbox {
            entries: VecDeque::new(),
            budget_bytes,
            used_bytes: 0,
            next_seq: 0,
            acknowledging,
            possibly_delivered: Vec::new(),
            acked: 0,
            over_budget_bytes: 0,
        }
    }

    /// The route changed: whether the new one acknowledges. Entries already written keep the
    /// grade they reached.
    pub fn set_acknowledging(&mut self, acknowledging: bool) {
        self.acknowledging = acknowledging;
    }

    /// Accepts a send in order, or refuses it (with the payload) when the budget is spent.
    pub fn push(
        &mut self,
        ticket: Ticket,
        lane: PayloadLane,
        payload: P,
    ) -> Result<Seq, Refused<P>> {
        let len = byte_len(&payload);
        if self.used_bytes.saturating_add(len) > self.budget_bytes {
            self.over_budget_bytes = self.over_budget_bytes.saturating_add(len);
            return Err(Refused { ticket, payload });
        }
        self.used_bytes += len;
        let seq = Seq(self.next_seq);
        self.next_seq += 1;
        self.entries.push_back(Entry {
            ticket,
            lane,
            seq,
            payload,
            grade: Grade::Queued,
            possibly_seen: false,
        });
        Ok(seq)
    }

    /// Hands every queued payload to `incarnation`, in send order: these are the ones to write
    /// now (a fresh send, or a replay after a heal). Each is marked written before it is
    /// returned, so nothing is written twice to one incarnation.
    pub fn take_writes(&mut self, incarnation: Incarnation) -> Vec<Seq> {
        let mut writes = Vec::new();
        for entry in self.entries.iter_mut() {
            if entry.grade == Grade::Queued {
                entry.grade = Grade::Written(incarnation);
                writes.push(entry.seq);
            }
        }
        writes
    }

    /// The plaintext of a held payload, to encrypt and write. Borrowed: the outbox keeps it.
    pub fn payload(&self, seq: Seq) -> Option<&P> {
        self.find(seq).map(|i| &self.entries[i].payload)
    }

    /// The write of `seq` was flushed. On an acknowledging route it is kept until the ack; on any
    /// other it can never be confirmed, so the plaintext is wiped and only the ticket is kept.
    /// `false` if `seq` was not written (a late flush for a path already lost).
    pub fn flushed(&mut self, seq: Seq) -> bool {
        let Some(i) = self.find(seq) else {
            return false;
        };
        let Grade::Written(incarnation) = self.entries[i].grade else {
            return false;
        };
        if self.acknowledging {
            self.entries[i].grade = Grade::Flushed(incarnation);
        } else if let Some(ticket) = self.discard(i) {
            self.possibly_delivered.push(ticket);
        }
        true
    }

    /// The peer acknowledged `seq`. `false` if it is not held.
    pub fn acked(&mut self, seq: Seq) -> bool {
        let Some(i) = self.find(seq) else {
            return false;
        };
        if self.entries[i].grade == Grade::Queued || self.discard(i).is_none() {
            return false;
        }
        self.acked += 1;
        true
    }

    /// `incarnation`'s path died (or its route fell back to the relay): what it was carrying and
    /// had not seen acknowledged is queued again for the next write, marked possibly seen.
    pub fn path_lost(&mut self, incarnation: Incarnation) {
        for entry in self.entries.iter_mut() {
            if matches!(entry.grade, Grade::Written(i) | Grade::Flushed(i) if i == incarnation) {
                entry.grade = Grade::Queued;
                entry.possibly_seen = true;
            }
        }
    }

    /// A true close: everything still held, by move, in send order.
    pub fn drain(&mut self) -> Drained<P> {
        let entries = std::mem::take(&mut self.entries);
        self.used_bytes = 0;
        let undelivered = entries
            .into_iter()
            .map(|entry| Undelivered {
                possibly_seen: entry.possibly_seen || entry.grade != Grade::Queued,
                ticket: entry.ticket,
                lane: entry.lane,
                seq: entry.seq,
                payload: entry.payload,
            })
            .collect();
        Drained {
            undelivered,
            possibly_delivered: std::mem::take(&mut self.possibly_delivered),
            acked: std::mem::take(&mut self.acked),
            over_budget_bytes: std::mem::take(&mut self.over_budget_bytes),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Plaintext bytes held, charged to the budget.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    pub fn grade(&self, seq: Seq) -> Option<Grade> {
        self.find(seq).map(|i| self.entries[i].grade)
    }

    fn find(&self, seq: Seq) -> Option<usize> {
        self.entries.binary_search_by_key(&seq, |e| e.seq).ok()
    }

    /// Removes entry `i`, wipes its plaintext, releases its bytes and returns its ticket.
    fn discard(&mut self, i: usize) -> Option<Ticket> {
        let mut entry = self.entries.remove(i)?;
        self.used_bytes = self.used_bytes.saturating_sub(byte_len(&entry.payload));
        entry.payload.wipe();
        Some(entry.ticket)
    }
}

impl Payload for citadel_types::crypto::SecBuffer {
    fn byte_len(&self) -> usize {
        self.len()
    }

    fn wipe(&mut self) {
        self.as_mut().fill(0);
    }
}
