//! A member's guarantee that each position of a group reaches its application at most once while
//! this process runs, and, in a replay group, in order with nothing skipped unannounced.
//!
//! A server hands a member a position again only when the member did not confirm it had it: a
//! backlog is removed once it is handed to the member's stream (`group_mail::forget`), so a
//! connection lost in between hands the same positions over on the next resume. It is kept per
//! node, not per session, because the repeat arrives on a new session. A consumer that keeps
//! state across its own restarts must still be idempotent by position.
//!
//! - Without replay, numbers may skip, so the last one delivered is all this keeps.
//! - In a replay group (its positions carry a chain head) the numbers have no gaps: a position
//!   past a gap is held, at most [`MAX_HELD_POSITIONS`] of them, and the gap is fetched from the
//!   server; one held past that is dropped and fetched in its turn. Positions the server no
//!   longer keeps are announced (`GroupBroadcast::OrderBroken`), and delivery goes on after them.

use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use citadel_types::proto::{GroupPosition, MessageGroupKey};
use std::collections::{BTreeMap, HashMap};

/// The most positions of one group a member holds past a gap while it fetches the gap.
pub(crate) const MAX_HELD_POSITIONS: usize = 256;

type Member = (u64, MessageGroupKey);

/// The last position delivered, per local member and group, and what a replay group holds past
/// a gap.
#[derive(Default, Debug)]
pub struct GroupDelivered {
    last: HashMap<Member, u64>,
    held: HashMap<Member, Held>,
}

#[derive(Default, Debug)]
struct Held {
    frames: BTreeMap<u64, (GroupBroadcast, GroupPosition)>,
    fetching: bool,
}

/// What a replay group's position that arrived calls for.
#[derive(Debug)]
pub(crate) enum Arrival {
    /// Deliver these, in order: the arrival and whatever it was the gap before.
    Deliver(Vec<(GroupBroadcast, GroupPosition)>),
    /// Fetch `(after, until]` from the server: the arrival is past a gap.
    Fetch { after: u64, until: u64 },
    /// Nothing: delivered already, or held while the gap before it is fetched.
    Nothing,
}

impl GroupDelivered {
    /// Without replay: whether `seq` of `key` is new to `member` here; recorded as delivered
    /// when it is.
    pub(crate) fn first_time(&mut self, member: u64, key: MessageGroupKey, seq: u64) -> bool {
        let last = self.last.entry((member, key)).or_default();
        if seq <= *last {
            return false;
        }
        *last = seq;
        true
    }

    /// The last position delivered to `member` in `key`.
    pub(crate) fn last(&self, member: u64, key: MessageGroupKey) -> u64 {
        self.last.get(&(member, key)).copied().unwrap_or_default()
    }

    /// `member` holds `key` through `through` (it resumes from there, or the positions before
    /// it are not its to read): nothing up to it is delivered again. Returns what that frees.
    pub(crate) fn holds_through(
        &mut self,
        member: u64,
        key: MessageGroupKey,
        through: u64,
    ) -> Vec<(GroupBroadcast, GroupPosition)> {
        let last = self.last.entry((member, key)).or_default();
        *last = (*last).max(through);
        let last = *last;
        let Some(held) = self.held.get_mut(&(member, key)) else {
            return Vec::new();
        };
        held.frames = held.frames.split_off(&(last + 1));
        self.drain(member, key)
    }

    /// In a replay group: `frame` arrived at `position` for `member`. `starts_log` for the
    /// broadcast that turns the log on, whose position is the first with no gap before it.
    pub(crate) fn arrive(
        &mut self,
        member: u64,
        key: MessageGroupKey,
        position: GroupPosition,
        frame: GroupBroadcast,
        starts_log: bool,
    ) -> Arrival {
        let last = self.last.entry((member, key)).or_default();
        if starts_log {
            *last = (*last).max(position.seq.saturating_sub(1));
        }
        let last = *last;
        if position.seq <= last {
            return Arrival::Nothing;
        }
        let held = self.held.entry((member, key)).or_default();
        if position.seq > last + 1 {
            if held.frames.len() < MAX_HELD_POSITIONS || held.frames.contains_key(&position.seq) {
                let _ = held.frames.insert(position.seq, (frame, position));
            }
            if held.fetching {
                return Arrival::Nothing;
            }
            held.fetching = true;
            let until = held.frames.keys().next().map_or(position.seq, |seq| seq - 1);
            return Arrival::Fetch { after: last, until };
        }
        let _ = held.frames.insert(position.seq, (frame, position));
        Arrival::Deliver(self.drain(member, key))
    }

    /// A fetch for `key` was answered and what it carried has arrived: the next fetch, if a gap
    /// is still open before what is held. `None` too when the answer brought nothing new
    /// (`progressed` false), so a fetch is never repeated without end.
    pub(crate) fn fetched(
        &mut self,
        member: u64,
        key: MessageGroupKey,
        progressed: bool,
    ) -> Option<(u64, u64)> {
        let last = self.last(member, key);
        let held = self.held.get_mut(&(member, key))?;
        held.fetching = false;
        let first = *held.frames.keys().next()?;
        if !progressed {
            return None;
        }
        held.fetching = true;
        Some((last, first - 1))
    }

    /// The held frames that follow on from the last delivered, removed and recorded delivered.
    fn drain(&mut self, member: u64, key: MessageGroupKey) -> Vec<(GroupBroadcast, GroupPosition)> {
        let mut out = Vec::new();
        let (Some(last), Some(held)) = (
            self.last.get_mut(&(member, key)),
            self.held.get_mut(&(member, key)),
        ) else {
            return out;
        };
        while let Some(entry) = held.frames.remove(&(*last + 1)) {
            *last += 1;
            out.push(entry);
        }
        if held.frames.is_empty() {
            held.fetching = false;
        }
        out
    }
}

#[cfg(test)]
#[path = "group_delivered_tests.rs"]
mod tests;
