//! A member's guarantee that each position of a group reaches its application at most once while
//! this process runs.
//!
//! A server hands a member a position again only when the member did not confirm it had it: a
//! backlog is removed once it is handed to the member's stream (`group_mail::forget`), so a
//! connection lost in between hands the same positions over on the next resume. Positions reach
//! a member in increasing order, so the last one delivered is all this needs to keep. It is kept
//! per node, not per session, because the repeat arrives on a new session. A consumer that keeps
//! state across its own restarts must still be idempotent by position.

use citadel_types::proto::MessageGroupKey;
use std::collections::HashMap;

/// The last position delivered, per local member and group.
#[derive(Default, Debug)]
pub struct GroupDelivered {
    last: HashMap<(u64, MessageGroupKey), u64>,
}

impl GroupDelivered {
    /// Whether `seq` of `key` is new to `member` here; recorded as delivered when it is.
    pub(crate) fn first_time(&mut self, member: u64, key: MessageGroupKey, seq: u64) -> bool {
        let last = self.last.entry((member, key)).or_default();
        if seq <= *last {
            return false;
        }
        *last = seq;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: MessageGroupKey = MessageGroupKey { cid: 1, mgid: 2 };

    #[test]
    fn a_position_is_delivered_once_per_member_and_group() {
        let mut delivered = GroupDelivered::default();
        assert!(delivered.first_time(5, KEY, 1));
        assert!(delivered.first_time(5, KEY, 3), "numbers may skip");
        assert!(!delivered.first_time(5, KEY, 3));
        assert!(!delivered.first_time(5, KEY, 2), "and never go back");
        assert!(
            delivered.first_time(6, KEY, 1),
            "another member's count is its own"
        );
        let other = MessageGroupKey { cid: 1, mgid: 3 };
        assert!(delivered.first_time(5, other, 1), "as is another group's");
    }
}
