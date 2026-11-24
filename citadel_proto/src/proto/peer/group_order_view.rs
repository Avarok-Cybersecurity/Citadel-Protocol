//! A replay group's order as its server last described it to this member: where the log starts,
//! the member's first readable position, and the limits that apply, among them the largest
//! message the group takes. Shared between a session and its group channel.

use citadel_types::proto::GroupOrderInfo;
use std::sync::Arc;

/// The cell a group channel reads its group's order from.
#[derive(Clone, Default)]
pub struct GroupOrderView(Arc<citadel_io::RwLock<Option<GroupOrderInfo>>>);

impl std::fmt::Debug for GroupOrderView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GroupOrderView").field(&self.get()).finish()
    }
}

impl GroupOrderView {
    /// The order as last described; `None` for a group without replay.
    pub fn get(&self) -> Option<GroupOrderInfo> {
        *self.0.read()
    }

    /// The server described the order as `info`. A member's first position, once told, stays.
    pub(crate) fn set(&self, mut info: GroupOrderInfo) {
        let mut cell = self.0.write();
        if info.joined.is_none() {
            info.joined = cell.and_then(|kept| kept.joined);
        }
        *cell = Some(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::GroupLogLimits;
    use std::time::Duration;

    #[test]
    fn a_members_first_position_is_kept_as_the_order_moves_on() {
        let limits = GroupLogLimits {
            max_age: Duration::from_secs(60),
            max_messages: 10,
            max_bytes: 1 << 20,
            max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES,
        };
        let joined = GroupOrderInfo {
            since: 1,
            head: 4,
            joined: Some(5),
            limits,
        };
        let view = GroupOrderView::default();
        let channel = view.clone();
        view.set(joined);
        view.set(GroupOrderInfo {
            head: 9,
            joined: None,
            ..joined
        });
        let seen = channel.get().unwrap();
        assert_eq!((seen.head, seen.joined), (9, Some(5)));
    }
}
