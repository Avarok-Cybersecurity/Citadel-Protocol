//! What became of one group message, member by member, as its sender's server reports it.

use serde::{Deserialize, Serialize};

/// The server's account of a group message it was asked to relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupDelivery {
    /// The server relayed it; each other member is in exactly one list.
    Relayed {
        /// Sent now to the member's live session.
        delivered: Vec<u64>,
        /// Held for the member, who reads it when it next connects.
        stored: Vec<u64>,
        /// Members it will not reach, and why.
        not_delivered: Vec<(u64, NotDelivered)>,
    },
    /// It reached no server, or the server could not relay it at all.
    NotRelayed(NotRelayed),
}

/// Why one member will not receive a relayed group message.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotDelivered {
    /// The member is offline and the group is ephemeral: nothing is held for it.
    Offline,
    /// What the server holds for the member in this group is at its cap.
    BacklogFull,
    /// The member could be neither reached nor held for.
    Unreachable,
}

/// Why a group message was not relayed to anyone.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotRelayed {
    /// The session that would have carried it has ended.
    SessionEnded,
    /// The server holds no such group.
    UnknownGroup,
    /// This session holds no keys for the group yet.
    NoGroupKey,
}

impl GroupDelivery {
    /// Whether every other member received the message or has it held for them.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Relayed { not_delivered, .. } if not_delivered.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_relay_that_reached_or_held_for_everyone_is_complete() {
        let relayed = |not_delivered| GroupDelivery::Relayed {
            delivered: vec![1],
            stored: vec![2],
            not_delivered,
        };
        assert!(relayed(vec![]).is_complete());
        assert!(!relayed(vec![(3, NotDelivered::Offline)]).is_complete());
        assert!(!GroupDelivery::NotRelayed(NotRelayed::SessionEnded).is_complete());
    }
}
