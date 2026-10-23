//! Whom the server relays a group broadcast to, and how: the group's members, mailed when offline
//! unless the group is ephemeral; and, for a message, whether it is within the group's caps (see
//! `group_limits`).
//!
//! Each lookup takes the registry's lock once, for reading, as the member lookup it replaces did.
//! The server handles a session's inbound packets concurrently, so a broadcast's relay order is
//! the order its handlers pass this lock: a handler that waited longer here (a write lock behind
//! the readers) would let a later message overtake it.

use crate::proto::peer::group_limits::admit;
use crate::proto::peer::message_group::MessageGroup;
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_types::proto::{GroupMessageRefusal, MessageGroupKey};

/// The members a group broadcast goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBroadcastTargets {
    pub members: Vec<u64>,
    /// `false` for an ephemeral group: a member offline now is not mailed the broadcast.
    pub mail_if_offline: bool,
}

impl GroupBroadcastTargets {
    /// The targets of `group`, or `None` when it has no members.
    fn of(group: &MessageGroup) -> Option<Self> {
        let members: Vec<u64> = group.concurrent_peers.keys().copied().collect();
        (!members.is_empty()).then_some(Self {
            members,
            mail_if_offline: !group.options.ephemeral,
        })
    }
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// The targets of a broadcast to `key`, or `None` when the group does not exist here or has
    /// no members.
    pub async fn group_broadcast_targets(
        &self,
        key: MessageGroupKey,
    ) -> Option<GroupBroadcastTargets> {
        let this = self.inner.read().await;
        let group = this.message_groups.get(&key.cid)?.get(&key.mgid)?;
        GroupBroadcastTargets::of(group)
    }

    /// Admits a message of `bytes` from `sender` to `key` under the group's limits, counting it
    /// against the sender's rate, and returns its targets. A group that does not exist here has
    /// no limits and no targets, as before limits.
    pub async fn admit_group_message(
        &self,
        key: MessageGroupKey,
        sender: u64,
        bytes: usize,
        now: Instant,
    ) -> Result<Option<GroupBroadcastTargets>, GroupMessageRefusal> {
        let this = self.inner.read().await;
        let Some(group) = this
            .message_groups
            .get(&key.cid)
            .and_then(|groups| groups.get(&key.mgid))
        else {
            return Ok(None);
        };
        admit(
            group.options.limits.as_ref(),
            &mut group.rates.lock(),
            sender,
            bytes,
            now,
        )?;
        Ok(GroupBroadcastTargets::of(group))
    }
}
