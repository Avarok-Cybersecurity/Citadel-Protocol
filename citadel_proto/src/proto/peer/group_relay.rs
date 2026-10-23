//! Whom the server relays a group broadcast to, and how: the group's members, mailed when offline
//! unless the group is ephemeral; and, for a message, whether it is within the group's caps (see
//! `group_limits`).
//!
//! Each lookup takes the registry's lock once, for reading, as the member lookup it replaces did.
//! The server handles a session's inbound packets concurrently, so a broadcast's relay order is
//! the order its handlers pass this lock: a handler that waited longer here (a write lock behind
//! the readers) would let a later message overtake it.

use crate::constants::{protocol_version_at_least, GROUP_RELAY_OPTIONS_SINCE};
use crate::error::NetworkError;
use crate::proto::peer::group_limits::admit;
use crate::proto::peer::message_group::MessageGroup;
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_io::{error, ErrorCode};
use citadel_types::proto::{GroupMessageRefusal, MessageGroupKey, MessageGroupOptions};

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

/// Client: whether the server, at `server_version`, can honour the relay options of a group about
/// to be created with `options`. A server before them would ignore them (mail an ephemeral
/// group's broadcasts, relay any message), so such a group is refused here, before it exists.
pub(crate) fn server_honours_relay_options(
    options: &MessageGroupOptions,
    server_version: Option<u32>,
) -> Result<(), NetworkError> {
    if options.needs_relay_options()
        && !protocol_version_at_least(server_version, GROUP_RELAY_OPTIONS_SINCE)
    {
        return Err(error!(ErrorCode::GroupRelayOptionsUnsupported));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROTOCOL_VERSION;
    use citadel_types::proto::GroupMessageLimits;
    use embedded_semver::Semver;

    fn older() -> Option<u32> {
        Some(Semver::new(0, 12, 1).to_u32().unwrap())
    }

    fn refused(options: &MessageGroupOptions, version: Option<u32>) -> Option<ErrorCode> {
        server_honours_relay_options(options, version)
            .err()
            .map(|err| err.code())
    }

    #[test]
    fn an_older_server_is_refused_an_ephemeral_or_limited_group() {
        let ephemeral = MessageGroupOptions {
            ephemeral: true,
            ..Default::default()
        };
        let limited = MessageGroupOptions {
            limits: GroupMessageLimits::new(64, 4).ok(),
            ..Default::default()
        };
        for options in [&ephemeral, &limited] {
            for version in [older(), None] {
                assert_eq!(
                    refused(options, version),
                    Some(ErrorCode::GroupRelayOptionsUnsupported),
                    "{options:?} at {version:?}"
                );
            }
            assert_eq!(refused(options, Some(*PROTOCOL_VERSION)), None);
        }
    }

    #[test]
    fn an_ordinary_group_is_created_on_any_server() {
        for version in [older(), None, Some(*PROTOCOL_VERSION)] {
            assert_eq!(refused(&MessageGroupOptions::default(), version), None);
        }
    }
}
