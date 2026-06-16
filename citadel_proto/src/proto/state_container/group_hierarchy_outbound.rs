//! Owner-side outbound handling for the Decentralized Hierarchy Encryption overlay: founding the
//! owner's CGKA at group creation and the `promote`/`demote` admin operations. Split out of
//! [`super::rekey_and_groups`] to keep that file focused; these run on the owner node only and emit
//! sealed `HierarchyAssign` (and, for demote, a re-key `Commit`) — command paths never reach the relay.

use super::includes::*;
use crate::proto::peer::group_cgka::GroupCgkaState;
use citadel_io::{error, ErrorCode};
use citadel_types::proto::{CommandPath, MessageGroupOptions};

impl<R: Ratchet> StateContainerInner<R> {
    /// Found the owner's CGKA state for a group it is creating. The key is locally derivable
    /// (`cid == this node`, `mgid == options.id`), so this runs at `Create` time without a round trip.
    pub(super) fn init_owner_cgka(
        &mut self,
        options: &MessageGroupOptions,
    ) -> Result<(), NetworkError> {
        let owner_cid = self
            .cnac
            .as_ref()
            .map(|c| c.get_cid())
            .ok_or_else(|| error!(ErrorCode::StateCnacNotLoaded))?;
        let key = MessageGroupKey::new(owner_cid, options.id);
        if !self.group_cgka.contains_key(&key) {
            let cgka = GroupCgkaState::new_owner(owner_cid, options.hierarchy.clone())?;
            let _ = self.group_cgka.insert(key, cgka);
        }
        Ok(())
    }

    /// Owner-local `promote`: (re)assign `target_cid` to `path` and, if they have already joined, send
    /// the sealed `HierarchyAssign` now (otherwise it is delivered when they join).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn outbound_promote(
        &mut self,
        key: MessageGroupKey,
        target_cid: u64,
        path: CommandPath,
        ratchet: &R,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
        to_primary_stream: &OutboundPrimaryStreamSender,
    ) -> Result<(), NetworkError> {
        let sealed = self
            .group_cgka
            .get_mut(&key)
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?
            .promote(target_cid, path)?;
        if let Some(payload) = sealed {
            self.send_hierarchy_assign(
                key,
                target_cid,
                payload,
                ratchet,
                ticket,
                timestamp,
                security_level,
                to_primary_stream,
            )?;
        }
        Ok(())
    }

    /// Owner-local `demote`: rotate + re-seal every member's assignment and epoch-bump, then send each
    /// `HierarchyAssign` and the re-key `Commit`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn outbound_demote(
        &mut self,
        key: MessageGroupKey,
        target_cid: u64,
        ratchet: &R,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
        to_primary_stream: &OutboundPrimaryStreamSender,
    ) -> Result<(), NetworkError> {
        let (assignments, commit_bytes, epoch) = self
            .group_cgka
            .get_mut(&key)
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?
            .demote(target_cid)?;

        for (member_cid, payload) in assignments {
            self.send_hierarchy_assign(
                key,
                member_cid,
                payload,
                ratchet,
                ticket,
                timestamp,
                security_level,
                to_primary_stream,
            )?;
        }

        let commit = GroupBroadcast::Commit {
            key,
            epoch,
            payload: commit_bytes,
        };
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            ratchet,
            &commit,
            ticket,
            C2S_IDENTITY_CID,
            timestamp,
            security_level,
        );
        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }

    /// Craft + send a sealed `HierarchyAssign` to one member (the relay routes it to `target_cid`).
    #[allow(clippy::too_many_arguments)]
    fn send_hierarchy_assign(
        &self,
        key: MessageGroupKey,
        target_cid: u64,
        payload: Vec<u8>,
        ratchet: &R,
        ticket: Ticket,
        timestamp: i64,
        security_level: SecurityLevel,
        to_primary_stream: &OutboundPrimaryStreamSender,
    ) -> Result<(), NetworkError> {
        let signal = GroupBroadcast::HierarchyAssign {
            key,
            target_cid,
            payload,
        };
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            ratchet,
            &signal,
            ticket,
            C2S_IDENTITY_CID,
            timestamp,
            security_level,
        );
        to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| NetworkError::generic(err.to_string()))
    }
}
