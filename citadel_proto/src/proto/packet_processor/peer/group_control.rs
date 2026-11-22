//! A group's control messages: its Commits and hierarchy assignments.
//!
//! Only a group's owner makes them: its creator, until ownership passes (see `group_succession`).
//! A server relays one only from the session it authenticated as the group's recorded owner, and
//! a member that cannot apply one keeps the state it had and its session: the message is a single
//! group's affair, not the connection's.

use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::group_cgka::GroupCgkaState;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

/// Server: whether a control message from the authenticated `sender` is relayed, for a group
/// whose recorded owner is `owner` (`None`: no such group here).
pub(crate) fn relays_control_from(sender: u64, owner: Option<u64>) -> bool {
    owner == Some(sender)
}

/// Server: whether `session_cid` is `key`'s recorded owner, the only member that may add, kick
/// or end. A request from anyone else is answered as failed.
pub(crate) async fn permits_control<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    session_cid: u64,
    key: MessageGroupKey,
) -> bool {
    let owner = session.hypernode_peer_layer.group_owner(key).await;
    let permitted = owner == Some(session_cid);
    if !permitted {
        log::warn!(target: "citadel", "Refusing a control request for {key:?} from {session_cid}: the group's owner is {owner:?}");
    }
    permitted
}

/// Member: applies the owner's Commit for `epoch`, if this member holds the group.
pub(crate) fn apply_commit(
    cgka: Option<&mut GroupCgkaState>,
    key: MessageGroupKey,
    payload: &[u8],
    epoch: u64,
) {
    if let Some(Err(err)) = cgka.map(|cgka| cgka.process_commit(payload, epoch)) {
        log::warn!(target: "citadel", "Ignoring a Commit for {key:?} epoch {epoch} this member cannot apply: {err}");
    }
}

/// Member: takes up the hierarchy position the owner assigned, if this member holds the group.
pub(crate) fn apply_hierarchy_assignment(
    cgka: Option<&mut GroupCgkaState>,
    key: MessageGroupKey,
    payload: &[u8],
) {
    if let Some(Err(err)) = cgka.map(|cgka| cgka.apply_hierarchy_assignment(payload)) {
        log::warn!(target: "citadel", "Ignoring a hierarchy assignment for {key:?} this member cannot apply: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::GroupHierarchyMode;

    const OWNER: u64 = 1;
    const MEMBER: u64 = 2;
    const KEY: MessageGroupKey = MessageGroupKey {
        cid: OWNER,
        mgid: 42,
    };

    fn owner_and_member() -> (GroupCgkaState, GroupCgkaState) {
        let mut owner = GroupCgkaState::new_owner(OWNER, GroupHierarchyMode::Flat).unwrap();
        let (mut member, key_package) =
            GroupCgkaState::new_joiner(MEMBER, GroupHierarchyMode::Flat).unwrap();
        let (welcome, _commit, _epoch, _assignments) = owner.add_member(&key_package).unwrap();
        member.join(&welcome).unwrap();
        (owner, member)
    }

    #[test]
    fn a_server_relays_control_messages_only_from_the_groups_recorded_owner() {
        assert!(relays_control_from(OWNER, Some(OWNER)));
        assert!(!relays_control_from(MEMBER, Some(OWNER)));
        // Once ownership has passed to MEMBER, the creator's control messages are not relayed.
        assert!(relays_control_from(MEMBER, Some(MEMBER)));
        assert!(!relays_control_from(KEY.cid, Some(MEMBER)));
        assert!(!relays_control_from(OWNER, None));
    }

    #[test]
    fn a_commit_a_member_cannot_read_changes_nothing() {
        let (mut owner, mut member) = owner_and_member();
        for epoch in 0..4 {
            apply_commit(Some(&mut member), KEY, b"not a commit", epoch);
        }
        let wire = owner.encrypt_message(b"still in step").unwrap();
        assert_eq!(member.decrypt_message(&wire).unwrap().1, b"still in step");
    }

    #[test]
    fn an_assignment_a_member_cannot_open_changes_nothing() {
        let (mut owner, mut member) = owner_and_member();
        apply_hierarchy_assignment(Some(&mut member), KEY, b"not an assignment");
        assert!(member.is_flat());
        let wire = owner.encrypt_message(b"still flat").unwrap();
        assert_eq!(member.decrypt_message(&wire).unwrap().1, b"still flat");
    }

    #[test]
    fn a_commit_for_a_group_this_member_does_not_hold_is_ignored() {
        apply_commit(None, KEY, b"anything", 1);
        apply_hierarchy_assignment(None, KEY, b"anything");
    }
}
