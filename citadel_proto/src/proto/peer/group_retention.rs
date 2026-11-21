//! What happens to an owner's message groups when the owner's session ends.
//!
//! A session ending is not leaving. A flat group's owner whose session ends still owns the group:
//! the group stays, its members keep sending to each other, and the owner resumes it when it
//! reconnects (see `group_resume`). Ownership passes only when the owner leaves (see
//! `group_succession`), and a group ends only when its owner closes it (`End`) or its last member
//! leaves. No timer ends a group.
//!
//! Command-hierarchy groups are dissolved at departure: their rank table lives only in the
//! owner's session (it never reaches the relay), so a re-founded group could only be flat, and
//! silently turning a group whose members may read only their subordinates into one where
//! everyone reads everything would be a confidentiality downgrade nobody agreed to.

use crate::proto::packet_processor::includes::Instant;
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};

/// A group that no longer exists, and the members (owner excluded) to tell.
pub type DissolvedGroup = (MessageGroupKey, Vec<u64>);

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Called when `owner`'s session `incarnation` ends: removes the command-hierarchy groups it
    /// owns and returns them with their members. Its flat groups stay. When a newer session has
    /// been admitted for this cid (a lingering session cleaned up after its replacement
    /// connected), the groups belong to the live session, so nothing is touched; it is decided
    /// under the lock, as it acts, so a replacement admitted before then is seen.
    pub async fn on_owner_departure(
        &self,
        owner: u64,
        incarnation: Instant,
    ) -> Vec<DissolvedGroup> {
        let mut this = self.inner.write().await;
        if !this.is_current_session(owner, incarnation) {
            return Vec::new();
        }
        let hierarchical: Vec<MessageGroupKey> = this
            .message_groups
            .iter()
            .flat_map(|(creator, groups)| {
                groups
                    .iter()
                    .filter(|(_, group)| {
                        group.owner == owner
                            && !matches!(group.options.hierarchy, GroupHierarchyMode::Flat)
                    })
                    .map(|(mgid, _)| MessageGroupKey {
                        cid: *creator,
                        mgid: *mgid,
                    })
            })
            .collect();
        let mut dissolved = Vec::with_capacity(hierarchical.len());
        for key in hierarchical {
            let Some(group) = this
                .message_groups
                .get_mut(&key.cid)
                .and_then(|groups| groups.remove(&key.mgid))
            else {
                continue;
            };
            this.commit_gates.close(key);
            this.persist_group_or_log(key).await;
            let members = group
                .concurrent_peers
                .into_keys()
                .filter(|cid| *cid != owner)
                .collect();
            dissolved.push((key, members));
        }
        dissolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_io::tokio;
    use citadel_types::proto::{MessageGroupOptions, ReadPolicy};
    use citadel_user::account_manager::AccountManager;
    use citadel_user::backend::BackendType;
    use std::time::Duration;

    const OWNER: u64 = 10;
    /// The owner's session.
    static SESSION: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    const MEMBER: u64 = 20;

    async fn layer_with_groups(
        options: &[MessageGroupOptions],
    ) -> (CitadelNodePeerLayer<StackedRatchet>, Vec<MessageGroupKey>) {
        let acc = AccountManager::<StackedRatchet, StackedRatchet>::new(
            BackendType::InMemory,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let layer = CitadelNodePeerLayer::new(acc.get_persistence_handler().clone());
        layer.admit(OWNER, *SESSION);
        let _ = layer.register_peer(OWNER).await.unwrap();
        let mut keys = Vec::new();
        for opts in options {
            let key = layer
                .create_new_message_group(OWNER, &vec![MEMBER], opts.clone())
                .await
                .unwrap();
            assert!(layer.upgrade_peer_in_group(key, MEMBER).await);
            keys.push(key);
        }
        (layer, keys)
    }

    fn flat() -> MessageGroupOptions {
        MessageGroupOptions::default()
    }

    fn hierarchical() -> MessageGroupOptions {
        MessageGroupOptions {
            hierarchy: GroupHierarchyMode::CommandHierarchy {
                read_policy: ReadPolicy::SuperiorOnly,
                ranks: Default::default(),
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_flat_group_outlives_its_owners_session_and_keeps_its_owner() {
        let (layer, keys) = layer_with_groups(&[flat()]).await;
        assert!(layer.on_owner_departure(OWNER, *SESSION).await.is_empty());
        assert!(layer.message_group_exists(keys[0]).await);
        assert_eq!(layer.group_owner(keys[0]).await, Some(OWNER));
    }

    #[tokio::test]
    async fn a_hierarchy_group_is_dissolved_at_departure() {
        let (layer, keys) = layer_with_groups(&[hierarchical(), flat()]).await;
        let dissolved = layer.on_owner_departure(OWNER, *SESSION).await;
        assert_eq!(dissolved, vec![(keys[0], vec![MEMBER])]);
        assert!(!layer.message_group_exists(keys[0]).await);
        assert!(layer.message_group_exists(keys[1]).await);
    }

    #[tokio::test]
    async fn a_lingering_sessions_shutdown_leaves_the_replacements_groups_alone() {
        let (layer, keys) = layer_with_groups(&[hierarchical()]).await;
        layer.admit(OWNER, *SESSION + Duration::from_millis(1));
        assert!(layer.on_owner_departure(OWNER, *SESSION).await.is_empty());
        assert!(layer.message_group_exists(keys[0]).await);
    }
}
