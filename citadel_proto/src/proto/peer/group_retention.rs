//! What happens to an owner's message groups when the owner's session ends.
//!
//! The server used to delete them on the spot, so any agent restart or network drop destroyed
//! every group the owner held, for the owner and all its members, with nothing telling anyone.
//!
//! Now a departing owner's flat groups are *held* for [`OWNERLESS_GROUP_GRACE`]. If the owner
//! reconnects within it, the groups are restored (see `RestoreOwnership`); if not, they are
//! dissolved and each member is sent `GroupBroadcast::Disconnected`. An explicit `End` still
//! removes a group at once.
//!
//! Command-hierarchy groups are dissolved at departure, not held: their rank table lives only in
//! the owner's session (it never reaches the relay), so a re-founded group could only be flat,
//! and silently turning a group whose members may read only their subordinates into one where
//! everyone reads everything would be a confidentiality downgrade nobody agreed to.

use crate::proto::peer::group_persistence::store_hold;
use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupHierarchyMode, MessageGroupKey};
use std::time::Duration;

/// How long a departed owner's groups are kept for it to reconnect. Long enough for an agent
/// restart or a network change with reconnect back-off; short enough that members of an owner who
/// is gone for good are told within minutes rather than left sending into a group nobody reads.
pub const OWNERLESS_GROUP_GRACE: Duration = Duration::from_secs(15 * 60);

/// A group that no longer exists, and the members (owner excluded) to tell.
pub type DissolvedGroup = (MessageGroupKey, Vec<u64>);

/// The outcome of an owner's session ending.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnerDeparture {
    /// Groups removed now (command-hierarchy groups).
    pub dissolved: Vec<DissolvedGroup>,
    /// Set when flat groups are being held: pass it to [`CitadelNodePeerLayer::expire_ownerless_groups`]
    /// after the grace period.
    pub held: Option<u64>,
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Called when `owner`'s session ends. `replaced` is true when a newer session already holds
    /// this cid (a lingering session being cleaned up after its replacement connected): the
    /// groups belong to the live session, so nothing is touched. `now_ns` (ns since the Unix
    /// epoch) is recorded as the start of the hold, so a server restart keeps only what is left.
    pub async fn on_owner_departure(
        &self,
        owner: u64,
        replaced: bool,
        now_ns: i64,
    ) -> OwnerDeparture {
        if replaced {
            return OwnerDeparture::default();
        }
        let mut this = self.inner.write().await;
        let Some(groups) = this.message_groups.get_mut(&owner) else {
            return OwnerDeparture::default();
        };
        let hierarchical: Vec<u128> = groups
            .iter()
            .filter(|(_, group)| !matches!(group.options.hierarchy, GroupHierarchyMode::Flat))
            .map(|(mgid, _)| *mgid)
            .collect();
        let dissolved = hierarchical
            .into_iter()
            .filter_map(|mgid| groups.remove(&mgid).map(|group| (mgid, group)))
            .map(|(mgid, group)| {
                let members = group
                    .concurrent_peers
                    .into_keys()
                    .filter(|cid| *cid != owner)
                    .collect();
                (MessageGroupKey { cid: owner, mgid }, members)
            })
            .collect();
        let still_held = !groups.is_empty();
        let held = if !still_held {
            None
        } else {
            this.next_departure_token += 1;
            let token = this.next_departure_token;
            let _ = this.ownerless_groups.insert(owner, token);
            Some(token)
        };
        let departure = OwnerDeparture { dissolved, held };
        for (key, _) in &departure.dissolved {
            this.persist_group_or_log(*key).await;
        }
        if held.is_some() {
            if let Err(err) = store_hold(&this.persistence_handler, owner, Some(now_ns)).await {
                log::error!(target: "citadel", "{err}: a restart will give {owner}'s groups a fresh grace period");
            }
        }
        departure
    }

    /// After the grace period: if `owner` has not reconnected since the departure that issued
    /// `token`, remove all its groups and return them with their members. Otherwise nothing.
    pub async fn expire_ownerless_groups(&self, owner: u64, token: u64) -> Vec<DissolvedGroup> {
        let mut this = self.inner.write().await;
        if this.ownerless_groups.get(&owner) != Some(&token) {
            return Vec::new();
        }
        let _ = this.ownerless_groups.remove(&owner);
        let expired: Vec<DissolvedGroup> = this
            .message_groups
            .remove(&owner)
            .unwrap_or_default()
            .into_iter()
            .map(|(mgid, group)| {
                let members = group
                    .concurrent_peers
                    .into_keys()
                    .filter(|cid| *cid != owner)
                    .collect();
                (MessageGroupKey { cid: owner, mgid }, members)
            })
            .collect();
        for (key, _) in &expired {
            this.persist_group_or_log(*key).await;
        }
        if let Err(err) = store_hold(&this.persistence_handler, owner, None).await {
            log::error!(target: "citadel", "{err}: a stale hold for {owner} remains");
        }
        expired
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

    const OWNER: u64 = 10;
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
    async fn a_departed_owners_flat_group_is_held_and_survives_a_reconnect() {
        let (layer, keys) = layer_with_groups(&[flat()]).await;
        let departure = layer.on_owner_departure(OWNER, false, 0).await;
        assert!(departure.dissolved.is_empty());
        let token = departure.held.expect("a flat group is held");
        assert!(layer.message_group_exists(keys[0]).await);

        // The owner reconnects inside the grace period: the expiry finds nothing to do.
        let _ = layer.register_peer(OWNER).await.unwrap();
        assert!(layer.expire_ownerless_groups(OWNER, token).await.is_empty());
        assert!(layer.message_group_exists(keys[0]).await);
    }

    #[tokio::test]
    async fn an_owner_who_never_returns_loses_the_group_and_members_are_named() {
        let (layer, keys) = layer_with_groups(&[flat()]).await;
        let token = layer
            .on_owner_departure(OWNER, false, 0)
            .await
            .held
            .unwrap();
        let expired = layer.expire_ownerless_groups(OWNER, token).await;
        assert_eq!(expired, vec![(keys[0], vec![MEMBER])]);
        assert!(!layer.message_group_exists(keys[0]).await);
    }

    #[tokio::test]
    async fn an_earlier_departures_timer_cannot_expire_a_later_one() {
        let (layer, keys) = layer_with_groups(&[flat()]).await;
        let first = layer
            .on_owner_departure(OWNER, false, 0)
            .await
            .held
            .unwrap();
        let _ = layer.register_peer(OWNER).await.unwrap();
        let second = layer
            .on_owner_departure(OWNER, false, 0)
            .await
            .held
            .unwrap();
        assert!(layer.expire_ownerless_groups(OWNER, first).await.is_empty());
        assert!(layer.message_group_exists(keys[0]).await);
        assert_eq!(layer.expire_ownerless_groups(OWNER, second).await.len(), 1);
    }

    #[tokio::test]
    async fn a_hierarchy_group_is_dissolved_at_departure_not_held() {
        let (layer, keys) = layer_with_groups(&[hierarchical(), flat()]).await;
        let departure = layer.on_owner_departure(OWNER, false, 0).await;
        assert_eq!(departure.dissolved, vec![(keys[0], vec![MEMBER])]);
        assert!(departure.held.is_some(), "the flat group is still held");
        assert!(!layer.message_group_exists(keys[0]).await);
        assert!(layer.message_group_exists(keys[1]).await);
    }

    #[tokio::test]
    async fn a_lingering_sessions_shutdown_leaves_the_replacements_groups_alone() {
        let (layer, keys) = layer_with_groups(&[hierarchical()]).await;
        assert_eq!(
            layer.on_owner_departure(OWNER, true, 0).await,
            OwnerDeparture::default()
        );
        assert!(layer.message_group_exists(keys[0]).await);
    }
}
