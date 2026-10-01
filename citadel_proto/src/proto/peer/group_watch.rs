//! Server-side rendezvous for a member waiting on a group its owner has not created yet.
//!
//! A joiner used to poll `ListGroupsFor` with sleeps of 1, 2, 4, 8 and 16 s and give up about 31 s
//! in, so an owner that created its group any later, or was merely stalled, left the joiner
//! failed for good. Now the joiner sends `AwaitGroup` and the server answers `GroupAvailable`
//! when the group exists: at once if it already does, otherwise when its owner creates it.
//!
//! The existence check and the registration happen under one write lock, and creation inserts
//! the group before it takes the watches, so a watch is either answered at registration or
//! taken at creation; it cannot fall between the two.

use crate::proto::peer::peer_layer::CitadelNodePeerLayer;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

/// Outstanding watches one session may hold, matching the groups one owner may hold.
pub const MAX_GROUP_WATCHES_PER_SESSION: usize = u8::MAX as usize + 1;

/// The server's answer to an `AwaitGroup`.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupWatch {
    /// The group exists now.
    Available,
    /// Registered: the watcher is told when the group is created.
    Pending,
    /// The session already holds [`MAX_GROUP_WATCHES_PER_SESSION`] watches.
    Refused,
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Answers now if `key` exists, otherwise registers `watcher`'s `ticket` for its creation.
    pub async fn watch_group(
        &self,
        watcher: u64,
        ticket: Ticket,
        key: MessageGroupKey,
    ) -> GroupWatch {
        let mut this = self.inner.write().await;
        let exists = this
            .message_groups
            .get(&key.cid)
            .is_some_and(|groups| groups.contains_key(&key.mgid));
        if exists {
            return GroupWatch::Available;
        }
        let watches = this.group_watches.entry(watcher).or_default();
        if watches.values().map(Vec::len).sum::<usize>() >= MAX_GROUP_WATCHES_PER_SESSION {
            return GroupWatch::Refused;
        }
        watches.entry(key).or_default().push(ticket);
        GroupWatch::Pending
    }

    /// Removes and returns every `(watcher, ticket)` waiting for `key`. Call after `key` exists.
    pub async fn take_group_watchers(&self, key: MessageGroupKey) -> Vec<(u64, Ticket)> {
        let mut this = self.inner.write().await;
        let mut taken = Vec::new();
        this.group_watches.retain(|watcher, watches| {
            if let Some(tickets) = watches.remove(&key) {
                taken.extend(tickets.into_iter().map(|ticket| (*watcher, ticket)));
            }
            !watches.is_empty()
        });
        taken
    }

    /// Forgets `watcher`'s watches when its session ends; nobody is left to answer.
    pub async fn drop_group_watches(&self, watcher: u64) {
        let _ = self.inner.write().await.group_watches.remove(&watcher);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_io::tokio;
    use citadel_types::proto::MessageGroupOptions;
    use citadel_user::account_manager::AccountManager;
    use citadel_user::backend::BackendType;

    const OWNER: u64 = 10;
    const JOINER: u64 = 20;
    const MGID: u128 = 7;

    fn key() -> MessageGroupKey {
        MessageGroupKey {
            cid: OWNER,
            mgid: MGID,
        }
    }

    async fn layer() -> CitadelNodePeerLayer<StackedRatchet> {
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
        layer
    }

    async fn create(layer: &CitadelNodePeerLayer<StackedRatchet>) {
        let options = MessageGroupOptions {
            id: MGID,
            ..Default::default()
        };
        assert_eq!(
            layer
                .create_new_message_group(OWNER, &vec![], options)
                .await,
            Some(key())
        );
    }

    #[citadel_io::tokio::test]
    async fn a_watch_placed_before_creation_is_answered_by_creation() {
        let layer = layer().await;
        assert_eq!(
            layer.watch_group(JOINER, Ticket(1), key()).await,
            GroupWatch::Pending
        );
        create(&layer).await;
        assert_eq!(
            layer.take_group_watchers(key()).await,
            vec![(JOINER, Ticket(1))]
        );
        assert!(layer.take_group_watchers(key()).await.is_empty());
    }

    #[citadel_io::tokio::test]
    async fn a_watch_on_an_existing_group_is_answered_at_once() {
        let layer = layer().await;
        create(&layer).await;
        assert_eq!(
            layer.watch_group(JOINER, Ticket(1), key()).await,
            GroupWatch::Available
        );
        assert!(layer.take_group_watchers(key()).await.is_empty());
    }

    #[citadel_io::tokio::test]
    async fn another_groups_creation_leaves_the_watch_in_place() {
        let layer = layer().await;
        let other = MessageGroupKey {
            cid: OWNER,
            mgid: MGID + 1,
        };
        let _ = layer.watch_group(JOINER, Ticket(1), key()).await;
        assert!(layer.take_group_watchers(other).await.is_empty());
        assert_eq!(
            layer.take_group_watchers(key()).await,
            vec![(JOINER, Ticket(1))]
        );
    }

    #[citadel_io::tokio::test]
    async fn a_departed_watcher_is_not_answered() {
        let layer = layer().await;
        let _ = layer.watch_group(JOINER, Ticket(1), key()).await;
        layer.drop_group_watches(JOINER).await;
        create(&layer).await;
        assert!(layer.take_group_watchers(key()).await.is_empty());
    }

    #[citadel_io::tokio::test]
    async fn watches_per_session_are_bounded() {
        let layer = layer().await;
        for ticket in 0..MAX_GROUP_WATCHES_PER_SESSION as u128 {
            assert_eq!(
                layer.watch_group(JOINER, Ticket(ticket), key()).await,
                GroupWatch::Pending
            );
        }
        assert_eq!(
            layer.watch_group(JOINER, Ticket(u128::MAX), key()).await,
            GroupWatch::Refused
        );
    }
}
