//! The owner a client's group channel acts under.
//!
//! A group's owner is its creator until the owner leaves; then the server records a successor
//! and tells the members (`GroupBroadcast::OwnershipTransferred`). Each open channel shares one
//! cell with its session, which updates it as the server reports the owner: at the channel's
//! opening (the Welcome, a restore prompt), and on every transfer. A channel that has left its
//! group holds no owner, so it can make no control request.

use std::sync::Arc;

/// The owner of a group as this session last heard it from the server; `None` once the channel
/// has left the group.
#[derive(Clone)]
pub struct GroupOwner(Arc<citadel_io::RwLock<Option<u64>>>);

impl std::fmt::Debug for GroupOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GroupOwner").field(&self.get()).finish()
    }
}

impl GroupOwner {
    /// A cell naming `owner`.
    pub(crate) fn new(owner: u64) -> Self {
        Self(Arc::new(citadel_io::RwLock::new(Some(owner))))
    }

    /// The owner as last reported, or `None` once the channel has left the group.
    pub fn get(&self) -> Option<u64> {
        *self.0.read()
    }

    /// Whether `cid` is the owner as last reported.
    pub fn is(&self, cid: u64) -> bool {
        self.get() == Some(cid)
    }

    pub(crate) fn set(&self, owner: Option<u64>) {
        *self.0.write() = owner;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_clone_sees_the_reported_owner() {
        let cell = GroupOwner::new(1);
        let channel = cell.clone();
        assert!(channel.is(1));
        cell.set(Some(2));
        assert!(channel.is(2) && !channel.is(1));
        cell.set(None);
        assert_eq!(channel.get(), None);
    }
}
