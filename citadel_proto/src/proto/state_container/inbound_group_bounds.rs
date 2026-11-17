//! How many groups a peer may hold open on this node for reassembly, and for how long.
//!
//! A group a peer announced is held only while its own packets keep arriving. It is reclaimed,
//! with the file transfer it belongs to, once it has been silent for [`GROUP_EXPIRE_TIME_MS`]
//! while the session was silent too, or once it has been silent for
//! [`INBOUND_GROUP_SILENCE_CEILING`] whatever else the session carried. No peer holds more than
//! [`MAX_INBOUND_GROUPS_PER_PEER`] open at once.

use super::includes::*;
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::proto::session_queue_handler::QueueWorkerResult;
use std::time::Duration;

/// The most groups one peer may have open here at once. A file transfer keeps at most two of
/// its groups in flight (the next is announced once the current one is half acknowledged), so
/// this admits 32 concurrent transfers from one peer while bounding what a peer can pin by
/// announcing groups it never sends.
pub(crate) const MAX_INBOUND_GROUPS_PER_PEER: usize = 64;

/// How long a group may stay silent while the session carries other traffic. The shorter
/// [`GROUP_EXPIRE_TIME_MS`] spares a group whose packets are queued behind other groups' on a
/// busy session; no sender's queue keeps a group waiting ten times that long.
pub(crate) const INBOUND_GROUP_SILENCE_CEILING: Duration =
    Duration::from_secs(GROUP_EXPIRE_TIME_MS.as_secs() * 10);

/// Whether an open group is reclaimed, given whether it has been silent past
/// [`GROUP_EXPIRE_TIME_MS`], whether past [`INBOUND_GROUP_SILENCE_CEILING`], and whether the
/// session as a whole has been silent past [`GROUP_EXPIRE_TIME_MS`].
pub(crate) fn reclaims(silent: bool, silent_past_ceiling: bool, session_silent: bool) -> bool {
    silent_past_ceiling || (silent && session_silent)
}

impl<R: Ratchet> StateContainerInner<R> {
    /// The groups `peer_cid` has open here.
    pub(crate) fn inbound_groups_open_for(&self, peer_cid: u64) -> usize {
        self.inbound_groups
            .iter()
            .filter(|entry| entry.key().target_cid == peer_cid)
            .count()
    }

    /// The periodic check on an open group: `Complete` once the group is gone, whether it
    /// completed or was reclaimed here; `Incomplete` while it is still held.
    pub(crate) fn reclaim_inbound_group_if_silent(&self, key: GroupKey) -> QueueWorkerResult {
        // Decide under a scoped `Ref`, then DROP it before any inbound_groups.remove (DashMap
        // self-deadlock otherwise).
        let should_remove = match self.inbound_groups.get(&key) {
            None => return QueueWorkerResult::Complete,
            Some(group) => reclaims(
                group.receiver.has_expired(GROUP_EXPIRE_TIME_MS),
                group.receiver.has_expired(INBOUND_GROUP_SILENCE_CEILING),
                self.meta_expiry_state.expired(),
            ),
        };
        if !should_remove {
            return QueueWorkerResult::Incomplete;
        }

        log::warn!(target: "citadel", "Inbound group {} has gone silent; removing for {}.", key.group_id, key.target_cid);
        if let Some((_, group)) = self.inbound_groups.remove(&key) {
            if group.object_id != ObjectId::zero() {
                // belongs to a file: dropping its entry drops the future streaming it to disk
                let file_key = FileKey::new(group.object_id);
                if self.inbound_files.remove(&file_key).is_some() {
                    log::warn!(target: "citadel", "File transfer expired");
                }
                let _ = self.file_transfer_handles.remove(&file_key);
            }
        }
        QueueWorkerResult::Complete
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "inbound_group_bounds_tests.rs"]
mod tests;
