//! What a server holds for a group member that is not there to receive a broadcast, and for how
//! long.
//!
//! Each member's backlog for one group is kept in its own byte map (member, group owner,
//! [`GROUP_MAILBOX_MAP`]), one entry per broadcast under `<mgid>/<held at, ns>/<uuid>`, so it is
//! read back in the order it was held. A backlog is bounded by the server's [`GroupMailLimits`]
//! and the group's own retention:
//!
//! - an entry older than the group's maximum age is dropped, both when the backlog is next written
//!   and when it is replayed;
//! - a message that would take the backlog past `max_messages` or `max_bytes` is not held for that
//!   member, and its sender is told so (the member's older backlog is kept);
//! - group control (Commits, membership notices) is always held: a member that misses one can
//!   never follow the group again. It counts toward the bytes others may use, and ages out alike.
//!
//! The decisions are pure ([`admit`], [`expired`]); [`hold`] and [`take`] do the I/O.

use crate::error::NetworkError;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use std::num::NonZeroUsize;
use std::time::Duration;
use uuid::Uuid;

/// The byte map a member's group backlogs are held in.
pub const GROUP_MAILBOX_MAP: &str = "group_mailbox";

/// The most a server holds for one member of one group while it is away. Required server
/// configuration (`ServerLimits::group_mail`): there are no defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupMailLimits {
    /// The longest a broadcast is held. A group may ask for less (`MessageGroupOptions::retention`).
    pub max_age: Duration,
    /// The most messages held per member and group.
    pub max_messages: NonZeroUsize,
    /// The most bytes held per member and group.
    pub max_bytes: NonZeroUsize,
}

impl GroupMailLimits {
    /// The age past which a group's backlog is dropped: the group's retention, never more than the
    /// server's maximum.
    pub fn max_age_for(&self, retention: Option<Duration>) -> Duration {
        retention.map_or(self.max_age, |asked| asked.min(self.max_age))
    }
}

/// One held entry, as far as the bounds are concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeldEntry {
    pub sub_key: String,
    pub held_at_ns: i64,
    pub bytes: usize,
    pub is_message: bool,
}

/// Whether a broadcast is held for a member.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Holding {
    Held,
    BacklogFull,
}

/// The entries of `held` older than `max_age` at `now_ns`.
pub(crate) fn expired(held: &[HeldEntry], max_age: Duration, now_ns: i64) -> Vec<String> {
    let max_age_ns = i64::try_from(max_age.as_nanos()).unwrap_or(i64::MAX);
    held.iter()
        .filter(|entry| now_ns.saturating_sub(entry.held_at_ns) > max_age_ns)
        .map(|entry| entry.sub_key.clone())
        .collect()
}

/// Whether one more broadcast of `bytes` may join `live` (the unexpired backlog).
pub(crate) fn admit(
    live: &[HeldEntry],
    bytes: usize,
    is_message: bool,
    limits: &GroupMailLimits,
) -> Holding {
    if !is_message {
        return Holding::Held;
    }
    let messages = live.iter().filter(|entry| entry.is_message).count();
    let held_bytes: usize = live.iter().map(|entry| entry.bytes).sum();
    if messages >= limits.max_messages.get()
        || held_bytes.saturating_add(bytes) > limits.max_bytes.get()
    {
        Holding::BacklogFull
    } else {
        Holding::Held
    }
}

fn sub_key(mgid: u128, held_at_ns: i64) -> String {
    format!("{mgid}/{held_at_ns:020}/{}", Uuid::new_v4())
}

fn held_at(sub_key: &str, mgid: u128) -> Option<i64> {
    let mut parts = sub_key.splitn(3, '/');
    (parts.next()?.parse::<u128>().ok()? == mgid).then_some(())?;
    parts.next()?.parse().ok()
}

/// `member`'s backlog for `key`, oldest first.
async fn backlog<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    member: u64,
    key: MessageGroupKey,
) -> Result<Vec<(HeldEntry, Vec<u8>)>, NetworkError> {
    let mut entries: Vec<(HeldEntry, Vec<u8>)> = pers
        .get_byte_map_values_by_key(member, key.cid, GROUP_MAILBOX_MAP)
        .await?
        .into_iter()
        .filter_map(|(sub_key, bytes)| {
            let held_at_ns = held_at(&sub_key, key.mgid)?;
            let is_message = matches!(
                GroupBroadcast::deserialize_from_vector(&bytes),
                Ok(GroupBroadcast::Message { .. })
            );
            let entry = HeldEntry {
                sub_key,
                held_at_ns,
                bytes: bytes.len(),
                is_message,
            };
            Some((entry, bytes))
        })
        .collect();
    entries.sort_by(|(a, _), (b, _)| a.sub_key.cmp(&b.sub_key));
    Ok(entries)
}

async fn drop_entries<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    member: u64,
    key: MessageGroupKey,
    sub_keys: &[String],
) -> Result<(), NetworkError> {
    for sub_key in sub_keys {
        let _ = pers
            .remove_byte_map_value(member, key.cid, GROUP_MAILBOX_MAP, sub_key)
            .await?;
    }
    Ok(())
}

/// Holds `signal` for `member` within the bounds, first dropping what has aged out.
pub(crate) async fn hold<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    member: u64,
    key: MessageGroupKey,
    signal: &GroupBroadcast,
    limits: &GroupMailLimits,
    max_age: Duration,
    now_ns: i64,
) -> Result<Holding, NetworkError> {
    let entries: Vec<HeldEntry> = backlog(pers, member, key)
        .await?
        .into_iter()
        .map(|(entry, _)| entry)
        .collect();
    let stale = expired(&entries, max_age, now_ns);
    drop_entries(pers, member, key, &stale).await?;
    let live: Vec<HeldEntry> = entries
        .into_iter()
        .filter(|entry| !stale.contains(&entry.sub_key))
        .collect();
    let bytes = signal
        .serialize_to_vector()
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    let is_message = matches!(signal, GroupBroadcast::Message { .. });
    let holding = admit(&live, bytes.len(), is_message, limits);
    if holding == Holding::Held {
        let _ = pers
            .store_byte_map_value(
                member,
                key.cid,
                GROUP_MAILBOX_MAP,
                &sub_key(key.mgid, now_ns),
                bytes,
            )
            .await?;
    }
    Ok(holding)
}

/// Removes and returns `member`'s backlog for `key`, oldest first, without what has aged out.
pub(crate) async fn take<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    member: u64,
    key: MessageGroupKey,
    max_age: Duration,
    now_ns: i64,
) -> Result<Vec<GroupBroadcast>, NetworkError> {
    let entries = backlog(pers, member, key).await?;
    let all: Vec<String> = entries.iter().map(|(e, _)| e.sub_key.clone()).collect();
    let held: Vec<HeldEntry> = entries.iter().map(|(e, _)| e.clone()).collect();
    let stale = expired(&held, max_age, now_ns);
    drop_entries(pers, member, key, &all).await?;
    Ok(entries
        .into_iter()
        .filter(|(entry, _)| !stale.contains(&entry.sub_key))
        .filter_map(|(_, bytes)| GroupBroadcast::deserialize_from_vector(&bytes).ok())
        .collect())
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "group_mail_tests.rs"]
mod tests;
