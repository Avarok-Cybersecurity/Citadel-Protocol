//! Reading a replay group's log, trimming it, and moving it to a new owner (see `group_log` for
//! where it is stored).

use super::group_log::{
    append, group_id, io_error, log_map, seq_key, write_meta, StoredEntry, NO_PEER, ORDERS,
};
use super::group_sequencer::GroupOrder;
use crate::error::NetworkError;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;

/// The stored entries at `seqs` of `key`'s log, in the order asked. A position the log no longer
/// holds is an error: the caller asked for it because the log said it had it.
pub(crate) async fn read<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    holder: u64,
    key: MessageGroupKey,
    seqs: &[u64],
) -> Result<Vec<StoredEntry>, NetworkError> {
    let mut entries = Vec::with_capacity(seqs.len());
    for seq in seqs {
        let bytes = pers
            .get_byte_map_value(holder, NO_PEER, &log_map(key), &seq_key(*seq))
            .await
            .map_err(|err| io_error("read an entry", err))?
            .ok_or_else(|| io_error("read an entry", format!("{seq} is not stored")))?;
        entries.push(
            StoredEntry::deserialize_from_vector(&bytes)
                .map_err(|err| io_error("decode an entry", err))?,
        );
    }
    Ok(entries)
}

/// Removes the entries at `seqs`. The caller has written the meta that says they are trimmed.
pub(crate) async fn remove<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    holder: u64,
    key: MessageGroupKey,
    seqs: &[u64],
) -> Result<(), NetworkError> {
    for seq in seqs {
        let _ = pers
            .remove_byte_map_value(holder, NO_PEER, &log_map(key), &seq_key(*seq))
            .await
            .map_err(|err| io_error("remove an entry", err))?;
    }
    Ok(())
}

/// Keeps `order`'s log within its limits at `now_ns`: the new floor is written before anything
/// is removed, so a crash between the two leaves entries the log no longer counts, never a log
/// that starts later than it says.
pub(crate) async fn trim<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    key: MessageGroupKey,
    order: &mut GroupOrder,
    now_ns: i64,
) -> Result<(), NetworkError> {
    let Some((dropped, through)) = order.replay.as_ref().and_then(|l| l.over_limits(now_ns)) else {
        return Ok(());
    };
    order.trimmed(through);
    write_meta(pers, key, order).await?;
    remove(pers, order.holder, key, &dropped).await
}

/// Moves `order`'s log and meta from its holder to `to`: everything is written under `to`
/// first and removed from the old holder after, so a crash between leaves a duplicate (the load
/// takes the furthest), never no log.
pub(crate) async fn relocate<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    key: MessageGroupKey,
    order: &mut GroupOrder,
    to: u64,
) -> Result<(), NetworkError> {
    let from = order.holder;
    let seqs: Vec<u64> = order
        .replay
        .as_ref()
        .map(|log| log.entries.iter().map(|e| e.seq).collect())
        .unwrap_or_default();
    for (seq, entry) in seqs.iter().zip(read(pers, from, key, &seqs).await?) {
        append(pers, to, key, *seq, &entry).await?;
    }
    order.holder = to;
    write_meta(pers, key, order).await?;
    remove(pers, from, key, &seqs).await?;
    let _ = pers
        .remove_byte_map_value(from, NO_PEER, ORDERS, &group_id(key))
        .await
        .map_err(|err| io_error("remove an order", err))?;
    Ok(())
}
