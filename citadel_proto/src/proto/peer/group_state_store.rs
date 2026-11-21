//! A client's group state, kept in its own account store so that it outlives the session.
//!
//! Each group's [`GroupCgkaState`] is written to the client node's byte map (account cid, group
//! owner, [`GROUP_STATE_MAP`], mgid) whenever it changes, and read back when the server prompts a
//! new session to restore the group. A member that reads its state back resumes the group: it
//! opens what the server held for it while it was away, under the keys it held then, and the
//! owner is not needed for that.
//!
//! Writes go through one writer task per session, in the order they were made, so an older
//! state never lands over a newer one. The bytes are the member's group secrets; they are kept as
//! the account store keeps the account's own keys.

use crate::error::NetworkError;
use crate::proto::peer::group_cgka::GroupCgkaState;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use citadel_types::proto::MessageGroupKey;
use citadel_user::backend::PersistenceHandler;
use zeroize::Zeroizing;

/// The byte map a client's group states are kept in.
pub const GROUP_STATE_MAP: &str = "group_state";

/// One write: the group's state, or `None` to forget it.
pub(crate) type StateWrite = (MessageGroupKey, Option<Zeroizing<Vec<u8>>>);

/// Starts the writer for `cid`'s group states and returns where to send its writes.
pub(crate) fn writer<R: Ratchet>(
    pers: PersistenceHandler<R, R>,
    cid: u64,
) -> UnboundedSender<StateWrite> {
    let (tx, mut rx) = unbounded_channel::<StateWrite>();
    let task = async move {
        while let Some((key, state)) = rx.recv().await {
            let sub_key = key.mgid.to_string();
            let written = match state {
                Some(bytes) => pers
                    .store_byte_map_value(cid, key.cid, GROUP_STATE_MAP, &sub_key, bytes.to_vec())
                    .await
                    .map(|_| ()),
                None => pers
                    .remove_byte_map_value(cid, key.cid, GROUP_STATE_MAP, &sub_key)
                    .await
                    .map(|_| ()),
            };
            if let Err(err) = written {
                log::error!(target: "citadel", "Unable to keep the state of {key:?} for {cid}: {err}");
            }
        }
    };
    let _ = spawn!(task);
    tx
}

/// `cid`'s stored state for `key`, if it kept one.
pub(crate) async fn load<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    cid: u64,
    key: MessageGroupKey,
) -> Result<Option<GroupCgkaState>, NetworkError> {
    let Some(bytes) = pers
        .get_byte_map_value(cid, key.cid, GROUP_STATE_MAP, &key.mgid.to_string())
        .await?
    else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    match GroupCgkaState::import(&bytes) {
        Ok(state) => Ok(Some(state)),
        Err(err) => {
            log::warn!(target: "citadel", "The stored state of {key:?} cannot be read ({err}); rejoining");
            Ok(None)
        }
    }
}
