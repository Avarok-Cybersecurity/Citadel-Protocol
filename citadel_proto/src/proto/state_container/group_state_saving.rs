//! Keeping this client's group states in its account store as they change (see
//! `peer::group_state_store`).

use super::StateContainerInner;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::{group_backup, group_state_store};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

impl<R: Ratchet> StateContainerInner<R> {
    /// Writes every group state that changed since it was last written. A server keeps none.
    pub(crate) fn save_changed_group_states(&mut self) {
        if self.is_server {
            return;
        }
        let changed: Vec<MessageGroupKey> = self
            .group_cgka
            .iter_mut()
            .filter_map(|(key, cgka)| cgka.take_unsaved().then_some(*key))
            .collect();
        for key in changed {
            let state = match self.group_cgka.get(&key).map(|cgka| cgka.export()) {
                Some(Ok(Some(bytes))) => bytes,
                Some(Ok(None)) | None => continue,
                Some(Err(err)) => {
                    log::error!(target: "citadel", "Unable to write out the state of {key:?}: {err}");
                    continue;
                }
            };
            self.write_group_state(key, Some(state));
            let _ = self.group_backups_due.insert(key);
        }
    }

    /// The `KeepState` signals for the states written since the last call, sealed under the
    /// account's key; none when the application gave the node no key for this account.
    pub(crate) fn take_group_backups(&mut self) -> Vec<GroupBroadcast> {
        let due = std::mem::take(&mut self.group_backups_due);
        let Some(cid) = self.cnac.as_ref().map(|cnac| cnac.get_cid()) else {
            return Vec::new();
        };
        let Some(account_key) = self
            .revfs_keys
            .as_ref()
            .and_then(|keys| keys.revfs_key(cid))
        else {
            return Vec::new();
        };
        due.into_iter()
            .filter_map(|key| {
                let state = self.group_cgka.get(&key)?.export().ok()??;
                match group_backup::seal(&account_key, key, &state) {
                    Ok(sealed) => Some(GroupBroadcast::KeepState { key, sealed }),
                    Err(err) => {
                        log::error!(target: "citadel", "{err}");
                        None
                    }
                }
            })
            .collect()
    }

    /// Forgets the stored state of `key`: the group is over for this member.
    pub(crate) fn forget_group_state(&mut self, key: MessageGroupKey) {
        if !self.is_server {
            self.write_group_state(key, None);
        }
    }

    fn write_group_state(
        &mut self,
        key: MessageGroupKey,
        state: Option<zeroize::Zeroizing<Vec<u8>>>,
    ) {
        let Some(cid) = self.cnac.as_ref().map(|cnac| cnac.get_cid()) else {
            return;
        };
        let writer = self.group_state_writer.get_or_insert_with(|| {
            let pers = self
                .node_remote
                .account_manager()
                .get_persistence_handler()
                .clone();
            group_state_store::writer(pers, cid)
        });
        if writer.send((key, state)).is_err() {
            log::error!(target: "citadel", "The group state writer for {cid} has stopped; {key:?} is not kept");
        }
    }
}
