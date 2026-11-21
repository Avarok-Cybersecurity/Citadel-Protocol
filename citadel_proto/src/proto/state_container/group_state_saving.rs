//! Keeping this client's group states in its account store as they change (see
//! `peer::group_state_store`).

use super::StateContainerInner;
use crate::proto::peer::group_state_store;
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
        }
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
