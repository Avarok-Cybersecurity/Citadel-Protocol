//! A client's group once the server has replayed what it held for it (`Resumed`): it is live
//! again. The application is told where its state came from, and a state that came from the
//! server's sealed copy has its leaf replaced, so no other device of the account can follow the
//! group on: a member by publishing a KeyPackage for a fresh leaf, the owner by committing one.

use super::group_broadcast::{forward_signal, GroupBroadcast};
use super::group_restore::{session_cid, Reply};
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupStateSource, MessageGroupKey};

/// What this device sends to replace its leaf, decided under the state lock.
enum Replace {
    Nothing,
    KeyPackage(Vec<u8>),
    Commit { payload: Vec<u8>, epoch: u64 },
}

/// Client, on `Resumed` for `key`.
pub(super) fn resumed<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let cid = session_cid(session)?;
    let (source, replace) = {
        let mut state = inner_mut_state!(session.state_container);
        match state.group_cgka.get_mut(&key) {
            Some(cgka) if cgka.needs_new_leaf() && cgka.is_owner() => {
                let (payload, epoch) = cgka.replace_own_leaf()?;
                (GroupStateSource::Backup, Replace::Commit { payload, epoch })
            }
            Some(cgka) if cgka.needs_new_leaf() => (
                GroupStateSource::Backup,
                Replace::KeyPackage(cgka.new_leaf_key_package(cid)?),
            ),
            Some(_) => (GroupStateSource::ThisDevice, Replace::Nothing),
            None => return Ok(PrimaryProcessorResult::Void),
        }
    };
    let restored = GroupBroadcast::Restored { key, source };
    let _ = forward_signal(session, reply.ticket, Some(key), restored)?;
    match replace {
        Replace::Nothing => Ok(PrimaryProcessorResult::Void),
        Replace::KeyPackage(payload) => {
            log::info!(target: "citadel", "Replacing this member's leaf in {key:?}");
            reply.send(GroupBroadcast::KeyPackage {
                key,
                joiner_cid: cid,
                payload,
            })
        }
        Replace::Commit { payload, epoch } => {
            log::info!(target: "citadel", "Replacing the owner's leaf in {key:?}");
            reply.send(GroupBroadcast::Commit {
                key,
                epoch,
                payload,
            })
        }
    }
}
