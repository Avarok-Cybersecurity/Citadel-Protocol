//! A client's group once the server has replayed what it held for it (`Resumed`): it is live
//! again. The application is told where its state came from, and a state that came from the
//! server's sealed copy has its leaf replaced, so no other device of the account can follow the
//! group on: a member by publishing a KeyPackage for a fresh leaf, the owner by committing one.
//!
//! A member made the owner while it was away takes over here, from the state it kept as a member:
//! it removes the leaves of whoever left meanwhile and commits from then on. The group relayed
//! while it was away, and what was held for it has just been replayed, so nothing is lost.

use super::group_broadcast::{forward_signal, GroupBroadcast};
use super::group_restore::{session_cid, Reply};
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupStateSource, MessageGroupKey};

/// What this device sends to replace its leaf, decided under the state lock.
enum Replace {
    Nothing,
    KeyPackage(Vec<u8>),
}

/// Client, on `Resumed` for `key`.
pub(super) fn resumed<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
    owner: u64,
    members: &[u64],
) -> Result<PrimaryProcessorResult, NetworkError> {
    let cid = session_cid(session)?;
    let (source, replace) = {
        let mut state = inner_mut_state!(session.state_container);
        match state.group_cgka.get_mut(&key) {
            Some(cgka) if owner == cid && !cgka.is_owner() => {
                log::info!(target: "citadel", "{cid} was made the owner of {key:?} while away; taking over");
                let source = if cgka.needs_new_leaf() {
                    GroupStateSource::Backup
                } else {
                    GroupStateSource::ThisDevice
                };
                let mut commits = cgka.take_ownership_as_of(members)?;
                if cgka.needs_new_leaf() {
                    commits.push(cgka.replace_own_leaf()?);
                }
                send_commits(session, &reply, key, commits)?;
                (source, Replace::Nothing)
            }
            Some(cgka) if cgka.needs_new_leaf() && cgka.is_owner() => {
                let commit = cgka.replace_own_leaf()?;
                send_commits(session, &reply, key, vec![commit])?;
                (GroupStateSource::Backup, Replace::Nothing)
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
    }
}

/// Queues `commits` in order. Called with the state lock held, so nothing this member seals at a
/// later epoch can reach a member ahead of the Commit that opens it.
fn send_commits<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: &Reply<'_, R>,
    key: MessageGroupKey,
    commits: Vec<(Vec<u8>, u64)>,
) -> Result<(), NetworkError> {
    for (payload, epoch) in commits {
        let commit = GroupBroadcast::Commit {
            key,
            epoch,
            payload,
        };
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            reply.sess_ratchet,
            &commit,
            reply.ticket,
            C2S_IDENTITY_CID,
            reply.timestamp,
            reply.security_level,
        )?;
        session.send_to_primary_stream(Some(reply.ticket), packet)?;
    }
    Ok(())
}
