//! What a member processes of one inbound group broadcast, in order: a positioned broadcast
//! ([`GroupBroadcast::Ordered`]) is taken apart and handed on at most once (`group_delivered`);
//! in a replay group it waits for the positions before it, which are fetched from the server
//! ([`GroupBroadcast::FetchRange`]), and the answer's broadcasts are handed on with it.

use super::group_broadcast::GroupBroadcast;
use super::group_restore::Reply;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_delivered::Arrival;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupOrderBroken, GroupPosition, MessageGroupKey};

/// A broadcast to process, with its position when it came positioned.
pub(super) type Arrived = (GroupBroadcast, Option<GroupPosition>);

/// The broadcasts `signal` hands on, in the order to process them. Empty when there is nothing
/// to process: a position this node delivered already, one held past a gap, or one sent to the
/// wrong side.
pub(super) fn arrivals<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    signal: GroupBroadcast,
    reply: &Reply<'_, R>,
) -> Result<Vec<Arrived>, NetworkError> {
    if session.is_server {
        return Ok(match signal {
            GroupBroadcast::Ordered { key, .. } => {
                log::warn!(target: "citadel", "Ignoring a positioned broadcast for {key:?}: only a server positions");
                Vec::new()
            }
            signal => vec![(signal, None)],
        });
    }
    match signal {
        GroupBroadcast::Ordered { .. } => positioned(session, member, signal, reply),
        GroupBroadcast::Range { key, frames, .. } => {
            let before = last(session, member, key);
            let mut out = Vec::new();
            for frame in frames {
                out.extend(positioned(session, member, frame, reply)?);
            }
            let progressed = last(session, member, key) > before;
            let next = delivered(session, |d| d.fetched(member, key, progressed));
            if let Some((after, until)) = next {
                fetch(session, reply, key, after, until)?;
            }
            Ok(out)
        }
        GroupBroadcast::Trimmed {
            key,
            earliest,
            order,
        } => {
            let last = last(session, member, key);
            let mut out = Vec::new();
            if last + 1 < earliest {
                out.push((
                    GroupBroadcast::OrderBroken {
                        key,
                        last,
                        reason: GroupOrderBroken::Trimmed { earliest },
                    },
                    None,
                ));
            }
            let freed = delivered(session, |d| {
                d.holds_through(member, key, earliest.saturating_sub(1))
            });
            if let Some((after, until)) = delivered(session, |d| d.fetched(member, key, true)) {
                fetch(session, reply, key, after, until)?;
            }
            out.push((
                GroupBroadcast::Trimmed {
                    key,
                    earliest,
                    order,
                },
                None,
            ));
            out.extend(freed.into_iter().map(|f| advanced(session, key, f)));
            Ok(out)
        }
        signal => Ok(vec![(signal, None)]),
    }
}

/// One positioned broadcast: what it hands on.
fn positioned<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    signal: GroupBroadcast,
    reply: &Reply<'_, R>,
) -> Result<Vec<Arrived>, NetworkError> {
    let GroupBroadcast::Ordered {
        key,
        position,
        frame,
    } = signal
    else {
        log::warn!(target: "citadel", "Ignoring an unpositioned broadcast where a positioned one belongs");
        return Ok(Vec::new());
    };
    if matches!(*frame, GroupBroadcast::Ordered { .. }) {
        log::warn!(target: "citadel", "Ignoring a broadcast for {key:?} positioned twice");
        return Ok(Vec::new());
    }
    if position.chain.is_none() {
        let first_time = delivered(session, |d| d.first_time(member, key, position.seq));
        if !first_time {
            log::trace!(target: "citadel", "Dropping position {} of {key:?}: delivered already", position.seq);
            return Ok(Vec::new());
        }
        return Ok(vec![(*frame, Some(position))]);
    }
    let starts_log = matches!(*frame, GroupBroadcast::ReplayEnabled { .. });
    match delivered(session, |d| d.arrive(member, key, position, *frame, starts_log)) {
        Arrival::Deliver(frames) => Ok(frames
            .into_iter()
            .map(|f| advanced(session, key, f))
            .collect()),
        Arrival::Fetch { after, until } => {
            fetch(session, reply, key, after, until)?;
            Ok(Vec::new())
        }
        Arrival::Nothing => Ok(Vec::new()),
    }
}

/// `frame`, delivered at `position`: the member's stored cursor follows it.
fn advanced<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    key: MessageGroupKey,
    (frame, position): (GroupBroadcast, GroupPosition),
) -> Arrived {
    let mut state = inner_mut_state!(session.state_container);
    if let Some(cgka) = state.group_cgka.get_mut(&key) {
        cgka.cursor = cgka.cursor.max(position.seq);
    }
    (frame, Some(position))
}

/// Asks the server for `(after, until]` of `key`'s log.
fn fetch<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: &Reply<'_, R>,
    key: MessageGroupKey,
    after: u64,
    until: u64,
) -> Result<(), NetworkError> {
    log::info!(target: "citadel", "Fetching ({after}, {until}] of {key:?}: a gap before what arrived");
    #[cfg(feature = "localhost-testing")]
    crate::test_hooks::group_gap_fetched(key);
    let packet = packet_crafter::peer_cmd::craft_group_message_packet(
        reply.sess_ratchet,
        &GroupBroadcast::FetchRange { key, after, until },
        reply.ticket,
        C2S_IDENTITY_CID,
        reply.timestamp,
        reply.security_level,
    )?;
    session.send_to_primary_stream(Some(reply.ticket), packet)
}

fn delivered<R: Ratchet, T: PlatformOps, O>(
    session: &CitadelSession<R, T>,
    f: impl FnOnce(&mut crate::proto::peer::group_delivered::GroupDelivered) -> O,
) -> O {
    f(&mut session.hypernode_peer_layer.group_delivered.lock())
}

fn last<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
) -> u64 {
    delivered(session, |d| d.last(member, key))
}
