//! The Commit acknowledgement that orders a join, at the owner and the members: the owner sends a
//! join's Commit and holds the Welcome, and each member acknowledges the Commit to the server,
//! which tells the owner once the Commit has settled (`group_commit_relay`). The rule for whom
//! the server waits on, and for how long, is in `group_commit_gate`; the owner's order of joins
//! is in `group_cgka::join_queue`.
//!
//! Every node takes part only with an adjacent node at `GROUP_COMMIT_ACK_SINCE` or later. With an
//! older one it does what it did before: the owner sends the Welcome, then the Commit, and the
//! server relays the Commit and waits on nobody.

use super::super::includes::*;
use super::group_broadcast::GroupBroadcast;
use crate::constants::{protocol_version_at_least, GROUP_COMMIT_ACK_SINCE};
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::outbound_sender::OutboundPrimaryStreamSender;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_cgka::join_queue::{HeldWelcome, QueuedKeyPackage};
use crate::proto::peer::group_cgka::GroupCgkaState;
use crate::proto::remote::Ticket;
use crate::proto::state_container::StateContainerInner;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

/// Whether the node at the other end of this node's C2S link takes part.
pub(crate) fn adjacent_acks<R: Ratchet>(state: &StateContainerInner<R>) -> bool {
    protocol_version_at_least(state.adjacent_protocol_version, GROUP_COMMIT_ACK_SINCE)
}

/// What every group packet one handler sends has in common.
pub(crate) struct Crafter<'a, R> {
    pub ratchet: &'a R,
    pub timestamp: i64,
    pub security_level: SecurityLevel,
}

impl<R: Ratchet> Crafter<'_, R> {
    fn packet(&self, signal: &GroupBroadcast, ticket: Ticket) -> Result<BytesMut, NetworkError> {
        packet_crafter::peer_cmd::craft_group_message_packet(
            self.ratchet,
            signal,
            ticket,
            C2S_IDENTITY_CID,
            self.timestamp,
            self.security_level,
        )
    }

    /// The packets that deliver a Welcome: the joiner's hierarchy assignment first, if it has
    /// one, so the joiner is in hierarchy mode before its channel opens, then the Welcome.
    pub(crate) fn welcome(
        &self,
        key: MessageGroupKey,
        held: HeldWelcome,
    ) -> Result<Vec<BytesMut>, NetworkError> {
        let target_cid = held.joiner_cid;
        let mut packets = Vec::with_capacity(2);
        if let Some(payload) = held.assignment {
            let assign = GroupBroadcast::HierarchyAssign {
                key,
                target_cid,
                payload,
            };
            packets.push(self.packet(&assign, held.ticket)?);
        }
        let welcome = GroupBroadcast::Welcome {
            key,
            joiner_cid: target_cid,
            payload: held.welcome,
        };
        packets.push(self.packet(&welcome, held.ticket)?);
        Ok(packets)
    }

    /// Owner: send a Welcome it held, ahead of a Commit about to follow it (see
    /// `JoinQueue::flush`).
    pub(crate) fn release_welcome(
        &self,
        key: MessageGroupKey,
        held: HeldWelcome,
        to_primary_stream: &OutboundPrimaryStreamSender,
    ) -> Result<(), NetworkError> {
        for packet in self.welcome(key, held)? {
            to_primary_stream
                .unbounded_send(packet)
                .map_err(|err| NetworkError::generic(err.to_string()))?;
        }
        Ok(())
    }

    fn commit(
        &self,
        key: MessageGroupKey,
        epoch: u64,
        payload: Vec<u8>,
        ticket: Ticket,
    ) -> Result<BytesMut, NetworkError> {
        let commit = GroupBroadcast::Commit {
            key,
            epoch,
            payload,
        };
        self.packet(&commit, ticket)
    }

    /// Owner: add the next queued joiner, if no Welcome is held, and hold its Welcome. A
    /// KeyPackage that cannot be added is logged and skipped, so it cannot stall those behind it.
    fn start_next_join(
        &self,
        cgka: &mut GroupCgkaState,
        key: MessageGroupKey,
    ) -> Result<Vec<BytesMut>, NetworkError> {
        while let Some(next) = cgka.joins.next() {
            match cgka.add_member(&next.key_package) {
                Ok((welcome, commit, epoch, assignment)) => {
                    cgka.joins.hold(HeldWelcome {
                        epoch,
                        joiner_cid: next.joiner_cid,
                        welcome,
                        assignment,
                        ticket: next.ticket,
                    });
                    return Ok(vec![self.commit(key, epoch, commit, next.ticket)?]);
                }
                Err(err) => {
                    log::error!(target: "citadel", "Not adding {} to {key:?}: its KeyPackage cannot be added: {err}", next.joiner_cid);
                }
            }
        }
        Ok(Vec::new())
    }
}

fn send_all<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ticket: Ticket,
    packets: Vec<BytesMut>,
) -> Result<(), NetworkError> {
    for packet in packets {
        session.send_to_primary_stream(Some(ticket), packet)?;
    }
    Ok(())
}

/// Owner: incorporate a joiner's `KeyPackage`. With a server that takes part, the Commit goes out
/// now and the Welcome when the Commit settles; otherwise the Welcome, then the Commit.
///
/// The packets are queued while the state lock is held, so nothing this owner seals at the new
/// epoch can reach a member ahead of the Commit that moves it there.
pub(super) fn owner_add_member<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    crafter: &Crafter<'_, R>,
    key: MessageGroupKey,
    joiner_cid: u64,
    key_package: &[u8],
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let mut state = inner_mut_state!(session.state_container);
    let gated = adjacent_acks(&state);
    // No state: this owner session has not re-founded the group yet. A member restoring
    // after the same outage can publish before this session's `RestoreOwnership` lands;
    // once it does, the server prompts the member again, and that KeyPackage is added.
    // Failing the session here cut the owner's link, and its reconnect raced the same way.
    let Some(cgka) = state.group_cgka.get_mut(&key) else {
        log::warn!(target: "citadel", "Ignoring a KeyPackage for {key:?} from {joiner_cid}: this session holds no tree for the group yet");
        return Ok(PrimaryProcessorResult::Void);
    };
    let packets = if gated {
        cgka.joins.enqueue(QueuedKeyPackage {
            joiner_cid,
            key_package: key_package.to_vec(),
            ticket,
        });
        crafter.start_next_join(cgka, key)?
    } else {
        let (welcome, commit, epoch, assignment) = cgka.add_member(key_package)?;
        let held = HeldWelcome {
            epoch,
            joiner_cid,
            welcome,
            assignment,
            ticket,
        };
        let mut packets = crafter.welcome(key, held)?;
        packets.push(crafter.commit(key, epoch, commit, ticket)?);
        packets
    };
    send_all(session, ticket, packets)?;
    Ok(PrimaryProcessorResult::Void)
}

/// Owner: the server reports the Commit for `epoch` settled. Release the Welcome it held, then
/// start the next queued join.
pub(super) fn owner_commit_settled<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    crafter: &Crafter<'_, R>,
    key: MessageGroupKey,
    epoch: u64,
    ticket: Ticket,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let mut state = inner_mut_state!(session.state_container);
    let Some(cgka) = state.group_cgka.get_mut(&key) else {
        log::warn!(target: "citadel", "Ignoring CommitSettled for {key:?}: this session holds no tree for the group");
        return Ok(PrimaryProcessorResult::Void);
    };
    let mut packets = match cgka.joins.settled(epoch) {
        Some(held) => crafter.welcome(key, held)?,
        None => Vec::new(),
    };
    packets.extend(crafter.start_next_join(cgka, key)?);
    send_all(session, ticket, packets)?;
    Ok(PrimaryProcessorResult::Void)
}

/// Member: tell the server this member has processed the Commit for `epoch`. Called with the
/// state lock still held from processing it, so every message this member sealed at the old
/// epoch is already queued ahead of the acknowledgement.
pub(super) fn acknowledge_commit<R: Ratchet, T: PlatformOps>(
    state: &StateContainerInner<R>,
    session: &CitadelSession<R, T>,
    crafter: &Crafter<'_, R>,
    key: MessageGroupKey,
    epoch: u64,
    ticket: Ticket,
) -> Result<(), NetworkError> {
    if !adjacent_acks(state) {
        return Ok(());
    }
    let packet = crafter.packet(&GroupBroadcast::CommitApplied { key, epoch }, ticket)?;
    session.send_to_primary_stream(Some(ticket), packet)
}
