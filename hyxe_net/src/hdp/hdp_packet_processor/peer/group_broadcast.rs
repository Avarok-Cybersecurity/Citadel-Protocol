use super::super::includes::*;
use serde::{Serialize, Deserialize};
use crate::hdp::peer::message_group::MessageGroupKey;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::hdp_packet_crafter::peer_cmd::ENDPOINT_ENCRYPTION_OFF;
use atomic::Ordering;
use crate::inner_arg::ExpectedInnerTarget;
use crate::functional::IfEqConditional;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_fs::io::SyncIO;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GroupBroadcast {
    // contains the set of peers that will receive an initial invitation (must be connected)
    Create(Vec<u64>),
    LeaveRoom(MessageGroupKey),
    LeaveRoomResponse(MessageGroupKey, bool, String),
    End(MessageGroupKey),
    EndResponse(MessageGroupKey, bool),
    Disconnected(MessageGroupKey),
    // username, key, message
    Message(String, MessageGroupKey, SecBuffer),
    // not actually a "response message", but rather, just like the other response types, just what the server sends to the requesting client
    MessageResponse(MessageGroupKey, bool),
    Add(MessageGroupKey, Vec<u64>),
    AddResponse(MessageGroupKey, Option<Vec<u64>>),
    AcceptMembership(MessageGroupKey),
    AcceptMembershipResponse(bool),
    Kick(MessageGroupKey, Vec<u64>),
    KickResponse(MessageGroupKey, bool),
    Invitation(MessageGroupKey),
    CreateResponse(Option<MessageGroupKey>),
    MemberStateChanged(MessageGroupKey, MemberState),
    GroupNonExists(MessageGroupKey)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MemberState {
    EnteredGroup(Vec<u64>),
    LeftGroup(Vec<u64>)
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GroupMemberAlterMode {
    Leave,
    Kick
}

impl Into<HdpServerResult> for (u64, Ticket, GroupBroadcast) {
    fn into(self) -> HdpServerResult {
        HdpServerResult::GroupEvent(self.0, self.1, self.2)
    }
}

pub async fn process(session_ref: &HdpSession, header: LayoutVerified<&[u8], HdpHeader>, payload: &[u8], sess_hyper_ratchet: &HyperRatchet) -> PrimaryProcessorResult {
    let session = inner!(session_ref);
    let signal = GroupBroadcast::deserialize_from_vector(payload).ok()?;
    let timestamp = session.time_tracker.get_global_time_ns();
    let ticket = header.context_info.get().into();
    let security_level = header.security_level.into();
    // since group broadcast packets never get proxied, the implicated cid is the local session cid
    let implicated_cid = header.session_cid.get();
    match signal {
        GroupBroadcast::Create(initial_peers) => {
            let key = session.session_manager.create_message_group_and_notify(timestamp, ticket, implicated_cid, initial_peers, security_level);
            let signal = GroupBroadcast::CreateResponse(key);
            let return_packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
            PrimaryProcessorResult::ReplyToSender(return_packet)
        }

        GroupBroadcast::MemberStateChanged(key, state) => {
            send_to_kernel(&session, ticket, GroupBroadcast::MemberStateChanged(key, state))
        }

        GroupBroadcast::End(key) => {
            permission_gate(implicated_cid, key)?;
            let success = session.session_manager.remove_message_group(implicated_cid, timestamp, ticket, key, security_level);
            let signal = GroupBroadcast::EndResponse(key, success);
            let return_packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
            PrimaryProcessorResult::ReplyToSender(return_packet)
        }

        GroupBroadcast::EndResponse(key, success) => {
            send_to_kernel(&session, ticket, GroupBroadcast::EndResponse(key, success))
        }

        GroupBroadcast::Disconnected(key) => {
            send_to_kernel(&session, ticket, GroupBroadcast::Disconnected(key))
        }

        GroupBroadcast::Message(username, key, message) => {
            if session.is_server {
                // The message will need to be broadcasted to every member in the group
                let success = session.session_manager.broadcast_signal_to_group(implicated_cid, timestamp, ticket, key, GroupBroadcast::Message(username, key, message), security_level);
                let resp = GroupBroadcast::MessageResponse(key, success);
                let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &resp, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
                PrimaryProcessorResult::ReplyToSender(packet)
            } else {
                // send to kernel
                send_to_kernel(&session, ticket, GroupBroadcast::Message(username, key, message))
            }
        }

        GroupBroadcast::MessageResponse(key, success) => {
            send_to_kernel(&session, ticket, GroupBroadcast::MessageResponse(key, success))
        }

        GroupBroadcast::AcceptMembership(key) => {
            // the server receives this
            // TODO: Optimize the unnecessary borrow-drop-borrow pattern of the SessionManager
            let sess_mgr = inner!(session.session_manager);
            let success = sess_mgr.hypernode_peer_layer.upgrade_peer_in_group(key, implicated_cid);
            if !success {
                log::warn!("Unable to upgrade peer {} for {:?}", implicated_cid, key);
            } else {
                // send broadcast to all group members
                std::mem::drop(sess_mgr);
                let entered = vec![implicated_cid];
                if !session.session_manager.broadcast_signal_to_group(implicated_cid, timestamp, ticket, key, GroupBroadcast::MemberStateChanged(key, MemberState::EnteredGroup(entered)), security_level) {
                    log::warn!("Unable to broadcast member acceptance to group {}", key);
                }
                log::info!("Successfully upgraded {} for {:?}", implicated_cid, key);
            }

            let signal = GroupBroadcast::AcceptMembershipResponse(success);
            let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
            PrimaryProcessorResult::ReplyToSender(packet)
        }

        GroupBroadcast::AcceptMembershipResponse(success) => {
            send_to_kernel(&session, ticket, GroupBroadcast::AcceptMembershipResponse(success))
        }

        GroupBroadcast::LeaveRoom(key) => {
            let success = session.session_manager.kick_from_message_group(GroupMemberAlterMode::Leave, implicated_cid, timestamp, ticket, key, vec![implicated_cid], security_level);
            let message = if success { format!("Successfully removed peer {} from room {}:{}", implicated_cid, key.cid, key.mgid) } else { format!("Unable to remove peer {} from room {}:{}", implicated_cid, key.cid, key.mgid) };
            let signal = GroupBroadcast::LeaveRoomResponse(key, success, message);
            let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
            PrimaryProcessorResult::ReplyToSender(packet)
        }

        GroupBroadcast::LeaveRoomResponse(key, success, response) => {
            send_to_kernel(&session, ticket, GroupBroadcast::LeaveRoomResponse(key, success, response))
        }

        GroupBroadcast::Add(key, peers) => {
            permission_gate(implicated_cid, key)?;
            // the server receives this. It then sends an invitation
            // if peer is not online, leave some mail. If peer is online,
            // send invitation
            let persistence_handler = session.account_manager.get_persistence_handler().clone();
            let sess_mgr = session.session_manager.clone();
            std::mem::drop(session);
            let peer_statuses = persistence_handler.hyperlan_peers_are_mutuals(implicated_cid, &peers).await?;
            let sess_mgr = inner!(sess_mgr);
            if sess_mgr.hypernode_peer_layer.message_group_exists(key) {
                let mut peers_failed = Vec::new();
                let mut peers_okay = Vec::new();
                for (peer, is_registered) in peers.iter().zip(peer_statuses) {
                    if is_registered {
                        if let Err(err) = sess_mgr.send_group_broadcast_signal_to(timestamp, ticket, *peer, true, GroupBroadcast::Invitation(key), security_level) {
                            log::warn!("Unable to send group broadcast from {} to {}: {}", implicated_cid, peer, err);
                            peers_failed.push(*peer);
                        } else {
                            peers_okay.push(*peer);
                        }
                    } else {
                        log::warn!("Peer {} is not registered to {}", peer, implicated_cid);
                        peers_failed.push(*peer);
                    }
                }

                if peers_okay.len() != 0 {
                    sess_mgr.hypernode_peer_layer.add_pending_peers_to_group(key, peers_okay);
                    std::mem::drop(sess_mgr);
                }

                let peers_failed = peers_failed.is_empty().if_eq(true, None).if_false_then(|| Some(peers_failed));

                let signal = GroupBroadcast::AddResponse(key, peers_failed);
                let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
                PrimaryProcessorResult::ReplyToSender(packet)
            } else {
                // Send error message
                let signal = GroupBroadcast::GroupNonExists(key);
                let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &signal, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
                PrimaryProcessorResult::ReplyToSender(packet)
            }
        }

        GroupBroadcast::AddResponse(key, failed_peers) => {
            send_to_kernel(&session, ticket, GroupBroadcast::AddResponse(key, failed_peers))
        }

        GroupBroadcast::Kick(key, peers) => {
            permission_gate(implicated_cid, key)?;
            let success = session.session_manager.kick_from_message_group(GroupMemberAlterMode::Kick, implicated_cid, timestamp, ticket, key, peers, security_level);
            let resp = GroupBroadcast::KickResponse(key, success);
            let packet = hdp_packet_crafter::peer_cmd::craft_group_message_packet(sess_hyper_ratchet, &resp, ticket, ENDPOINT_ENCRYPTION_OFF, timestamp, security_level);
            PrimaryProcessorResult::ReplyToSender(packet)
        }

        GroupBroadcast::KickResponse(key, success) => {
            send_to_kernel(&session, ticket, GroupBroadcast::KickResponse(key, success))
        }

        GroupBroadcast::Invitation(key) => {
            send_to_kernel(&session, ticket, GroupBroadcast::Invitation(key))
        }

        GroupBroadcast::CreateResponse(key_opt) => {
            send_to_kernel(&session, ticket, GroupBroadcast::CreateResponse(key_opt))
        }

        GroupBroadcast::GroupNonExists(key) => {
            send_to_kernel(&session, ticket, GroupBroadcast::GroupNonExists(key))
        }
    }
}

fn send_to_kernel(session: &dyn ExpectedInnerTarget<HdpSessionInner>, ticket: Ticket, broadcast: GroupBroadcast) -> PrimaryProcessorResult {
    let implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
    session.kernel_tx.unbounded_send((implicated_cid, ticket, broadcast).into())?;
    PrimaryProcessorResult::Void
}

/// Returns None if the implicated_cid is NOT the key's cid.
///
/// Passing the permission gate requires that the implicated_cid is the key's owning cid
fn permission_gate(implicated_cid: u64, key: MessageGroupKey) -> Option<()> {
    if implicated_cid != key.cid {
        None
    } else {
        Some(())
    }
}