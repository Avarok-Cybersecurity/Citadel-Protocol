//! Group Broadcast Handler for Citadel Protocol
//!
//! This module implements the group messaging and management functionality in the
//! Citadel Protocol network. It handles group creation, membership management,
//! message broadcasting, and group state synchronization.
//!
//! # Features
//!
//! - Group creation and termination
//! - Membership management (add, remove, kick)
//! - Message broadcasting
//! - Permission control
//! - Group state tracking
//! - Invitation handling
//! - Group listing
//!
//! # Important Notes
//!
//! - All group operations require authentication
//! - Group owners have special permissions
//! - Messages are securely encrypted
//! - Supports group state persistence
//! - Handles member disconnections
//!
//! # Related Components
//!
//! - `CitadelSession`: Session management
//! - `MessageGroupKey`: Group identification
//! - `GroupBroadcastPayload`: Message handling
//! - `MessageGroupOptions`: Group configuration
//! - `MemberState`: Member status tracking

use super::super::includes::*;
use crate::error::NetworkError;
use crate::functional::*;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::{GroupChannelCreated, GroupEvent};
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_cgka::GroupCgkaState;
use crate::proto::peer::group_channel::GroupBroadcastPayload;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecBuffer;
use citadel_types::proto::{
    GroupHierarchyMode, GroupMemberAlterMode, MemberState, MessageGroupKey, MessageGroupOptions,
};
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Enum representing different types of group broadcast messages
pub enum GroupBroadcast {
    /// Create a new group with initial invitees
    Create {
        /// CIDs of initial members
        initial_invitees: Vec<u64>,
        /// Group configuration options
        options: MessageGroupOptions,
    },
    /// Leave a group
    LeaveRoom {
        /// Group key
        key: MessageGroupKey,
    },
    /// Response to leaving a group
    LeaveRoomResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
        /// Response message
        message: String,
    },
    /// End a group
    End {
        /// Group key
        key: MessageGroupKey,
    },
    /// Response to ending a group
    EndResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
    },
    /// Disconnected from a group
    Disconnected {
        /// Group key
        key: MessageGroupKey,
    },
    /// Message broadcast to a group
    Message {
        /// Sender CID
        sender: u64,
        /// Group key
        key: MessageGroupKey,
        /// Message payload
        message: SecBuffer,
    },
    /// Response to a message broadcast
    MessageResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
    },
    /// A joiner publishes its post-quantum TreeKEM `KeyPackage` to the group owner so the owner can
    /// Add it to the ratchet tree. `payload` is an opaque serialized `citadel_treekem::KeyPackage` —
    /// the relay forwards it verbatim and never inspects it (zero-trust).
    KeyPackage {
        /// Group key
        key: MessageGroupKey,
        /// The joining member's CID (so the owner knows where to route the Welcome)
        joiner_cid: u64,
        /// Opaque serialized `citadel_treekem::KeyPackage`
        payload: Vec<u8>,
    },
    /// The group owner delivers a TreeKEM `Welcome` to a single joiner (routed to `joiner_cid`).
    /// `payload` is an opaque serialized `citadel_treekem::Welcome`; the relay never inspects it.
    Welcome {
        /// Group key
        key: MessageGroupKey,
        /// The joining member's CID (the server routes this packet to this CID)
        joiner_cid: u64,
        /// Opaque serialized `citadel_treekem::Welcome`
        payload: Vec<u8>,
    },
    /// The group owner broadcasts a TreeKEM `Commit` to the existing members (everyone but the joiner).
    /// `payload` is an opaque serialized `citadel_treekem::Commit`; the relay never inspects it.
    Commit {
        /// Group key
        key: MessageGroupKey,
        /// The epoch this commit advances the group into (monotonic; used for ordering/gating)
        epoch: u64,
        /// Opaque serialized `citadel_treekem::Commit`
        payload: Vec<u8>,
    },
    /// The group owner delivers a Decentralized-Hierarchy-Encryption node-secret assignment to one
    /// member (routed to `target_cid`). `payload` is the member's command path + node secret, sealed to
    /// that member's leaf KEM key — opaque to the relay, which sees neither the path nor the secret.
    HierarchyAssign {
        /// Group key
        key: MessageGroupKey,
        /// The member receiving the assignment (the server routes this packet to this CID)
        target_cid: u64,
        /// Opaque KEM-sealed `citadel_treekem::HierarchyMember`
        payload: Vec<u8>,
    },
    /// Owner-local request (from the group handle) to assign/raise `target_cid` to `path`. Handled
    /// entirely on the owner node — it never reaches the relay; the resulting [`Self::HierarchyAssign`]
    /// (carrying only the sealed node secret) is what goes on the wire, so `path` stays off it.
    Promote {
        /// Group key
        key: MessageGroupKey,
        /// The member being (re)assigned
        target_cid: u64,
        /// The command path to assign (owner-local; never serialized to the relay)
        path: citadel_types::proto::CommandPath,
    },
    /// Owner-local request (from the group handle) to revoke `target_cid`'s elevated rank. Handled on
    /// the owner node: it rotates the hierarchy, re-seals each member's assignment, and epoch-bumps.
    Demote {
        /// Group key
        key: MessageGroupKey,
        /// The member being demoted
        target_cid: u64,
    },
    /// Add members to a group
    Add {
        /// Group key
        key: MessageGroupKey,
        /// CIDs of members to add
        invitees: Vec<u64>,
    },
    /// Response to adding members to a group
    AddResponse {
        /// Group key
        key: MessageGroupKey,
        /// List of failed invitations
        failed_to_invite_list: Option<Vec<u64>>,
    },
    /// Accept membership in a group
    AcceptMembership {
        /// Target CID
        target: u64,
        /// Group key
        key: MessageGroupKey,
    },
    /// Decline membership in a group
    DeclineMembership {
        /// Target CID
        target: u64,
        /// Group key
        key: MessageGroupKey,
    },
    /// Response to accepting membership in a group
    AcceptMembershipResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
    },
    /// Response to declining membership in a group
    DeclineMembershipResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
    },
    /// Kick members from a group
    Kick {
        /// Group key
        key: MessageGroupKey,
        /// CIDs of members to kick
        kick_list: Vec<u64>,
    },
    /// Response to kicking members from a group
    KickResponse {
        /// Group key
        key: MessageGroupKey,
        /// Success status
        success: bool,
    },
    /// List groups for a user
    ListGroupsFor {
        /// User CID
        cid: u64,
    },
    /// Response to listing groups for a user
    ListResponse {
        /// List of group keys
        groups: Vec<MessageGroupKey>,
    },
    /// Request to join a group
    RequestJoin {
        /// Sender CID
        sender: u64,
        /// Group key
        key: MessageGroupKey,
    },
    /// Invitation to join a group
    Invitation {
        /// Sender CID
        sender: u64,
        /// Group key
        key: MessageGroupKey,
    },
    /// Response to creating a group
    CreateResponse {
        /// Group key (optional)
        key: Option<MessageGroupKey>,
    },
    /// Member state changed
    MemberStateChanged {
        /// Group key
        key: MessageGroupKey,
        /// New member state
        state: MemberState,
    },
    /// Group does not exist
    GroupNonExists {
        /// Group key
        key: MessageGroupKey,
    },
    /// Request to join a group is pending
    RequestJoinPending {
        /// Result of the request
        result: Result<(), String>,
        /// Group key
        key: MessageGroupKey,
    },
}

#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_ref.is_server, src = header.session_cid.get(), target = header.target_cid.get()
    )
))]
/// Process a group broadcast message
pub async fn process_group_broadcast<R: Ratchet, T: PlatformOps>(
    session_ref: &CitadelSession<R, T>,
    header: Ref<&[u8], HdpHeader>,
    payload: &[u8],
    sess_ratchet: &R,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;
    let signal = return_if_none!(
        GroupBroadcast::deserialize_from_vector(payload).ok(),
        "invalid GroupBroadcast packet"
    );
    let timestamp = session.time_tracker.get_global_time_ns();
    let ticket = header.context_info.get().into();
    let security_level = header.security_level.into();
    // since group broadcast packets never get proxied, the implicated cid is the local session cid
    let session_cid = header.session_cid.get();
    log::trace!(target: "citadel", "[GROUP:{}] message: {:?}", session.is_server.if_true("server").if_false("client"), signal);
    match signal {
        GroupBroadcast::Create {
            initial_invitees: initial_peers,
            options,
        } => {
            let key = session
                .session_manager
                .create_message_group_and_notify(
                    timestamp,
                    ticket,
                    session_cid,
                    initial_peers,
                    security_level,
                    options,
                )
                .await;
            let signal = GroupBroadcast::CreateResponse { key };
            let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &signal,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
        }

        GroupBroadcast::RequestJoinPending { result, key } => forward_signal(
            session,
            ticket,
            None,
            GroupBroadcast::RequestJoinPending { result, key },
        ),

        GroupBroadcast::RequestJoin { sender, key } => {
            if session.is_server {
                // if the group is auto-accept enabled, rebound a GroupBroadcast::AcceptMembershipResponse
                let peer_layer = &session.hypernode_peer_layer;
                let result = if peer_layer.message_group_exists(key).await {
                    peer_layer
                        .add_pending_peers_to_group(key, vec![session_cid])
                        .await;
                    peer_layer.request_join(session_cid, key).await
                } else {
                    None
                };

                match result {
                    None => {
                        // group does not exist. Send error packet
                        log::warn!(target: "citadel", "Group {key:?} does not exist");
                        let error = GroupBroadcast::GroupNonExists { key };
                        let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                            sess_ratchet,
                            &error,
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        );
                        Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
                    }

                    Some(true) => {
                        // user has been automatically added to the group via auto-accept.
                        let success =
                            GroupBroadcast::AcceptMembershipResponse { key, success: true };
                        let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                            sess_ratchet,
                            &success,
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        );
                        Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
                    }

                    Some(false) => {
                        // auto-accept is not enabled. Relay signal to owner
                        let res = session.session_manager.route_packet_to(key.cid, |peer_hr| {
                            packet_crafter::peer_cmd::craft_group_message_packet(
                                peer_hr,
                                &GroupBroadcast::RequestJoin { sender, key },
                                ticket,
                                C2S_IDENTITY_CID,
                                timestamp,
                                security_level,
                            )
                        });

                        let signal = GroupBroadcast::RequestJoinPending { result: res, key };
                        let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                            sess_ratchet,
                            &signal,
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        );
                        Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
                    }
                }
            } else {
                forward_signal(
                    session,
                    ticket,
                    Some(key),
                    GroupBroadcast::RequestJoin { sender, key },
                )
            }
        }

        GroupBroadcast::ListGroupsFor { cid: owner } => {
            let message_groups = session
                .hypernode_peer_layer
                .list_message_groups_for(owner)
                .await
                .unwrap_or_default();
            let signal = GroupBroadcast::ListResponse {
                groups: message_groups,
            };
            let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &signal,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
        }

        GroupBroadcast::ListResponse {
            groups: message_groups,
        } => forward_signal(
            session,
            ticket,
            None,
            GroupBroadcast::ListResponse {
                groups: message_groups,
            },
        ),

        GroupBroadcast::MemberStateChanged { key, state } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::MemberStateChanged { key, state },
        ),

        GroupBroadcast::End { key } => {
            return_if_none!(permission_gate(session_cid, key), "Permission denied");
            let success = session
                .session_manager
                .remove_message_group(session_cid, timestamp, ticket, key, security_level)
                .await;
            let signal = GroupBroadcast::EndResponse { key, success };
            let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &signal,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
        }

        GroupBroadcast::EndResponse { key, success } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::EndResponse { key, success },
        )
        .inspect(|_res| {
            let _ = inner_mut_state!(session.state_container)
                .group_channels
                .remove(&key);
        }),

        GroupBroadcast::Disconnected { key } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::Disconnected { key },
        )
        .inspect(|_res| {
            let _ = inner_mut_state!(session.state_container)
                .group_channels
                .remove(&key);
        }),

        GroupBroadcast::Message {
            sender: username,
            key,
            message,
        } => {
            if session.is_server {
                log::trace!(target: "citadel", "[Group/Server] Received message {message:?}");
                // The message will need to be broadcasted to every member in the group
                let success = session
                    .session_manager
                    .broadcast_signal_to_group(
                        session_cid,
                        timestamp,
                        ticket,
                        key,
                        GroupBroadcast::Message {
                            sender: username,
                            key,
                            message,
                        },
                        security_level,
                    )
                    .await
                    .unwrap_or(false);
                let resp = GroupBroadcast::MessageResponse { key, success };
                let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                    sess_ratchet,
                    &resp,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                );
                Ok(PrimaryProcessorResult::ReplyToSender(packet))
            } else {
                // Client: decrypt the E2E CGKA ciphertext to plaintext before handing it to the app. In
                // a CommandHierarchy group a non-permitted reader (a sibling/subordinate of the sender)
                // legitimately cannot decrypt — drop the message for them rather than erroring.
                let plaintext = {
                    let state = inner_state!(session.state_container);
                    match state.group_cgka.get(&key) {
                        Some(cgka) => match cgka.decrypt_message(message.as_ref()) {
                            Ok(plaintext) => plaintext,
                            Err(err) => {
                                log::trace!(target: "citadel", "Dropping group message for {key:?}: not a permitted reader ({err})");
                                return Ok(PrimaryProcessorResult::Void);
                            }
                        },
                        None => {
                            log::warn!(target: "citadel", "Dropping group message for {key:?}: no CGKA state");
                            return Ok(PrimaryProcessorResult::Void);
                        }
                    }
                };
                forward_signal(
                    session,
                    ticket,
                    Some(key),
                    GroupBroadcast::Message {
                        sender: username,
                        key,
                        message: SecBuffer::from(plaintext),
                    },
                )
            }
        }

        GroupBroadcast::MessageResponse { key, success } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::MessageResponse { key, success },
        ),

        GroupBroadcast::AcceptMembership { target, key } => {
            let success = session
                .hypernode_peer_layer
                .upgrade_peer_in_group(key, target)
                .await;
            if !success {
                log::warn!(target: "citadel", "Unable to upgrade peer {target} for {key:?}");
            } else {
                // send broadcast to all group members
                let entered = vec![target];
                if !session
                    .session_manager
                    .broadcast_signal_to_group(
                        session_cid,
                        timestamp,
                        ticket,
                        key,
                        GroupBroadcast::MemberStateChanged {
                            key,
                            state: MemberState::EnteredGroup { cids: entered },
                        },
                        security_level,
                    )
                    .await
                    .unwrap_or(false)
                {
                    log::warn!(target: "citadel", "Unable to broadcast member acceptance to group {key}");
                }
                log::trace!(target: "citadel", "Successfully upgraded {target} for {key:?}");
            }

            // tell the user who accepted the membership
            let signal = GroupBroadcast::AcceptMembershipResponse { key, success };
            let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &signal,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(packet))
        }

        GroupBroadcast::DeclineMembership { target, key } => {
            if session.is_server {
                let mut success = session
                    .hypernode_peer_layer
                    .remove_pending_peer_from_group(key, target)
                    .await;

                success = session
                    .session_manager
                    .route_packet_to(target, |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::DeclineMembership { target, key },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    })
                    .is_ok()
                    && success;

                // tell the user who declined the membership
                let signal = GroupBroadcast::DeclineMembershipResponse { key, success };
                let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                    sess_ratchet,
                    &signal,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                );

                Ok(PrimaryProcessorResult::ReplyToSender(packet))
            } else {
                // send to kernel/channel
                forward_signal(
                    session,
                    ticket,
                    Some(key),
                    GroupBroadcast::DeclineMembership { target, key },
                )
            }
        }

        GroupBroadcast::AcceptMembershipResponse { key, success } => {
            if success && (key.cid != session_cid) {
                // Zero-trust join: instead of immediately opening a channel, the joiner publishes its
                // TreeKEM KeyPackage to the owner and defers the channel until its Welcome arrives.
                cgka_joiner_publish_key_package(
                    session,
                    sess_ratchet,
                    key,
                    session_cid,
                    ticket,
                    timestamp,
                    security_level,
                )
            } else {
                forward_signal(
                    session,
                    ticket,
                    Some(key),
                    GroupBroadcast::AcceptMembershipResponse { key, success },
                )
            }
        }

        GroupBroadcast::DeclineMembershipResponse { key, success } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::DeclineMembershipResponse { key, success },
        ),

        GroupBroadcast::LeaveRoom { key } => {
            // TODO: If the user leaving the room is the message group owner, then leave
            let success = session
                .session_manager
                .kick_from_message_group(
                    GroupMemberAlterMode::Leave,
                    session_cid,
                    timestamp,
                    ticket,
                    key,
                    vec![session_cid],
                    security_level,
                )
                .await
                .ok()
                .unwrap_or(false);
            let message = if success {
                format!(
                    "Successfully removed peer {} from room {}:{}",
                    session_cid, key.cid, key.mgid
                )
            } else {
                format!(
                    "Unable to remove peer {} from room {}:{}",
                    session_cid, key.cid, key.mgid
                )
            };
            let signal = GroupBroadcast::LeaveRoomResponse {
                key,
                success,
                message,
            };
            let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &signal,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(packet))
        }

        GroupBroadcast::LeaveRoomResponse {
            key,
            success,
            message: response,
        } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::LeaveRoomResponse {
                key,
                success,
                message: response,
            },
        )
        .inspect(|_res| {
            let _ = inner_mut_state!(session.state_container)
                .group_channels
                .remove(&key);
        }),

        GroupBroadcast::Add {
            key,
            invitees: peers,
        } => {
            return_if_none!(permission_gate(session_cid, key), "Permission denied");
            // the server receives this. It then sends an invitation
            // if peer is not online, leave some mail. If peer is online,
            // send invitation
            let persistence_handler = session.account_manager.get_persistence_handler().clone();
            let sess_mgr = session.session_manager.clone();
            let peer_layer = &session.hypernode_peer_layer;
            let peer_statuses = persistence_handler
                .hyperlan_peers_are_mutuals(session_cid, &peers)
                .await?;

            if peer_layer.message_group_exists(key).await {
                let (peers_okay, peers_failed) = sess_mgr
                    .send_group_broadcast_signal_to(
                        timestamp,
                        ticket,
                        peers.iter().cloned().zip(peer_statuses.clone()),
                        true,
                        GroupBroadcast::Invitation {
                            sender: session_cid,
                            key,
                        },
                        security_level,
                    )
                    .await
                    .map_err(NetworkError::generic)?;

                if !peers_okay.is_empty() {
                    peer_layer.add_pending_peers_to_group(key, peers_okay).await;
                    std::mem::drop(sess_mgr);
                }

                let peers_failed = peers_failed
                    .is_empty()
                    .if_eq(true, None)
                    .if_false_then(|| Some(peers_failed));

                let signal = GroupBroadcast::AddResponse {
                    key,
                    failed_to_invite_list: peers_failed,
                };
                let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                    sess_ratchet,
                    &signal,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                );
                Ok(PrimaryProcessorResult::ReplyToSender(packet))
            } else {
                // Send error message
                let signal = GroupBroadcast::GroupNonExists { key };
                let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                    sess_ratchet,
                    &signal,
                    ticket,
                    C2S_IDENTITY_CID,
                    timestamp,
                    security_level,
                );
                Ok(PrimaryProcessorResult::ReplyToSender(packet))
            }
        }

        GroupBroadcast::AddResponse {
            key,
            failed_to_invite_list: failed_peers,
        } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::AddResponse {
                key,
                failed_to_invite_list: failed_peers,
            },
        ),

        GroupBroadcast::Kick {
            key,
            kick_list: peers,
        } => {
            return_if_none!(permission_gate(session_cid, key), "Permission denied");
            let success = session
                .session_manager
                .kick_from_message_group(
                    GroupMemberAlterMode::Kick,
                    session_cid,
                    timestamp,
                    ticket,
                    key,
                    peers,
                    security_level,
                )
                .await
                .ok()
                .unwrap_or(false);
            let resp = GroupBroadcast::KickResponse { key, success };
            let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &resp,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(packet))
        }

        GroupBroadcast::KickResponse { key, success } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::KickResponse { key, success },
        ),

        GroupBroadcast::Invitation { sender, key } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::Invitation { sender, key },
        ),

        GroupBroadcast::CreateResponse { key: key_opt } => match key_opt {
            // The owner already founded its CGKA group when it sent `Create` (the key is locally
            // derivable), so here it just opens the channel.
            Some(key) => create_group_channel(ticket, key, session),

            None => forward_signal(
                session,
                ticket,
                None,
                GroupBroadcast::CreateResponse { key: None },
            ),
        },

        GroupBroadcast::GroupNonExists { key } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::GroupNonExists { key },
        ),

        GroupBroadcast::KeyPackage {
            key,
            joiner_cid,
            payload,
        } => {
            if session.is_server {
                // Relay verbatim to the owner; the relay never inspects `payload` (zero-trust).
                let _ = session
                    .session_manager
                    .route_packet_to(key.cid, move |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::KeyPackage {
                                key,
                                joiner_cid,
                                payload,
                            },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    });
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Owner: add the joiner to the ratchet tree and emit its Welcome + the members' Commit.
                cgka_owner_add_member(
                    session,
                    sess_ratchet,
                    key,
                    joiner_cid,
                    &payload,
                    ticket,
                    timestamp,
                    security_level,
                )
            }
        }

        GroupBroadcast::Welcome {
            key,
            joiner_cid,
            payload,
        } => {
            if session.is_server {
                // Relay verbatim to the single joiner; the relay never inspects `payload`.
                let _ = session
                    .session_manager
                    .route_packet_to(joiner_cid, move |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::Welcome {
                                key,
                                joiner_cid,
                                payload,
                            },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    });
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Joiner: bootstrap the group state from the Welcome, then open the group channel.
                {
                    let mut state = inner_mut_state!(session.state_container);
                    let cgka = state
                        .group_cgka
                        .get_mut(&key)
                        .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
                    cgka.join(&payload)?;
                }
                create_group_channel(ticket, key, session)
            }
        }

        GroupBroadcast::Commit {
            key,
            epoch,
            payload,
        } => {
            if session.is_server {
                // Relay verbatim to the existing members (the fanout excludes the owner/sender). The
                // brand-new joiner may also receive it; its Welcome already covers this epoch, so its
                // coordinator gates the commit out.
                let _ = session
                    .session_manager
                    .broadcast_signal_to_group(
                        session_cid,
                        timestamp,
                        ticket,
                        key,
                        GroupBroadcast::Commit {
                            key,
                            epoch,
                            payload,
                        },
                        security_level,
                    )
                    .await
                    .unwrap_or(false);
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Member: apply the commit (epoch-gated) to advance the ratchet tree.
                let mut state = inner_mut_state!(session.state_container);
                if let Some(cgka) = state.group_cgka.get_mut(&key) {
                    cgka.process_commit(&payload, epoch)?;
                }
                Ok(PrimaryProcessorResult::Void)
            }
        }

        GroupBroadcast::HierarchyAssign {
            key,
            target_cid,
            payload,
        } => {
            if session.is_server {
                // Relay verbatim to the assigned member; the relay sees neither path nor node secret.
                let _ = session
                    .session_manager
                    .route_packet_to(target_cid, move |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::HierarchyAssign {
                                key,
                                target_cid,
                                payload,
                            },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    });
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Member: take up the assigned hierarchy position (path + node secret).
                let mut state = inner_mut_state!(session.state_container);
                if let Some(cgka) = state.group_cgka.get_mut(&key) {
                    cgka.apply_hierarchy_assignment(&payload)?;
                }
                Ok(PrimaryProcessorResult::Void)
            }
        }

        // Promote/Demote are owner-local admin requests handled entirely on the outbound path
        // (`process_outbound_broadcast_command`); they are never relayed, so receiving one is a no-op.
        GroupBroadcast::Promote { .. } | GroupBroadcast::Demote { .. } => {
            log::warn!(target: "citadel", "Received an owner-local hierarchy admin signal inbound; ignoring");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

/// Create a group channel
fn create_group_channel<R: Ratchet, T: PlatformOps>(
    ticket: Ticket,
    key: MessageGroupKey,
    session: &CitadelSession<R, T>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let channel = inner_mut_state!(session.state_container)
        .setup_group_channel_endpoints(key, ticket, session)?;
    let session_cid = session
        .session_cid
        .get()
        .ok_or_else(|| error!(ErrorCode::StateImplicatedCidNotLoaded))?;
    session.send_to_kernel(NodeResult::GroupChannelCreated(GroupChannelCreated {
        ticket,
        channel,
        session_cid,
    }))?;
    Ok(PrimaryProcessorResult::Void)
}

/// A joiner generates its TreeKEM `KeyPackage`, stores its pending CGKA state, and publishes the
/// KeyPackage to the owner (routed by the relay). The group channel is deferred until the Welcome.
#[allow(clippy::too_many_arguments)]
fn cgka_joiner_publish_key_package<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    key: MessageGroupKey,
    joiner_cid: u64,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let kp_bytes = {
        let mut state = inner_mut_state!(session.state_container);
        if state.group_cgka.contains_key(&key) {
            // Already joining/among this group; nothing to publish.
            return Ok(PrimaryProcessorResult::Void);
        }
        let (cgka, kp_bytes) = GroupCgkaState::new_joiner(joiner_cid, GroupHierarchyMode::Flat)?;
        let _ = state.group_cgka.insert(key, cgka);
        kp_bytes
    };

    let signal = GroupBroadcast::KeyPackage {
        key,
        joiner_cid,
        payload: kp_bytes,
    };
    let packet = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &signal,
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    );
    session.send_to_primary_stream(Some(ticket), packet)?;
    Ok(PrimaryProcessorResult::Void)
}

/// The owner incorporates a joiner's published `KeyPackage` into the ratchet tree, then sends the
/// resulting `Welcome` to the joiner and the `Commit` to the existing members (both via the relay).
#[allow(clippy::too_many_arguments)]
fn cgka_owner_add_member<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    key: MessageGroupKey,
    joiner_cid: u64,
    key_package_bytes: &[u8],
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (welcome_bytes, commit_bytes, epoch, assignment) = {
        let mut state = inner_mut_state!(session.state_container);
        let cgka = state
            .group_cgka
            .get_mut(&key)
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        cgka.add_member(key_package_bytes)?
    };

    // HierarchyAssign -> the joiner FIRST (before the Welcome), if this is a CommandHierarchy group and
    // the joiner has a rank. Both travel the same ordered C2S→joiner stream, so applying the assignment
    // (which switches the joiner into hierarchy mode) before the Welcome opens its channel removes the
    // window where the joiner would otherwise send/receive in the wrong (flat) mode.
    if let Some(sealed) = assignment {
        send_hierarchy_assign(
            session,
            sess_ratchet,
            key,
            joiner_cid,
            sealed,
            ticket,
            timestamp,
            security_level,
        )?;
    }

    // Welcome -> the joiner (the relay routes to `joiner_cid`).
    let welcome = GroupBroadcast::Welcome {
        key,
        joiner_cid,
        payload: welcome_bytes,
    };
    let welcome_packet = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &welcome,
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    );
    session.send_to_primary_stream(Some(ticket), welcome_packet)?;

    // Commit -> the existing members (the relay fans out, excluding the owner).
    let commit = GroupBroadcast::Commit {
        key,
        epoch,
        payload: commit_bytes,
    };
    let commit_packet = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &commit,
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    );
    session.send_to_primary_stream(Some(ticket), commit_packet)?;

    Ok(PrimaryProcessorResult::Void)
}

/// Send a sealed Decentralized-Hierarchy-Encryption assignment to a single member (relay routes it).
#[allow(clippy::too_many_arguments)]
fn send_hierarchy_assign<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    key: MessageGroupKey,
    target_cid: u64,
    sealed: Vec<u8>,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<(), NetworkError> {
    let signal = GroupBroadcast::HierarchyAssign {
        key,
        target_cid,
        payload: sealed,
    };
    let packet = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &signal,
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    );
    session.send_to_primary_stream(Some(ticket), packet)?;
    Ok(())
}

impl From<GroupBroadcast> for GroupBroadcastPayload {
    /// Convert GroupBroadcast to GroupBroadcastPayload
    fn from(broadcast: GroupBroadcast) -> Self {
        match broadcast {
            GroupBroadcast::Message {
                sender,
                key: _key,
                message: payload,
            } => GroupBroadcastPayload::Message { payload, sender },
            evt => GroupBroadcastPayload::Event { payload: evt },
        }
    }
}

/// Forward a signal to the kernel or a group channel
fn forward_signal<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ticket: Ticket,
    key: Option<MessageGroupKey>,
    broadcast: GroupBroadcast,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session_cid = return_if_none!(session.session_cid.get(), "Implicated CID not loaded");

    if let Some(key) = key {
        // send to the dedicated channel
        if let Some(tx) = inner_mut_state!(session.state_container)
            .group_channels
            .get(&key)
        {
            if let Err(err) = tx.unbounded_send(broadcast.into()) {
                log::error!(target: "citadel", "Unable to forward group broadcast signal. Reason: {err:?}");
            }

            return Ok(PrimaryProcessorResult::Void);
        }
    }

    // send to kernel
    session
        .send_to_kernel(NodeResult::GroupEvent(GroupEvent {
            session_cid,
            ticket,
            event: broadcast,
        }))
        .map_err(|err| error!(ErrorCode::PeerKernelTxDead, format!("{err:?}")))?;
    Ok(PrimaryProcessorResult::Void)
}

/// Permission gate for group operations
fn permission_gate(session_cid: u64, key: MessageGroupKey) -> Option<()> {
    if session_cid != key.cid {
        None
    } else {
        Some(())
    }
}
