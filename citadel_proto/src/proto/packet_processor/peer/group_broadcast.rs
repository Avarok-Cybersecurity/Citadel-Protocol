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
use super::{
    group_backup_relay, group_commit_ack, group_commit_relay, group_control, group_message_relay, group_ordered,
    group_restore, group_resume_relay, group_resumed, group_succession_relay,
};
use crate::error::NetworkError;
use crate::functional::*;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::{GroupChannelCreated, GroupEvent};
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_cgka::GroupCgkaState;
use crate::proto::peer::group_channel::GroupBroadcastPayload;
use crate::proto::peer::group_watch::GroupWatch;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecBuffer;
use citadel_types::proto::{
    GroupDelivery, GroupEndReason, GroupHierarchyMode, GroupLogLimits, GroupMemberAlterMode,
    GroupMessageId, GroupMessageRefusal, GroupOrderBroken, GroupOrderInfo, GroupPosition,
    GroupReplayRefusal, GroupStateSource, MemberState, MessageGroupKey, MessageGroupOptions,
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
    /// The group has ended for this member, and why.
    Disconnected {
        /// Group key
        key: MessageGroupKey,
        /// Why
        reason: GroupEndReason,
    },
    /// To the application, never on the wire: this device has the group back after its session
    /// was restored, from `source`. Sent once per group, once the server has replayed what it held
    /// (or, for `Rejoined` and `Refounded`, once the device has started over).
    Restored {
        /// Group key
        key: MessageGroupKey,
        /// Where the state came from
        source: GroupStateSource,
    },
    /// Message broadcast to a group
    Message {
        /// Sender CID
        sender: u64,
        /// Group key
        key: MessageGroupKey,
        /// The sender's id for it: a message sent again under the same id is given the same
        /// position and relayed once
        id: GroupMessageId,
        /// Message payload
        message: SecBuffer,
    },
    /// The server's account of a message broadcast, member by member
    MessageResponse {
        /// Group key
        key: MessageGroupKey,
        /// The id of the message answered
        id: GroupMessageId,
        /// Where the message stands in the group's order; `None` when it was not relayed
        position: Option<GroupPosition>,
        /// Which members received it, have it held for them, or will not receive it
        delivery: GroupDelivery,
    },
    /// Server → member: a broadcast at its position in the group's order (a message, a Commit,
    /// and, in a replay group, a membership or ownership change or replay turned on). To the
    /// application, a positioned event of a replay group.
    Ordered {
        /// Group key
        key: MessageGroupKey,
        /// Where it stands
        position: GroupPosition,
        /// The broadcast
        frame: Box<GroupBroadcast>,
    },
    /// Owner → server: keep this group's broadcasts in one ordered log from the next position
    /// on, within `limits` (see [`GroupLogLimits`]).
    EnableReplay {
        /// Group key
        key: MessageGroupKey,
        /// The limits asked for; the server holds them to its own
        limits: GroupLogLimits,
    },
    /// Positioned (inside [`Self::Ordered`]): the group keeps a log from this position on.
    ReplayEnabled {
        /// Group key
        key: MessageGroupKey,
        /// Where the log starts and the limits that apply
        order: GroupOrderInfo,
    },
    /// Server → owner: replay was not turned on.
    ReplayRefused {
        /// Group key
        key: MessageGroupKey,
        /// Why
        refusal: GroupReplayRefusal,
    },
    /// Member → server: send the positions `(after, until]` of a replay group's log.
    FetchRange {
        /// Group key
        key: MessageGroupKey,
        /// The last position the member holds
        after: u64,
        /// The last position wanted
        until: u64,
    },
    /// Server → member: the positions asked for, in order (each an [`Self::Ordered`]), at most
    /// a server's page of them; `head` is the log's last position when they were read.
    Range {
        /// Group key
        key: MessageGroupKey,
        /// The log's last position
        head: u64,
        /// The positioned broadcasts
        frames: Vec<GroupBroadcast>,
    },
    /// Server → member: positions it asked for, or is being replayed, are older than the log
    /// keeps; the log starts at `earliest`.
    Trimmed {
        /// Group key
        key: MessageGroupKey,
        /// The first position the log holds
        earliest: u64,
        /// The group's order
        order: GroupOrderInfo,
    },
    /// To the application, never on the wire: the replay group's channel delivers nothing past
    /// `last` until the member resumes the group.
    OrderBroken {
        /// Group key
        key: MessageGroupKey,
        /// The last position delivered
        last: u64,
        /// Why
        reason: GroupOrderBroken,
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
        /// The generation of the owner's tree, as the server records it (the server sets it)
        tree: u64,
        /// The group's owner, as the server records it (the server sets it)
        owner: u64,
        /// For a replay group, its order and the joiner's first position (the server sets it)
        order: Option<GroupOrderInfo>,
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
    /// Server → member, when the member's session is (re-)established while the server still lists
    /// it in `key`, or the owner founded the tree afresh. A member that kept its state for this
    /// `tree` answers [`Self::ResumeMembership`]; one that did not publishes a fresh
    /// [`Self::KeyPackage`], the owner re-adds it (replacing its stale leaf) and returns a Welcome.
    RestoreMembership {
        /// Group key
        key: MessageGroupKey,
        /// The generation of the owner's tree the group is on
        tree: u64,
        /// The group's owner, as the server records it
        owner: u64,
    },
    /// Member → server: this session holds the member's state for the group's current tree. The
    /// server replays what it held for the member, then sends the group to it live.
    ResumeMembership {
        /// Group key
        key: MessageGroupKey,
        /// The last position of the group's log this member holds; `None` when it holds none
        after: Option<u64>,
    },
    /// Owner → server: as [`Self::ResumeMembership`], for the owner, which kept its tree.
    ResumeOwnership {
        /// Group key
        key: MessageGroupKey,
        /// As in [`Self::ResumeMembership`]
        after: Option<u64>,
    },
    /// Server → member, after replaying what it held for the member: the group is live from here.
    Resumed {
        /// Group key
        key: MessageGroupKey,
        /// The group's owner, as the server records it
        owner: u64,
        /// The group's members, as the server records them. A member made the owner while it was
        /// away takes over from these: it removes every leaf of a cid not among them.
        members: Vec<u64>,
        /// For a replay group, its order, the head being what was replayed through
        order: Option<GroupOrderInfo>,
    },
    /// Member → server: keep this sealed state of the member's for the group, in place of the
    /// last (see `peer::group_backup`). The server cannot open it.
    KeepState {
        /// Group key
        key: MessageGroupKey,
        /// The state, sealed under the account's key
        sealed: Vec<u8>,
    },
    /// Member → server: the session holds no state for the group; send the one kept for it.
    FetchState {
        /// Group key
        key: MessageGroupKey,
    },
    /// Server → member: the state kept for it, if any, on the group's current tree.
    KeptState {
        /// Group key
        key: MessageGroupKey,
        /// The generation of the owner's tree the group is on
        tree: u64,
        /// The group's owner, as the server records it
        owner: u64,
        /// The sealed state, if the server keeps one for the member
        sealed: Option<Vec<u8>>,
    },
    /// Restoring a group whose owner's session ended and was re-established.
    ///
    /// Server → owner, at the owner's (re)connect: the group still exists here; if the owner kept
    /// no state for its tree, or kept it as a member before ownership passed to it, it re-founds. The owner re-founds the tree (fresh leaf secret, epoch 0) and
    /// opens a group channel, then echoes this signal back.
    ///
    /// Owner → server, once re-founded: the server sends [`Self::RestoreMembership`] to every member,
    /// who rejoin the new tree with fresh KeyPackages. Only the owner's echo is acted on.
    RestoreOwnership {
        /// Group key
        key: MessageGroupKey,
        /// Server → owner: the generation of the tree the group is on. Ignored in the echo.
        tree: u64,
    },
    /// Local notice (never sent on the wire) that a group message addressed to this session was
    /// dropped because it could not be decrypted here: it arrived before this session's Welcome,
    /// or, in a flat group, it was sealed at an epoch this session does not hold.
    /// Delivered to the group channel if one is open, otherwise to the kernel as a [`GroupEvent`].
    MessageDropped {
        /// Group key
        key: MessageGroupKey,
        /// The sender of the dropped message
        sender: u64,
        /// Why it could not be delivered
        reason: String,
    },
    /// Member → server: answer with [`Self::GroupAvailable`] once `key` exists — at once if it
    /// already does, otherwise when its owner creates it (see `group_watch`).
    AwaitGroup {
        /// Group key
        key: MessageGroupKey,
    },
    /// Server → member, on the `AwaitGroup` ticket: `key` exists.
    GroupAvailable {
        /// Group key
        key: MessageGroupKey,
    },
    /// Member → server: this member has processed the owner's Commit for `epoch`, so it seals
    /// nothing more at the epoch before it (see `group_commit_gate`).
    CommitApplied {
        /// Group key
        key: MessageGroupKey,
        /// The epoch of the Commit processed
        epoch: u64,
    },
    /// Server → owner: every member the server waited on has processed the Commit for `epoch`,
    /// so the owner may release the Welcome it held for that join.
    CommitSettled {
        /// Group key
        key: MessageGroupKey,
        /// The epoch of the settled Commit
        epoch: u64,
    },
    /// Server → sender: the server refused to relay the sender's message to `key`, which reached
    /// nobody, because it broke one of the group's limits.
    MessageRefused {
        /// Group key
        key: MessageGroupKey,
        /// The limit the message broke
        refusal: GroupMessageRefusal,
    },
    /// Server → every remaining member: the owner left, and `owner`, the remaining member with
    /// the highest cid, owns the group now. Mailed to a member that is offline. The group keeps
    /// its key. The new owner removes `previous` from the ratchet tree and commits from then on.
    OwnershipTransferred {
        /// Group key
        key: MessageGroupKey,
        /// The group's owner from now on
        owner: u64,
        /// The owner that left
        previous: u64,
        /// The generation of the group's tree, for a new owner that holds no state for it
        tree: u64,
    },
}

/// Why a session that has not received its Welcome drops a group message.
const NO_GROUP_KEY_YET: &str =
    "this session holds no key for the group yet (it has not received its Welcome)";

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
    turn: Option<crate::proto::group_lane::Turn>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let ticket = header.context_info.get().into();
    let security_level = header.security_level.into();
    let result = process_signal(session_ref, header, payload, sess_ratchet, turn).await;
    if !session_ref.is_server {
        // Whatever this packet changed in a group's state is kept before the next one, here
        // and, sealed, at the server.
        let backups = {
            let mut state = inner_mut_state!(session_ref.state_container);
            state.save_changed_group_states();
            state.take_group_backups()
        };
        let timestamp = session_ref.time_tracker.get_global_time_ns();
        for backup in backups {
            let packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &backup,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            )?;
            session_ref.send_to_primary_stream(Some(ticket), packet)?;
        }
    }
    result
}

async fn process_signal<R: Ratchet, T: PlatformOps>(
    session_ref: &CitadelSession<R, T>,
    header: Ref<&[u8], HdpHeader>,
    payload: &[u8],
    sess_ratchet: &R,
    turn: Option<crate::proto::group_lane::Turn>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;
    let signal = return_if_none!(
        GroupBroadcast::deserialize_from_vector(payload).ok(),
        "invalid GroupBroadcast packet"
    );
    let _turn = crate::proto::group_lane::in_order(turn).await;

    let timestamp = session.time_tracker.get_global_time_ns();
    let ticket = header.context_info.get().into();
    let security_level = header.security_level.into();
    // since group broadcast packets never get proxied, the implicated cid is the local session cid
    let session_cid = header.session_cid.get();
    let crafter = group_commit_ack::Crafter {
        ratchet: sess_ratchet,
        timestamp,
        security_level,
    };
    let reply = group_restore::Reply {
        sess_ratchet,
        ticket,
        timestamp,
        security_level,
    };
    log::trace!(target: "citadel", "[GROUP:{}] message: {:?}", session.is_server.if_true("server").if_false("client"), signal);
    let Some((signal, position)) = group_ordered::unwrap_ordered(session, session_cid, signal)
    else {
        return Ok(PrimaryProcessorResult::Void);
    };
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
            )?;
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
                        )?;
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
                        )?;
                        Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
                    }

                    Some(false) => {
                        // auto-accept is not enabled. Relay signal to owner
                        let owner = return_if_none!(
                            peer_layer.group_owner(key).await,
                            "group removed while a join was requested"
                        );
                        let res = session.session_manager.route_packet_to(owner, |peer_hr| {
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
                        )?;
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

        GroupBroadcast::AwaitGroup { key } => {
            if !session.is_server {
                log::warn!(target: "citadel", "Client received a server-only AwaitGroup for {key:?}");
                return Ok(PrimaryProcessorResult::Void);
            }
            let reply = match session
                .hypernode_peer_layer
                .watch_group(session_cid, ticket, key)
                .await
            {
                GroupWatch::Available => GroupBroadcast::GroupAvailable { key },
                GroupWatch::Pending => return Ok(PrimaryProcessorResult::Void),
                GroupWatch::Refused => {
                    log::warn!(target: "citadel", "Session {session_cid} holds too many group watches; refusing {key:?}");
                    GroupBroadcast::GroupNonExists { key }
                }
            };
            let return_packet = packet_crafter::peer_cmd::craft_group_message_packet(
                sess_ratchet,
                &reply,
                ticket,
                C2S_IDENTITY_CID,
                timestamp,
                security_level,
            )?;
            Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
        }

        GroupBroadcast::GroupAvailable { key } => forward_signal(
            session,
            ticket,
            None,
            GroupBroadcast::GroupAvailable { key },
        ),

        GroupBroadcast::ListGroupsFor { cid: owner } => {
            let message_groups = session
                .hypernode_peer_layer
                .list_message_groups_for(owner)
                .await;
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
            )?;
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
            let success = group_control::permits_control(session, session_cid, key).await
                && session
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
            )?;
            Ok(PrimaryProcessorResult::ReplyToSender(return_packet))
        }

        GroupBroadcast::EndResponse { key, success } => {
            // The channel reads no owner by the time its application hears the group ended.
            if success {
                inner_mut_state!(session.state_container).record_group_owner(key, None);
            }
            forward_signal(
                session,
                ticket,
                Some(key),
                GroupBroadcast::EndResponse { key, success },
            )
            .inspect(|_res| {
                if success {
                    let _ = inner_mut_state!(session.state_container)
                        .group_channels
                        .remove(&key);
                }
            })
        }

        GroupBroadcast::Disconnected { key, reason } => {
            inner_mut_state!(session.state_container).record_group_owner(key, None);
            forward_signal(
                session,
                ticket,
                Some(key),
                GroupBroadcast::Disconnected { key, reason },
            )
            .inspect(|_res| {
                let mut state = inner_mut_state!(session.state_container);
                let _ = state.group_channels.remove(&key);
                // The group is gone for this member: its keys are of no further use.
                let _ = state.group_cgka.remove(&key);
                state.forget_group_state(key);
            })
        }

        GroupBroadcast::Message {
            sender: username,
            key,
            id,
            message,
        } => {
            if session.is_server {
                log::trace!(target: "citadel", "[Group/Server] Received message {message:?}");
                let inbound = group_message_relay::InboundGroupMessage {
                    session_cid,
                    key,
                    id,
                    message,
                    ticket,
                    timestamp,
                    security_level,
                };
                group_message_relay::relay(session, sess_ratchet, inbound).await
            } else {
                // Client: decrypt the E2E CGKA ciphertext to plaintext before handing it to the app. In
                // a CommandHierarchy group a non-permitted reader (a sibling/subordinate of the sender)
                // legitimately cannot decrypt — drop the message for them rather than erroring.
                // A member opens a message only under the leaf of the member the server says sent
                // it, and only once (the leaf's signature and the replay window are checked by
                // `decrypt_message`).
                let plaintext = {
                    let mut state = inner_mut_state!(session.state_container);
                    match state.group_cgka.get_mut(&key) {
                        Some(cgka) if cgka.is_pending_join() => Err(NO_GROUP_KEY_YET.to_string()),
                        Some(cgka) => match cgka.decrypt_message(message.as_ref()) {
                            Ok((signer, plaintext)) if signer == username => Ok(plaintext),
                            Ok((signer, _)) => Err(format!(
                                "it is signed by {signer}, not by its sender {username}"
                            )),
                            // A flat group withholds nothing from a member: a message it cannot
                            // open (sealed at an epoch it does not hold) is lost to it.
                            Err(err) if cgka.is_flat() => {
                                Err(format!("this session cannot decrypt it: {err}"))
                            }
                            Err(err) => {
                                log::trace!(target: "citadel", "Dropping group message for {key:?}: not a permitted reader ({err})");
                                return Ok(PrimaryProcessorResult::Void);
                            }
                        },
                        None => Err(NO_GROUP_KEY_YET.to_string()),
                    }
                };
                // A server positions every message it relays; one without a position was not
                // relayed by a server of this release.
                let plaintext = match position {
                    Some(_) => plaintext,
                    None => Err("it carries no position in the group's order".to_string()),
                };
                // This session cannot read the message, and a silent drop here is invisible at both
                // ends. Tell the application.
                let plaintext = match plaintext {
                    Ok(plaintext) => plaintext,
                    Err(reason) => {
                        log::warn!(target: "citadel", "Dropping group message for {key:?} from {username}: {reason}");
                        return forward_signal(
                            session,
                            ticket,
                            Some(key),
                            GroupBroadcast::MessageDropped {
                                key,
                                sender: username,
                                reason,
                            },
                        );
                    }
                };
                let Some(position) = position else {
                    return Ok(PrimaryProcessorResult::Void);
                };
                let opened = GroupBroadcast::Message {
                    sender: username,
                    key,
                    id,
                    message: SecBuffer::from(plaintext),
                };
                forward_signal(
                    session,
                    ticket,
                    Some(key),
                    group_ordered::opened(key, position, opened),
                )
            }
        }

        GroupBroadcast::MessageResponse {
            key,
            id,
            position,
            delivery,
        } => forward_signal(
            session,
            ticket,
            Some(key),
            GroupBroadcast::MessageResponse {
                key,
                id,
                position,
                delivery,
            },
        ),

        GroupBroadcast::Ordered { key, .. } => {
            log::warn!(target: "citadel", "Ignoring a broadcast for {key:?} positioned twice");
            Ok(PrimaryProcessorResult::Void)
        }

        GroupBroadcast::EnableReplay { key, .. } | GroupBroadcast::FetchRange { key, .. } => {
            group_ordered::refuse_replay(session, reply, key)
        }

        answer @ (GroupBroadcast::ReplayEnabled { .. }
        | GroupBroadcast::ReplayRefused { .. }
        | GroupBroadcast::Range { .. }
        | GroupBroadcast::Trimmed { .. }
        | GroupBroadcast::OrderBroken { .. }) => {
            group_ordered::replay_answer(session, ticket, answer)
        }

        GroupBroadcast::MessageRefused { key, refusal } => {
            if session.is_server {
                log::warn!(target: "citadel", "Ignoring a MessageRefused for {key:?}: only a server sends one");
                return Ok(PrimaryProcessorResult::Void);
            }
            forward_signal(
                session,
                ticket,
                Some(key),
                GroupBroadcast::MessageRefused { key, refusal },
            )
        }

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
                // The owner accepted someone else's join request: the answer below reaches only
                // the owner, and the joiner publishes its KeyPackage on this answer, as an
                // invitee does on its own. Without it the joiner is a member the server relays to
                // that never receives its Welcome.
                if target != session_cid {
                    let relayed = session.session_manager.route_packet_to(target, |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::AcceptMembershipResponse { key, success },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    });
                    if let Err(err) = relayed {
                        log::error!(target: "citadel", "Failed to tell joiner {target} it was accepted into {key:?}: {err:?}. It will not receive its Welcome.");
                    }
                }
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
            )?;
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
                )?;

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
            // The answer to this session's own acceptance, unless it is already in the group (an
            // owner accepting someone else's request to join is answered the same way).
            let in_group = inner_state!(session.state_container)
                .group_cgka
                .get(&key)
                .is_some_and(|cgka| !cgka.is_pending_join());
            if success && !in_group {
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
                    JoinMode::KeepMembership,
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
            // The owner leaving passes the group on; the last member leaving closes it.
            let success = group_succession_relay::leave(
                session,
                session_cid,
                key,
                ticket,
                timestamp,
                security_level,
            )
            .await;
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
            )?;
            Ok(PrimaryProcessorResult::ReplyToSender(packet))
        }

        GroupBroadcast::LeaveRoomResponse {
            key,
            success,
            message: response,
        } => {
            // The channel reads no owner by the time its application hears it has left.
            if success {
                inner_mut_state!(session.state_container).record_group_owner(key, None);
            }
            forward_signal(
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
            })
        }

        GroupBroadcast::Add {
            key,
            invitees: peers,
        } => {
            if !group_control::permits_control(session, session_cid, key).await {
                let signal = GroupBroadcast::AddResponse {
                    key,
                    failed_to_invite_list: Some(peers),
                };
                return reply.send(signal);
            }
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
                )?;
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
                )?;
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
            kick_list: mut peers,
        } => {
            // An owner leaves its group with `LeaveRoom`, which passes it on.
            peers.retain(|peer| *peer != session_cid);
            let success = group_control::permits_control(session, session_cid, key).await
                && session
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
            )?;
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
            Some(key) => create_group_channel(ticket, key, session, session_cid),

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
                // Relay verbatim to the group's recorded owner; the relay never inspects
                // `payload` (zero-trust).
                //
                // A failed relay here is the whole of the join: the owner never sees the
                // KeyPackage, never sends a Welcome, and the joiner waits until it republishes.
                let Some(owner) = session.hypernode_peer_layer.group_owner(key).await else {
                    log::warn!(target: "citadel", "Not relaying a KeyPackage for {key:?}: no such group");
                    return Ok(PrimaryProcessorResult::Void);
                };
                let relayed = session
                    .session_manager
                    .route_packet_to(owner, move |peer_hr| {
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
                if let Err(err) = relayed {
                    log::error!(target: "citadel", "Failed to relay KeyPackage for {key:?} from joiner {joiner_cid} to owner {owner}: {err:?}. The join will not complete until the joiner republishes.");
                }
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Owner: add the joiner to the ratchet tree and emit the members' Commit and its Welcome.
                group_commit_ack::owner_add_member(
                    session, &crafter, key, joiner_cid, &payload, ticket,
                )
            }
        }

        GroupBroadcast::Welcome {
            key,
            joiner_cid,
            tree: _claimed,
            owner: claimed_owner,
            order: _,
            payload,
        } => {
            if session.is_server {
                // The tree generation and the owner are the server's record, never the sender's
                // claim; the joiner keeps them with its state, and the Welcome and the joiner's
                // going live are one step for every fan-out (`group_resume`).
                let recorded = session.hypernode_peer_layer.group_tree_and_owner(key).await;
                let Some((tree, owner)) = recorded else {
                    log::warn!(target: "citadel", "Not relaying a Welcome for {key:?}: no such group");
                    return Ok(PrimaryProcessorResult::Void);
                };
                if !group_control::relays_control_from(session_cid, Some(owner)) {
                    log::warn!(target: "citadel", "Not relaying a Welcome for {key:?} from {session_cid}: only the group's owner welcomes");
                    return Ok(PrimaryProcessorResult::Void);
                }
                let _ordered = session
                    .hypernode_peer_layer
                    .group_order
                    .clone()
                    .lock_owned()
                    .await;
                // Relay verbatim to the single joiner; the relay never inspects `payload`.
                //
                // A dropped Welcome is as terminal as a dropped KeyPackage: the
                // owner has already added the joiner to its tree, so the group
                // moves on with a member that can never decrypt anything.
                let relayed = session
                    .session_manager
                    .route_packet_to(joiner_cid, move |peer_hr| {
                        packet_crafter::peer_cmd::craft_group_message_packet(
                            peer_hr,
                            &GroupBroadcast::Welcome {
                                key,
                                joiner_cid,
                                tree,
                                owner,
                                order: None,
                                payload,
                            },
                            ticket,
                            C2S_IDENTITY_CID,
                            timestamp,
                            security_level,
                        )
                    });
                match relayed {
                    Err(err) => {
                        log::error!(target: "citadel", "Failed to relay Welcome for {key:?} to joiner {joiner_cid}: {err:?}. That member is in the owner's tree but cannot decrypt until it republishes.");
                    }
                    Ok(()) => group_resume_relay::welcomed(session, joiner_cid, key).await,
                }
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Joiner: bootstrap the group state from the Welcome, then open the group channel.
                let channel_open = {
                    let mut state = inner_mut_state!(session.state_container);
                    // A Welcome for a KeyPackage an earlier session of this cid published: the
                    // state it would open died with that session. This session republishes when
                    // the server prompts it (`RestoreMembership`), so the Welcome is stale, and
                    // failing the session over it only starts the restore again.
                    let Some(cgka) = state.group_cgka.get_mut(&key) else {
                        log::warn!(target: "citadel", "Ignoring a Welcome for {key:?}: this session published no KeyPackage for it");
                        return Ok(PrimaryProcessorResult::Void);
                    };
                    // A Welcome sealed to a leaf this member has since replaced (two restore prompts
                    // crossed, each publishing a KeyPackage) cannot be opened; the Welcome for the
                    // current leaf follows it. That is not a reason to fail the session.
                    if let Err(err) = cgka.join(&payload) {
                        log::warn!(target: "citadel", "Ignoring a Welcome for {key:?} this member cannot open (superseded by a newer KeyPackage): {err}");
                        return Ok(PrimaryProcessorResult::Void);
                    }
                    cgka.tree = _claimed;
                    state.record_group_owner(key, Some(claimed_owner));
                    state.has_open_group_channel(key)
                };
                // A member rejoining a re-founded group keeps the channel its application already has.
                if channel_open {
                    Ok(PrimaryProcessorResult::Void)
                } else {
                    create_group_channel(ticket, key, session, claimed_owner)
                }
            }
        }

        GroupBroadcast::Commit {
            key,
            epoch,
            payload,
        } => {
            if session.is_server {
                let owner = session.hypernode_peer_layer.group_owner(key).await;
                if !group_control::relays_control_from(session_cid, owner) {
                    log::warn!(target: "citadel", "Not relaying a Commit for {key:?} from {session_cid}: only the group's owner commits");
                    return Ok(PrimaryProcessorResult::Void);
                }
                // Relay verbatim to the existing members (the fanout excludes the owner/sender). The
                // joiner receives it too and, still awaiting its Welcome, ignores it.
                group_commit_relay::relay_commit(
                    session,
                    session_cid,
                    key,
                    epoch,
                    payload,
                    ticket,
                    timestamp,
                    security_level,
                )
                .await
            } else {
                #[cfg(feature = "localhost-testing")]
                crate::test_hooks::inbound_commit(session_cid).await;
                // Member: apply the commit (epoch-gated) to advance the ratchet tree, then
                // acknowledge it under the same lock.
                let mut state = inner_mut_state!(session.state_container);
                // A Commit this member cannot apply is acknowledged like one it ignores (an epoch
                // it is not at): it will never apply it, and the owner's joins must not wait on it.
                group_control::apply_commit(state.group_cgka.get_mut(&key), key, &payload, epoch);
                group_commit_ack::acknowledge_commit(
                    &state, session, &crafter, key, epoch, ticket,
                )?;
                #[cfg(feature = "localhost-testing")]
                crate::test_hooks::commit_applied(session_cid);
                Ok(PrimaryProcessorResult::Void)
            }
        }

        GroupBroadcast::HierarchyAssign {
            key,
            target_cid,
            payload,
        } => {
            if session.is_server {
                let owner = session.hypernode_peer_layer.group_owner(key).await;
                if !group_control::relays_control_from(session_cid, owner) {
                    log::warn!(target: "citadel", "Not relaying a hierarchy assignment for {key:?} from {session_cid}: only the group's owner assigns");
                    return Ok(PrimaryProcessorResult::Void);
                }
                // Relay verbatim to the assigned member; the relay sees neither path nor node secret.
                //
                // A dropped assignment is silent by construction: the member
                // simply never gains its command path, and nothing distinguishes
                // that from a member who was never assigned one.
                let relayed = session
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
                if let Err(err) = relayed {
                    log::error!(target: "citadel", "Failed to relay HierarchyAssign for {key:?} to member {target_cid}: {err:?}. That member will have no command path.");
                }
                Ok(PrimaryProcessorResult::Void)
            } else {
                // Member: take up the assigned hierarchy position (path + node secret).
                let mut state = inner_mut_state!(session.state_container);
                group_control::apply_hierarchy_assignment(
                    state.group_cgka.get_mut(&key),
                    key,
                    &payload,
                );
                Ok(PrimaryProcessorResult::Void)
            }
        }

        GroupBroadcast::RestoreMembership { key, tree, owner } => {
            if session.is_server || owner == session_cid {
                log::warn!(target: "citadel", "Ignoring RestoreMembership for {key:?}: only a non-owner member acts on it");
                return Ok(PrimaryProcessorResult::Void);
            }
            inner_mut_state!(session.state_container).record_group_owner(key, Some(owner));
            group_restore::restore(session, reply, key, tree, owner).await
        }

        GroupBroadcast::ResumeMembership { key, .. } | GroupBroadcast::ResumeOwnership { key, .. } => {
            if !session.is_server {
                log::warn!(target: "citadel", "Ignoring a resume for {key:?}: only a server acts on it");
                return Ok(PrimaryProcessorResult::Void);
            }
            group_resume_relay::resume(
                session,
                sess_ratchet,
                session_cid,
                key,
                ticket,
                security_level,
            )
            .await?;
            Ok(PrimaryProcessorResult::Void)
        }

        GroupBroadcast::RestoreOwnership { key, tree } => {
            if session.is_server {
                if session.hypernode_peer_layer.group_owner(key).await != Some(session_cid) {
                    log::warn!(target: "citadel", "Ignoring RestoreOwnership for {key:?}: {session_cid} is not its owner");
                    return Ok(PrimaryProcessorResult::Void);
                }
                // The owner has re-founded the tree: bring the members back into it.
                group_resume_relay::refounded(session, key, ticket, timestamp, security_level)
                    .await;
                Ok(PrimaryProcessorResult::Void)
            } else {
                group_restore::restore(session, reply, key, tree, session_cid).await
            }
        }

        GroupBroadcast::Resumed {
            key,
            owner,
            members,
            order: _,
        } => {
            if session.is_server {
                return Ok(PrimaryProcessorResult::Void);
            }
            group_resumed::resumed(session, reply, key, owner, &members)
        }

        GroupBroadcast::Restored { key, .. } => {
            log::warn!(target: "citadel", "Ignoring a Restored for {key:?}: it is only ever told to the application");
            Ok(PrimaryProcessorResult::Void)
        }

        GroupBroadcast::KeepState { key, sealed } => {
            if session.is_server {
                group_backup_relay::keep(session, session_cid, key, sealed).await?;
            }
            Ok(PrimaryProcessorResult::Void)
        }

        GroupBroadcast::FetchState { key } => {
            if !session.is_server {
                return Ok(PrimaryProcessorResult::Void);
            }
            match group_backup_relay::fetch(session, session_cid, key).await? {
                Some(kept) => reply.send(kept),
                None => Ok(PrimaryProcessorResult::Void),
            }
        }

        GroupBroadcast::KeptState {
            key,
            tree,
            owner,
            sealed,
        } => {
            if session.is_server {
                return Ok(PrimaryProcessorResult::Void);
            }
            group_restore::kept(session, reply, key, tree, owner, sealed)
        }

        GroupBroadcast::CommitApplied { key, epoch } => {
            if !session.is_server {
                log::warn!(target: "citadel", "Ignoring a CommitApplied for {key:?}: only a server acts on it");
                return Ok(PrimaryProcessorResult::Void);
            }
            group_commit_relay::member_applied_commit(
                session,
                session_cid,
                key,
                epoch,
                ticket,
                timestamp,
                security_level,
            )
            .await
        }

        GroupBroadcast::CommitSettled { key, epoch } => {
            if session.is_server {
                log::warn!(target: "citadel", "Ignoring a CommitSettled for {key:?}: only its owner acts on it");
                return Ok(PrimaryProcessorResult::Void);
            }
            group_commit_ack::owner_commit_settled(session, &crafter, key, epoch, ticket)
        }

        GroupBroadcast::OwnershipTransferred {
            key,
            owner,
            previous,
            tree,
        } => {
            if session.is_server {
                log::warn!(target: "citadel", "Ignoring an OwnershipTransferred for {key:?}: only a server sends one");
                return Ok(PrimaryProcessorResult::Void);
            }
            group_succession_relay::ownership_transferred(
                session,
                &crafter,
                group_succession_relay::Transfer {
                    key,
                    owner,
                    previous,
                    tree,
                },
                ticket,
            )
        }

        GroupBroadcast::MessageDropped { key, .. } => {
            log::warn!(target: "citadel", "Ignoring a MessageDropped notice for {key:?} from the wire; it is local-only");
            Ok(PrimaryProcessorResult::Void)
        }

        // Promote/Demote are owner-local admin requests handled entirely on the outbound path
        // (`process_outbound_broadcast_command`); they are never relayed, so receiving one is a no-op.
        GroupBroadcast::Promote { .. } | GroupBroadcast::Demote { .. } => {
            log::warn!(target: "citadel", "Received an owner-local hierarchy admin signal inbound; ignoring");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

/// Create a group channel acting under `owner`, the group's owner as the server reports it
pub(super) fn create_group_channel<R: Ratchet, T: PlatformOps>(
    ticket: Ticket,
    key: MessageGroupKey,
    session: &CitadelSession<R, T>,
    owner: u64,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let channel = inner_mut_state!(session.state_container)
        .setup_group_channel_endpoints(key, ticket, session, owner)?;
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

/// Whether a KeyPackage publish may replace state this session already holds as a member.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum JoinMode {
    /// An invitation accepted: a session already in the group has nothing to publish.
    KeepMembership,
    /// A restore prompt: any state held is not in the owner's current tree, so start over.
    Replace,
}

/// A joiner generates its TreeKEM `KeyPackage`, stores its pending CGKA state, and publishes the
/// KeyPackage to the owner (routed by the relay). The group channel is deferred until the Welcome.
#[allow(clippy::too_many_arguments)]
pub(super) fn cgka_joiner_publish_key_package<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    key: MessageGroupKey,
    joiner_cid: u64,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
    mode: JoinMode,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let kp_bytes = {
        let mut state = inner_mut_state!(session.state_container);
        // "Already joining" and "already a member" are NOT the same answer.
        //
        // This asked `contains_key`, which conflates them. A joiner inserts its
        // state and publishes its KeyPackage in one step, so if the server
        // failed to relay that KeyPackage -- and it discarded relay errors --
        // the entry stayed behind with no group ever formed. Every retry then
        // hit this guard and returned Void: the join was wedged permanently,
        // and silently, by a single dropped packet.
        //
        // `is_pending_join` is the distinction the state already modelled
        // (`group: None` until the Welcome lands). A member still short-circuits;
        // a stalled joiner republishes.
        match state.group_cgka.get(&key) {
            Some(cgka) if !cgka.is_pending_join() && mode == JoinMode::KeepMembership => {
                // Already among this group; nothing to publish.
                return Ok(PrimaryProcessorResult::Void);
            }
            Some(_) => {
                log::warn!(target: "citadel", "Republishing KeyPackage for {key:?}: a previous join for this group never received its Welcome");
            }
            None => {}
        }
        let (cgka, kp_bytes) = GroupCgkaState::new_joiner(joiner_cid, GroupHierarchyMode::Flat)?;
        // Replaces any stalled pending state, along with its now-dead leaf secret.
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
    )?;
    session.send_to_primary_stream(Some(ticket), packet)?;
    Ok(PrimaryProcessorResult::Void)
}

/// Owner, prompted by the server after reconnecting, or told it succeeded to a group it holds no
/// state for: re-found the group's tree, open the group channel for the application, and tell the
/// server it may bring the members back. A fresh leaf secret and epoch 0: nothing from the old
/// tree is reused.
pub(super) fn cgka_owner_refound<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    key: MessageGroupKey,
    tree: u64,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session_cid = session
        .session_cid
        .get()
        .ok_or_else(|| error!(ErrorCode::StateImplicatedCidNotLoaded))?;
    let channel_open = {
        let mut state = inner_mut_state!(session.state_container);
        if state.group_cgka.contains_key(&key) {
            log::warn!(target: "citadel", "Ignoring RestoreOwnership for {key:?}: this session already holds the group");
            return Ok(PrimaryProcessorResult::Void);
        }
        // Only flat groups outlive their owner's session (see `group_retention`).
        let mut cgka = GroupCgkaState::new_owner(session_cid, GroupHierarchyMode::Flat)?;
        // The server moves the group to the next tree when it reads the echo below.
        cgka.tree = tree + 1;
        let _ = state.group_cgka.insert(key, cgka);
        state.record_group_owner(key, Some(session_cid));
        state.has_open_group_channel(key)
    };
    if !channel_open {
        let _ = create_group_channel(ticket, key, session, session_cid)?;
    }
    let packet = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &GroupBroadcast::RestoreOwnership { key, tree: 0 },
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    )?;
    session.send_to_primary_stream(Some(ticket), packet)?;
    Ok(PrimaryProcessorResult::Void)
}

impl From<GroupBroadcast> for GroupBroadcastPayload {
    /// Convert GroupBroadcast to GroupBroadcastPayload
    fn from(broadcast: GroupBroadcast) -> Self {
        group_ordered::to_payload(broadcast)
    }
}

/// Forward a signal to the kernel or a group channel
pub(super) fn forward_signal<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    ticket: Ticket,
    key: Option<MessageGroupKey>,
    broadcast: GroupBroadcast,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session_cid = return_if_none!(session.session_cid.get(), "Implicated CID not loaded");

    // To the group's channel while the application holds it open; otherwise to the kernel.
    let broadcast = match key {
        Some(key) => {
            let mut state = inner_mut_state!(session.state_container);
            match state.group_channels.get(&key) {
                Some(tx) => match tx.unbounded_send(broadcast.into()) {
                    Ok(()) => return Ok(PrimaryProcessorResult::Void),
                    Err(unsent) => {
                        let _ = state.group_channels.remove(&key);
                        group_ordered::from_payload(key, unsent.0)
                    }
                },
                None => broadcast,
            }
        }
        None => broadcast,
    };

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
