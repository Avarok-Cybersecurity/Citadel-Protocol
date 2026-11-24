/*!
# Peer Module

This module is the root of the peer-to-peer networking implementation in the Citadel Protocol, organizing various submodules for P2P functionality.

## Features
- **Complete P2P Stack**: Provides a full peer-to-peer networking solution
- **Modular Architecture**: Separates concerns into specialized submodules
- **Security-First Design**: Implements secure communication patterns
- **NAT Traversal**: Supports various NAT traversal techniques
- **Group Communication**: Enables secure group messaging

## Submodules
- `peer_layer`: Core peer networking infrastructure and state management
- `channel`: Basic peer-to-peer communication channels
- `group_channel`: Group communication channels
- `peer_crypt`: Cryptographic operations and key exchange
- `message_group`: Group messaging framework
- `p2p_conn_handler`: Direct P2P connection management
- `hole_punch_compat_sink_stream`: NAT traversal compatibility layer

## Important Notes
1. All peer communication is encrypted by default
2. NAT traversal is handled automatically
3. Group messaging follows a consent-based model
4. Connection state is managed through the peer layer

## Related Components
- `session`: Manages connection sessions
- `packet_processor`: Handles packet routing
- `state_container`: Tracks connection state
- `remote`: Manages remote connections

*/

pub(crate) mod mailbox;
/// For managing the state of peer-related activities
pub mod peer_layer;

pub mod channel;

pub mod group_channel;

/// Client-side coordinator for the zero-trust post-quantum TreeKEM group CGKA.
pub mod group_cgka;

/// What a server keeps of an owner's message groups when the owner's session ends.
pub mod group_retention;

/// Who owns a group once its owner leaves, and when a group ends.
pub mod group_succession;

/// The owner a client's group channel acts under.
pub mod group_owner;
/// A replay group's order, as its server last described it to this member.
pub mod group_order_view;

/// Server-side rendezvous for a member waiting on a group its owner has not created yet.
pub mod group_watch;

/// Server-side wait for a group's members to apply the owner's latest Commit.
pub mod group_commit_gate;

/// The server's group registry, persisted through the account backend
pub mod group_persistence;
pub(crate) mod group_persistence_shape;

/// What a server holds for a group member that is away.
pub mod group_backup;
/// Each group position reaching a member's application at most once per process run.
pub mod group_delivered;
/// Server-side caps on a group's message size and rate
pub(crate) mod group_limits;
/// A replay group's log kept within its limits, and ranges read from it (decisions only).
pub(crate) mod group_log_plan;
/// Where a group's order is stored.
pub(crate) mod group_log;
/// Reading, trimming and moving a replay group's log.
pub(crate) mod group_log_ops;
/// A replay group's log at the server: started, turned on, described and read.
pub(crate) mod group_replay;
pub mod group_mail;
/// Positioning a group broadcast on the server, with its order stored first.
pub(crate) mod group_position;
/// Whom the server relays a group broadcast to, and whether a message is within its caps
pub mod group_relay;
pub mod group_resume;
/// The order of each group's broadcasts (decisions only).
pub mod group_sequencer;
pub mod group_state_store;

/// Loading the group registry at server start, and keeping its durable copy in step
pub mod group_restart;

pub mod peer_crypt;

pub mod message_group;

pub mod p2p_conn_handler;

pub mod class_gates;
/// End-to-end signatures over a P2P key exchange by each account's identity key.
pub mod kex_auth;
pub mod kex_path;
/// The SDK adapters of the in-session negotiation layer.
pub mod negotiation;
pub mod p2p_path;
pub(crate) mod p2p_plan;
pub(crate) mod p2p_seal_binding;

/// Per-attempt outcomes of the P2P path campaign (which path won, and why the others did not)
pub mod p2p_outcome;
pub(crate) mod p2p_outcome_context;

pub(crate) mod direct_journal;

pub(crate) mod direct_route;
pub(crate) mod disconnect_request;
pub(crate) mod pair_role;

pub(crate) mod p2p_campaign;

pub(crate) mod coordination;

pub(crate) mod p2p_rearm;

pub(crate) mod p2p_retry;

#[cfg(not(target_family = "wasm"))]
pub(crate) mod turn_p2p;
#[cfg(not(target_family = "wasm"))]
mod turn_rendezvous;

pub(crate) mod hole_punch_compat_sink_stream;
