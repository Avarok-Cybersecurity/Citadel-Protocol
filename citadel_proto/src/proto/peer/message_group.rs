/*!
# Message Group Module

This module implements the group messaging framework for the Citadel Protocol, providing a consent-based group communication model.

## Features
- **Axis of Consent Model**: Implements a centralized consent model around the group initiator
- **Peer Management**: Handles both concurrent and pending peer states
- **Group Lifecycle**: Manages group creation, membership, and termination
- **Permission System**: Supports group options and peer-specific permissions
- **Short-lived Messaging Frames**: Optimized for temporary group communications

## Core Components
- `MessageGroup`: Main structure managing group state and peer membership
- `MessageGroupPeer`: Represents individual peer state and metadata
- `MessageGroupOptions`: Configures group behavior and permissions

## Important Notes
1. Groups are centered around an "axis of consent" (the initiator)
2. Consent is not transitive - all members must connect directly to the initiator
3. Groups are short-lived and terminate when the initiator disconnects
4. Local message history persists after group termination

## Related Components
- `peer_layer`: Manages peer-to-peer networking
- `group_channel`: Implements group communication channels
- `session`: Manages connection sessions
- `state_container`: Tracks connection state

*/

use citadel_types::proto::MessageGroupOptions;
use std::collections::HashMap;

/// A [MessageGroup] is a set of HyperLAN Clients communicating through the HyperLAN Server.
/// let P_0 be peer 0. Let S be the HyperLAN Server. Let there be a set of n peers: P_0 ... P_n-1
/// in a message group, G. When P_0 wants to start a message group, a request is sent to the central
/// server S. Once the server receives the request, it creates the [MessageGroup] G(P_0) below and places it
/// into the [PeerLayer]. Any peers connected to P_0 (the "message group initiator") will be able to
/// see G(P_0). If P_1 is in G(P_0), and some P_j is connected to P_1, P_j does not necessarily have
/// the capacity to connect to G(P_0); instead, the basic requirement is that P_j is connected to P_0.
/// In other words, *consent is not directly transitive*. By ensuring all P_n are connected to P_0, it instead enforces
/// an axis of consent. If Jacob is connected to John, and Sally is connected to John, then either Jacob
/// or Sally may opt-in to communicate in a group *with* John. Jacob or Sally are never forced to, and are given
/// a set of the peripheral users before entering G(P_0). If John ever leaves, the axis falls and the group
/// disintegrates. In this model, John was the axis of consent, and the peripheral users were Jacob and Sally.
/// Axis of consent: P_0
/// Peripheral Users: all users connected to P_0 *and* agreed to enter G(P_0)
/// [MessageGroup]s should be seen as short-lived messaging frames. They stay alive as long as the axis of consent
/// keeps the group alive or disconnects from the HyperLAN Server. When P_0 leaves, users will still have local messages
/// of the chat, but won't receive anymore chats from the group
pub struct MessageGroup {
    // peer cid, entry (entry will contain metadata in the future)
    pub(crate) concurrent_peers: HashMap<u64, MessageGroupPeer>,
    pub(crate) pending_peers: HashMap<u64, MessageGroupPeer>,
    pub(crate) options: MessageGroupOptions,
}

/// TODO: Attributed data (e.g., permissions)
pub(crate) struct MessageGroupPeer {
    #[allow(dead_code)]
    pub peer_cid: u64,
}
