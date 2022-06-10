use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fmt::Formatter;

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
///
/// Axis of consent: P_0
/// Peripheral Users: all users connected to P_0 *and* agreed to enter G(P_0)
///
/// [MessageGroup]s should be seen as short-lived messaging frames. They stay alive as long as the axis of consent
/// keeps the group alive or disconnects from the HyperLAN Server. When P_0 leaves, users will still have local messages
/// of the chat, but won't receive anymore chats from the group
pub struct MessageGroup {
    // peer cid, entry (entry will contain metadata in the future)
    pub(crate) concurrent_peers: HashMap<u64, MessageGroupPeer>,
    pub(crate) pending_peers: HashMap<u64, MessageGroupPeer>,
    pub(crate) options: MessageGroupOptions
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Options for creating message groups
pub struct MessageGroupOptions {
    pub group_type: GroupType,
    pub id: u128
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Copy, Clone)]
pub enum GroupType {
    /// A public group is a group where any user registered to the owner can join
    Public,
    /// A private group is a group where the group can only be joined when the owner
    /// sends out Invitation requests to mutually-registered peers
    Private
}

/// TODO: Attributed data (e.g., permissions)
pub(crate) struct MessageGroupPeer {
    #[allow(dead_code)]
    pub peer_cid: u64,
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageGroupKey {
    pub cid: u64,
    pub mgid: u128
}

impl MessageGroupKey {
    pub fn new(cid: u64, mgid: u128) -> Self {
        Self { cid, mgid }
    }
}

impl std::fmt::Debug for MessageGroupKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for MessageGroupKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.cid, self.mgid)
    }
}