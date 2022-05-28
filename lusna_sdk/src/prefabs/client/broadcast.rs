use crate::prelude::{UserIdentifier, MessageGroupKey, NetKernel};

/// A kernel that streamlines creating, connecting, and interacting with groups. Unlike
/// [`PeerConnectionKernel`] and [`SingleClientServerConnectionKernel`], this kernel
/// expects that the client is already registered to the central.
/// Each group has a single owner, and, each connecting peer must at least be registered
/// to the owner alone. The owner thus serves as an "axis of consent", where each member
/// trusts the owner, and through this trust, transitivity of trust flows to all other
/// future members that connect to the group.
pub struct BroadcastKernel {
    initial_request: GroupInitRequestType,
    c2s_kernel: Box<dyn NetKernel>
}

/// Before running the [`BroadcastKernel`], each peer must send this request
/// to the protocol. One peer can create a group, allowing others to join the group.
///
/// Each peer may create multiple groups. Each new group will have a new group_id
pub enum GroupInitRequestType {
    /// Create a new group, under owner, with a list of users that are desired to be invited
    Create { owner: UserIdentifier, invite_list: Vec<UserIdentifier> },
    /// Join a pre-existing group as local_user that is administered by owner, and an optional group_id.
    /// If the local_user is not yet registered to the owner, an error will be thrown
    /// If the group_id is not known, None can be used, in which case the protocol will
    /// attempt to find the latest group created by the owner
    Join { local_user: UserIdentifier, owner: UserIdentifier, group_id: Option<u128> },
}

impl BroadcastKernel {

}