use crate::prelude::*;
use crate::prefabs::ClientServerRemote;
use std::marker::PhantomData;
use futures::Future;

/// A kernel that streamlines creating, connecting, and interacting with groups
/// Each group has a single owner, and, each connecting peer must at least be registered
/// to the owner alone. The owner thus serves as an "axis of consent", where each member
/// trusts the owner, and through this trust, transitivity of trust flows to all other
/// future members that connect to the group.
pub struct BroadcastKernel<F, Fut> {
    inner_kernel: Box<dyn NetKernel>,
    _pd: PhantomData<fn() -> (F, Fut)>
}

/// Before running the [`BroadcastKernel`], each peer must send this request
/// to the protocol. One peer can create a group, allowing others to join the group.
///
/// Each peer may create multiple groups. Each new group will have a new group_id
pub enum GroupInitRequestType {
    /// Create a new group, under owner, with a list of users that are desired to be invited
    Create { local_user: UserIdentifier, invite_list: Vec<UserIdentifier>, auto_accept: bool },
    /// Join a pre-existing group as local_user that is administered by owner, and a group_id
    /// that corresponds to a unique group administered by the particular owner
    Join { local_user: UserIdentifier, owner: UserIdentifier, group_id: u128 },
}

#[async_trait]
impl<F, Fut> PrefabFunctions<GroupInitRequestType> for BroadcastKernel<F, Fut>
    where
        F: FnOnce(Result<GroupChannel, NetworkError>) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    type UserLevelInputFunction = F;

    async fn on_c2s_channel_received(connect_success: ConnectSuccess, remote: ClientServerRemote, arg: GroupInitRequestType, fx: Self::UserLevelInputFunction) -> Result<(), NetworkError> {
        let implicated_cid = connect_success.cid;

        let request = match arg {
            GroupInitRequestType::Create { local_user, invite_list, auto_accept } => {
                // ensure local user is registered to each on the invite list
                let mut peers_registered = vec![];
                for peer in &invite_list {
                    let peer = peer.search_peer(implicated_cid, remote.inner.account_manager()).await?
                        .ok_or_else(|| NetworkError::msg(format!("User {:?} is not registered to {:?}", peer, &local_user)))?;
                    peers_registered.push(peer.cid)
                }

                // TODO: auto accept for users
                GroupBroadcast::Create(peers_registered, auto_accept)
            }

            GroupInitRequestType::Join { local_user, owner, group_id } => {
                // ensure local is registered to owner
                let peer = owner.search_peer(implicated_cid, remote.inner.account_manager()).await?
                    .ok_or_else(|| NetworkError::msg(format!("User {:?} is not registered to {:?}", owner, &local_user)))?;

                // TODO: implement RequestJoin, and, auto_accept for owners
                GroupBroadcast::RequestJoin(peer.cid)
            }
        };

        let request = HdpServerRequest::GroupBroadcastCommand(implicated_cid, request);
    }

    fn construct(kernel: Box<dyn NetKernel>) -> Self {
        Self {
            inner_kernel: kernel,
            _pd: Default::default()
        }
    }
}