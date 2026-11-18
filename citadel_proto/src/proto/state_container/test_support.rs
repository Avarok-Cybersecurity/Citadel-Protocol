//! A real state container, with no session around it, for tests of what it holds.

use super::includes::*;
use crate::constants::MAX_OUTGOING_UNPROCESSED_REQUESTS;
use crate::kernel::kernel_communicator::{
    KernelAsyncCallbackHandler, KernelAsyncCallbackHandlerInner,
};
use crate::proto::outbound_sender::BoundedSender;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;
use citadel_wire::hypernode_type::NodeType;

pub(crate) async fn state_container(
    is_server: bool,
    keep_alive_timeout_ns: i64,
) -> StateContainer<StackedRatchet> {
    let (requests, _) = BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS);
    let account_manager = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .expect("in-memory account manager");
    let node_remote = NodeRemote::new(
        requests,
        KernelAsyncCallbackHandler {
            inner: Arc::new(Mutex::new(KernelAsyncCallbackHandlerInner {
                map: Default::default(),
            })),
        },
        account_manager,
        NodeType::default(),
        crate::proto::misc::local_rebind::LocalRebinder::new(),
        Default::default(),
        Default::default(),
    );
    let (kernel_tx, _) = unbounded();
    let time_tracker = TimeTracker::new();
    StateContainerInner::create(
        kernel_tx,
        node_remote,
        keep_alive_timeout_ns,
        SessionState::Connected.into(),
        None,
        time_tracker,
        None,
        is_server,
        crate::proto::transfer_stats::TransferStats::new(time_tracker.get_global_time_ns(), 0),
        UdpMode::Disabled,
        Default::default(),
    )
}
