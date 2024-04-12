use citadel_user::account_manager::AccountManager;
use citadel_wire::exports::ClientConfig;
use citadel_wire::hypernode_type::NodeType;
use std::sync::Arc;
use tokio::macros::support::Future;
use tokio::runtime::Handle;

use crate::error::NetworkError;
use crate::macros::ContextRequirements;
use crate::prelude::{PreSharedKey, ServerUnderlyingProtocol};

/// for handling easy asynchronous callbacks
pub mod kernel_communicator;
/// The mid-level entity in this crate which uses a multithreaded tokio runtime
/// with a single-threaded lower-level [HdpServer]
pub mod kernel_executor;
/// The entity which interfaces the lower-level [HdpServer] and the higher-level API
pub mod kernel_trait;

pub trait RuntimeFuture: Future<Output = Result<(), NetworkError>> + ContextRequirements {}
impl<T: Future<Output = Result<(), NetworkError>> + ContextRequirements> RuntimeFuture for T {}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
/// Used for fine-tuning parameters within the [`KernelExecutor`]
pub struct KernelExecutorSettings {
    max_concurrency: Option<usize>,
}

impl KernelExecutorSettings {
    /// Determines the maximum number of concurrent asynchronous subroutines executed for
    /// [`NetKernel::on_node_event_received`]. Default is None, implying there is no limit
    pub fn with_max_concurrency(mut self, max_concurrency: impl Into<Option<usize>>) -> Self {
        self.max_concurrency = max_concurrency.into();
        self
    }
}

pub struct KernelExecutorArguments<K> {
    pub rt: Handle,
    pub hypernode_type: NodeType,
    pub account_manager: AccountManager,
    pub kernel: K,
    pub underlying_proto: ServerUnderlyingProtocol,
    pub client_config: Option<Arc<ClientConfig>>,
    pub kernel_executor_settings: KernelExecutorSettings,
    pub stun_servers: Option<Vec<String>>,
    pub server_only_session_password: Option<PreSharedKey>,
}
