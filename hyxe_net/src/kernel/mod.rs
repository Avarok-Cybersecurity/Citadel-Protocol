use tokio::macros::support::Future;

use crate::error::NetworkError;
use crate::macros::ContextRequirements;

/// The entity which interfaces the lower-level [HdpServer] and the higher-level API
pub mod kernel;
/// for handling easy asynchronous callbacks
pub mod kernel_communicator;
/// The mid-level entity in this crate which uses a multithreaded tokio runtime
/// with a single-threaded lower-level [HdpServer]
pub mod kernel_executor;

pub trait RuntimeFuture: Future<Output = Result<(), NetworkError>> + ContextRequirements {}
impl<T: Future<Output = Result<(), NetworkError>> + ContextRequirements> RuntimeFuture for T {}

#[derive(Default, Debug)]
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
