use tokio::macros::support::Future;

use crate::error::NetworkError;
use crate::macros::ContextRequirements;

/// The mid-level entity in this crate which uses a multithreaded tokio runtime
/// with a single-threaded lower-level [HdpServer]
pub mod kernel_executor;
/// The entity which interfaces the lower-level [HdpServer] and the higher-level API
pub mod kernel;

pub trait RuntimeFuture: Future<Output=Result<(), NetworkError>> + ContextRequirements {}
impl<T: Future<Output=Result<(), NetworkError>> + ContextRequirements> RuntimeFuture for T {}
