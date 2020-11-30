use async_trait::async_trait;

use crate::error::NetworkError;
use crate::hdp::hdp_server::{HdpServerRemote, HdpServerResult};

/// The [Kernel] is the thread-safe interface between the single-threaded async
/// [HdpServer] and the multithreaded higher-level
#[async_trait]
pub trait NetKernel where Self: Send + Sync {
    /// when the kernel executes, it will be given a handle to the server
    async fn on_start(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError>;
    /// When the server processes a valid entry, the value is sent here
    async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError>;
    /// The [KernelExecutor] must know when to stop the underlying server for a safe shutdown. In the event loop,
    /// `can_run` is polled periodically to determine if the Kernel even needs the server to keep running
    fn can_run(&self) -> bool;
    /// When it's time to shutdown, this function is called
    async fn on_stop(&self) -> Result<(), NetworkError>;
}