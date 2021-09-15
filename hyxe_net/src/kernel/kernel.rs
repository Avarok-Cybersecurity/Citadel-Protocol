use async_trait::async_trait;

use crate::error::NetworkError;
use crate::hdp::hdp_server::{HdpServerRemote, HdpServerResult};

/// The [NetKernel] is the thread-safe interface between the single-threaded OR multi-threaded async
/// protocol and your network application
#[async_trait]
pub trait NetKernel: Send + Sync + 'static {
    /// when the kernel executes, it will be given a handle to the server
    fn load_remote(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError>;
    /// After the server remote is passed to the kernel, this function will be called once to allow the application to make any initial calls
    async fn on_start(&self) -> Result<(), NetworkError>;
    /// When the server processes a valid entry, the value is sent here. Each call to 'on_server_message_received' is done
    /// *concurrently* (but NOT in *parallel*). This allows code inside this function to await without blocking new incoming
    /// messages
    async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError>;
    /// When the system is ready to shutdown, this is called
    async fn on_stop(self) -> Result<(), NetworkError>;
    /// The [KernelExecutor] must know when to stop the underlying server for a safe shutdown. In the event loop,
    /// `can_run` is polled before sending a message to 'on_server_message_received' to determine if the kernel's state is valid
    fn can_run(&self) -> bool {
        true
    }
}