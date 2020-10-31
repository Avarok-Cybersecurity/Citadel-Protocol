use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;

use hyxe_user::account_manager::AccountManager;

use crate::kernel::kernel::Kernel;
use crate::error::NetworkError;
use crate::hdp::hdp_server::{HdpServer, HdpServerRemote, HdpServerResult};
use hyxe_nat::hypernode_type::HyperNodeType;

/// Creates a [KernelExecutor]
pub struct KernelExecutor<K: Kernel + Send + Sync> {
    server: HdpServer,
    server_remote: Option<HdpServerRemote>,
    server_to_kernel_rx: Option<UnboundedReceiver<HdpServerResult>>,
    kernel: K,
}

impl<K: Kernel + Send + Sync + 'static> KernelExecutor<K> {
    /// Creates a new [KernelExecutor]. Panics if the server cannot start
    pub async fn new<T: AsRef<str>>(hypernode_type: HyperNodeType, account_manager: AccountManager, kernel: K, bind_addr: T, primary_port: u16) -> Result<Self, NetworkError> {
        let (server_to_kernel_tx, server_to_kernel_rx) = unbounded();
        let server = HdpServer::new(hypernode_type, server_to_kernel_tx, bind_addr, primary_port, account_manager).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self { server, server_remote: None, server_to_kernel_rx: Some(server_to_kernel_rx), kernel })
    }

    /// This function is expected to be asynchronously executed from the context of the tokio runtime
    pub async fn execute(mut self) -> Result<(), NetworkError> {
        //let local_set = tokio::task::LocalSet::new();
        let runtime = new_runtime!();

        let server = self.server.clone();
        let kernel = self.kernel;
        log::info!("Obtaining server remote ...");
        // The function in execute only spawns_local, but does not actually run anything until we run run_until with the local set
        let server_remote = HdpServer::load(server, &runtime).await?;
        log::info!("Done obtaining server remote ...");

        let _ = self.server_remote.replace(server_remote.clone());

        let server_to_kernel_rx = self.server_to_kernel_rx.take().unwrap();

        let server_remote_kernel = server_remote.clone();

        // Now, run the kernel in its own mutlithreaded environment,
        //let _ = tokio::task::spawn(Self::multithreaded_kernel_inner_loop(kernel, server_to_kernel_rx, server_remote_kernel));
        // and run_until (single-thread) on the server. This starts all the futures loaded above
        //local_set.await;
        let res = runtime.execute_kernel(Self::multithreaded_kernel_inner_loop(kernel, server_to_kernel_rx, server_remote_kernel)).await;
        log::info!("Kernel::execute is finishing ... program going to quit");
        res
    }

    async fn multithreaded_kernel_inner_loop(mut kernel: K, mut server_to_kernel_rx: UnboundedReceiver<HdpServerResult>, hdp_server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        log::info!("Kernel multithreaded environment executed ...");
        // Load the remote into the kernel
        kernel.on_start(hdp_server_remote).await?;

        while let Some(message) = server_to_kernel_rx.next().await {
            if !kernel.can_run().await {
                break;
            }

            if let Err(_err) = kernel.on_server_message_received(message).await {
                break;
            }
        }

        log::info!("Calling kernel on_stop ...");

        kernel.on_stop().await
    }
}