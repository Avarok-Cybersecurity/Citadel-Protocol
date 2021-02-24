use std::pin::Pin;
use std::sync::Arc;

use tokio::net::ToSocketAddrs;
use tokio::runtime::Runtime;
use tokio::task::LocalSet;
use tokio_stream::StreamExt;

use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_user::account_manager::AccountManager;

use crate::error::NetworkError;
use crate::hdp::hdp_packet_processor::includes::Duration;
use crate::hdp::hdp_server::{HdpServer, HdpServerRemote, HdpServerResult};
use crate::hdp::outbound_sender::{unbounded, UnboundedReceiver};
use crate::kernel::kernel::NetKernel;
use crate::kernel::RuntimeFuture;

/// Creates a [KernelExecutor]
pub struct KernelExecutor<K: NetKernel> {
    server_remote: Option<HdpServerRemote>,
    server_to_kernel_rx: Option<UnboundedReceiver<HdpServerResult>>,
    shutdown_aleter_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    context: Option<(Arc<Runtime>, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>)>,
    kernel: K,
}

impl<K: NetKernel> KernelExecutor<K> {
    /// Creates a new [KernelExecutor]. Panics if the server cannot start
    pub async fn new<T: ToSocketAddrs + std::net::ToSocketAddrs + Send + 'static>(rt: Arc<Runtime>, hypernode_type: HyperNodeType, account_manager: AccountManager, kernel: K, bind_addr: T) -> Result<Self, NetworkError> {
        let (server_to_kernel_tx, server_to_kernel_rx) = unbounded();
        let (server_shutdown_alerter_tx, server_shutdown_alerter_rx) = tokio::sync::oneshot::channel();
        // After this gets called, the server starts running and we get a remote
        let (remote, future, localset_opt) = HdpServer::init(hypernode_type, server_to_kernel_tx, bind_addr, account_manager, server_shutdown_alerter_tx).await.map_err(|err| NetworkError::Generic(err.to_string()))?;

        Ok(Self { shutdown_aleter_rx: Some(server_shutdown_alerter_rx), server_remote: Some(remote), server_to_kernel_rx: Some(server_to_kernel_rx), kernel, context: Some((rt, future, localset_opt)) })
    }

    /// This function is expected to be asynchronously executed from the context of the tokio runtime
    pub async fn execute(mut self) -> Result<(), NetworkError> {
        let kernel = self.kernel;

        let server_to_kernel_rx = self.server_to_kernel_rx.take().unwrap();
        let server_remote = self.server_remote.take().unwrap();
        let shutdown_alerter_rx = self.shutdown_aleter_rx.take().unwrap();

        let (rt, hdp_server, _localset_opt) = self.context.take().unwrap();

        let kernel_future = rt.spawn(Self::multithreaded_kernel_inner_loop(kernel, server_to_kernel_rx, server_remote ,shutdown_alerter_rx));

        log::info!("KernelExecutor::execute is now executing ...");

        let ret = {
            #[cfg(feature = "multi-threaded")]
                {
                    let hdp_server_future = rt.spawn(hdp_server);
                    tokio::select! {
                        ret0 = kernel_future => ret0.map_err(|err| NetworkError::Generic(err.to_string()))?,
                        ret1 = hdp_server_future => ret1.map_err(|err| NetworkError::Generic(err.to_string()))?
                    }
                }
            #[cfg(not(feature = "multi-threaded"))]
                {
                    let localset = _localset_opt.unwrap();
                    //let _ = localset.spawn_local(hdp_server);
                    let hdp_server_future = localset.run_until(hdp_server);
                    //let hdp_server_future = localset;
                    tokio::select! {
                        ret0 = kernel_future => ret0.map_err(|err| NetworkError::Generic(err.to_string()))?,
                        ret1 = hdp_server_future => ret1
                    }
                }
        };

        log::info!("KernelExecutor::execute has finished execution");
        ret
    }

    #[allow(unused_must_use)]
    async fn multithreaded_kernel_inner_loop(mut kernel: K, server_to_kernel_rx: UnboundedReceiver<HdpServerResult>, hdp_server_remote: HdpServerRemote, shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<(), NetworkError> {
        log::info!("Kernel multithreaded environment executed ...");
        // Load the remote into the kernel
        kernel.on_start(hdp_server_remote.clone()).await?;

        let kernel = std::sync::Arc::new(kernel);

        let mut receiver = tokio_stream::wrappers::UnboundedReceiverStream::new(server_to_kernel_rx);

        while let Some(message) = receiver.next().await {
            match message {
                HdpServerResult::Shutdown => {
                    log::info!("Kernel received safe shutdown signal");
                    break;
                }

                message => {
                    if !kernel.can_run() {
                        break;
                    }

                    let kernel = kernel.clone();
                    let remote = hdp_server_remote.clone();
                    // Ensure that we don't block further calls to next().await, and offload the task to the tokio runtime
                    let _ = tokio::task::spawn(async move {
                        if let Err(err) = kernel.on_server_message_received(message).await {
                            log::error!("Kernel threw an error: {:?}. Will end", &err);
                            // calling this will cause server_to_kernel_rx to receive a shutdown message
                            remote.shutdown();
                        }
                    });
                }
            }
        }

        log::info!("Calling kernel on_stop, but first awaiting HdpServer for clean shutdown ...");
        tokio::time::timeout(Duration::from_millis(300), shutdown).await;
        log::info!("Kernel confirmed HdpServer has been shut down");
        kernel.on_stop().await
    }
}