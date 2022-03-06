use std::pin::Pin;

use futures::TryStreamExt;
use tokio::runtime::Handle;
use tokio::task::LocalSet;

use hyxe_nat::hypernode_type::NodeType;
use hyxe_user::account_manager::AccountManager;

use crate::error::NetworkError;
use crate::hdp::hdp_packet_processor::includes::Duration;
use crate::hdp::hdp_node::{HdpServer, NodeRemote, HdpServerResult};
use crate::hdp::misc::panic_future::ExplicitPanicFuture;
use crate::hdp::misc::underlying_proto::UnderlyingProtocol;
use crate::hdp::outbound_sender::{unbounded, UnboundedReceiver};
use crate::kernel::kernel::NetKernel;
use crate::kernel::kernel_communicator::KernelAsyncCallbackHandler;
use crate::kernel::RuntimeFuture;
use hyxe_nat::exports::tokio_rustls::rustls::ClientConfig;
use std::sync::Arc;

/// Creates a [KernelExecutor]
pub struct KernelExecutor<K: NetKernel> {
    server_remote: Option<NodeRemote>,
    server_to_kernel_rx: Option<UnboundedReceiver<HdpServerResult>>,
    shutdown_alerter_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    callback_handler: Option<KernelAsyncCallbackHandler>,
    context: Option<(Handle, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>)>,
    account_manager: AccountManager,
    kernel: K,
}

impl<K: NetKernel> KernelExecutor<K> {
    /// Creates a new [KernelExecutor]. Panics if the server cannot start
    /// - underlying_proto: The proto to use for client to server communications
    pub async fn new(rt: Handle, hypernode_type: NodeType, account_manager: AccountManager, kernel: K, underlying_proto: UnderlyingProtocol, client_config: Option<Arc<ClientConfig>>) -> Result<Self, NetworkError> {
        let (server_to_kernel_tx, server_to_kernel_rx) = unbounded();
        let (server_shutdown_alerter_tx, server_shutdown_alerter_rx) = tokio::sync::oneshot::channel();
        // After this gets called, the server starts running and we get a remote
        let (remote, future, localset_opt, callback_handler) = HdpServer::init(hypernode_type, server_to_kernel_tx, account_manager.clone(), server_shutdown_alerter_tx, underlying_proto, client_config).await.map_err(|err| NetworkError::Generic(err.to_string()))?;

        Ok(Self { shutdown_alerter_rx: Some(server_shutdown_alerter_rx), callback_handler: Some(callback_handler), server_remote: Some(remote), server_to_kernel_rx: Some(server_to_kernel_rx), kernel, context: Some((rt, future, localset_opt)), account_manager })
    }

    /// This function is expected to be asynchronously executed from the context of the tokio runtime
    pub async fn execute(mut self) -> Result<(), NetworkError> {
        let kernel = self.kernel;

        let server_to_kernel_rx = self.server_to_kernel_rx.take().unwrap();
        let server_remote = self.server_remote.take().unwrap();
        let shutdown_alerter_rx = self.shutdown_alerter_rx.take().unwrap();
        let callback_handler = self.callback_handler.take().unwrap();

        let (rt, hdp_server, _localset_opt) = self.context.take().unwrap();

        let kernel_future = ExplicitPanicFuture::new(rt.spawn(Self::multithreaded_kernel_inner_loop(kernel, server_to_kernel_rx, server_remote ,shutdown_alerter_rx, callback_handler)));

        log::info!("KernelExecutor::execute is now executing ...");

        let ret = {
            #[cfg(feature = "multi-threaded")]
                {
                    let hdp_server_future = ExplicitPanicFuture::new(rt.spawn(hdp_server));
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
    async fn multithreaded_kernel_inner_loop(mut kernel: K, mut server_to_kernel_rx: UnboundedReceiver<HdpServerResult>, ref hdp_server_remote: NodeRemote, shutdown: tokio::sync::oneshot::Receiver<()>, ref callback_handler: KernelAsyncCallbackHandler) -> Result<(), NetworkError> {
        log::info!("Kernel multithreaded environment executed ...");
        // Load the remote into the kernel
        kernel.load_remote(hdp_server_remote.clone())?;

        let ref kernel_ref = kernel;

        let init = async move {
            kernel_ref.on_start().await
        };

        let inbound_stream = async move {
            let reader = async_stream::try_stream! {
                while let Some(value) = server_to_kernel_rx.recv().await {
                    yield value;
                }
            };

            reader.try_for_each_concurrent(None, |message: HdpServerResult| async move {
                log::info!("[KernelExecutor] Received message {:?}", message);
                match message {
                    HdpServerResult::Shutdown => {
                        log::info!("Kernel received safe shutdown signal");
                        Ok(())
                    }

                    message => {
                        if !kernel_ref.can_run() {
                            Err(NetworkError::Generic("Kernel can no longer run".to_string()))
                        } else {
                            callback_handler.on_message_received(message, |message| async move {
                                if let Err(err) = kernel_ref.on_node_event_received(message).await {
                                    log::error!("Kernel threw an error: {:?}. Will end", &err);
                                    // calling this will cause server_to_kernel_rx to receive a shutdown message
                                    hdp_server_remote.clone().shutdown().await?;
                                    Err(err)
                                } else {
                                    Ok(())
                                }
                            }).await
                        }
                    }
                }
            }).await
        };

        let exec_res = tokio::try_join!(init, inbound_stream);

        log::info!("Calling kernel on_stop, but first awaiting HdpServer for clean shutdown ...");
        tokio::time::timeout(Duration::from_millis(300), shutdown).await;
        log::info!("Kernel confirmed HdpServer has been shut down");
        let stop_res = kernel.on_stop().await;
        // give precedence to the exection res
        exec_res.and(stop_res.map(|_| ()))
    }

    pub fn account_manager(&self) -> &AccountManager {
        &self.account_manager
    }
}