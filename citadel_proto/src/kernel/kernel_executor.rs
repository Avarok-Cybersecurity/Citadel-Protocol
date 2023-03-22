use std::pin::Pin;

use futures::TryStreamExt;
use tokio::runtime::Handle;
use tokio::task::LocalSet;

use citadel_user::account_manager::AccountManager;

use crate::error::NetworkError;
use crate::kernel::kernel_communicator::KernelAsyncCallbackHandler;
use crate::kernel::kernel_trait::NetKernel;
use crate::kernel::{KernelExecutorArguments, KernelExecutorSettings, RuntimeFuture};
use crate::proto::node::HdpServer;
use crate::proto::node_result::NodeResult;
use crate::proto::outbound_sender::{unbounded, UnboundedReceiver};
use crate::proto::packet_processor::includes::Duration;
use crate::proto::remote::NodeRemote;

/// Creates a [KernelExecutor]
pub struct KernelExecutor<K: NetKernel> {
    server_remote: Option<NodeRemote>,
    server_to_kernel_rx: Option<UnboundedReceiver<NodeResult>>,
    shutdown_alerter_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    callback_handler: Option<KernelAsyncCallbackHandler>,
    context: Option<KernelContext>,
    account_manager: AccountManager,
    kernel_executor_settings: KernelExecutorSettings,
    kernel: K,
}

type KernelContext = (Handle, Pin<Box<dyn RuntimeFuture>>, Option<LocalSet>);

impl<K: NetKernel> KernelExecutor<K> {
    /// Creates a new [KernelExecutor]. Panics if the server cannot start
    /// - underlying_proto: The proto to use for client to server communications
    pub async fn new(args: KernelExecutorArguments<K>) -> Result<Self, NetworkError> {
        let KernelExecutorArguments::<K> {
            rt,
            hypernode_type,
            account_manager,
            kernel,
            underlying_proto,
            client_config,
            kernel_executor_settings,
            stun_servers,
        } = args;
        let (server_to_kernel_tx, server_to_kernel_rx) = unbounded();
        let (server_shutdown_alerter_tx, server_shutdown_alerter_rx) =
            tokio::sync::oneshot::channel();
        // After this gets called, the server starts running and we get a remote
        let (remote, future, localset_opt, callback_handler) = HdpServer::init(
            hypernode_type,
            server_to_kernel_tx,
            account_manager.clone(),
            server_shutdown_alerter_tx,
            underlying_proto,
            client_config,
            stun_servers,
        )
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;

        Ok(Self {
            kernel_executor_settings,
            shutdown_alerter_rx: Some(server_shutdown_alerter_rx),
            callback_handler: Some(callback_handler),
            server_remote: Some(remote),
            server_to_kernel_rx: Some(server_to_kernel_rx),
            kernel,
            context: Some((rt, future, localset_opt)),
            account_manager,
        })
    }

    /// This function is expected to be asynchronously executed from the context of the tokio runtime
    pub async fn execute(mut self) -> Result<K, NetworkError> {
        let mut kernel = self.kernel;

        let server_to_kernel_rx = self.server_to_kernel_rx.take().unwrap();
        let server_remote = self.server_remote.take().unwrap();
        let kernel_executor_settings = self.kernel_executor_settings;
        let shutdown_alerter_rx = self.shutdown_alerter_rx.take().unwrap();
        let callback_handler = self.callback_handler.take().unwrap();

        let (_rt, hdp_server, _localset_opt) = self.context.take().unwrap();

        log::trace!(target: "citadel", "KernelExecutor::execute is now executing ...");

        let ret = {
            let kernel_future = Self::kernel_inner_loop(
                &mut kernel,
                server_to_kernel_rx,
                server_remote,
                shutdown_alerter_rx,
                callback_handler,
                kernel_executor_settings,
            );
            #[cfg(feature = "multi-threaded")]
            {
                use crate::proto::misc::panic_future::ExplicitPanicFuture;
                let hdp_server_future = ExplicitPanicFuture::new(_rt.spawn(hdp_server));
                tokio::select! {
                    ret0 = kernel_future => ret0,
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
                    ret0 = kernel_future => ret0,
                    ret1 = hdp_server_future => ret1
                }
            }
        };

        log::trace!(target: "citadel", "KernelExecutor::execute has finished execution");
        ret.map(|_| kernel)
    }

    #[allow(unused_must_use)]
    async fn kernel_inner_loop(
        kernel: &mut K,
        mut server_to_kernel_rx: UnboundedReceiver<NodeResult>,
        ref hdp_server_remote: NodeRemote,
        shutdown: tokio::sync::oneshot::Receiver<()>,
        ref callback_handler: KernelAsyncCallbackHandler,
        kernel_settings: KernelExecutorSettings,
    ) -> Result<(), NetworkError> {
        log::trace!(target: "citadel", "Kernel multithreaded environment executed ...");
        // Load the remote into the kernel
        kernel.load_remote(hdp_server_remote.clone())?;

        let (ref clean_stop_tx, mut clean_stop_rx) = tokio::sync::mpsc::channel::<()>(1);
        let kernel_ref = &*kernel;

        let init = async move { kernel_ref.on_start().await };

        let inbound_stream = async move {
            let reader = async_stream::try_stream! {
                while let Some(value) = server_to_kernel_rx.recv().await {
                    yield value;
                }
            };

            reader.try_for_each_concurrent(kernel_settings.max_concurrency, |message: NodeResult| async move {
                log::trace!(target: "citadel", "[KernelExecutor] Received message {:?}", message);
                match message {
                    NodeResult::Shutdown => {
                        log::trace!(target: "citadel", "Kernel received safe shutdown signal");
                        let _ = clean_stop_tx.send(()).await;
                        Ok(())
                    }

                    message => {
                        callback_handler.on_message_received(message, |message| async move {
                            if let Err(err) = kernel_ref.on_node_event_received(message).await {
                                log::error!(target: "citadel", "Kernel threw an error: {:?}. Will end", &err);
                                // calling this will cause server_to_kernel_rx to receive a shutdown message
                                hdp_server_remote.clone().shutdown().await?;
                                Err(err)
                            } else {
                                Ok(())
                            }
                        }).await
                    }
                }
            }).await
        };

        let base_execution = futures::future::try_join(init, inbound_stream);

        let exec_res = tokio::select! {
            base_res = base_execution => base_res.map(|_| ()),
            _stopper = clean_stop_rx.recv() => Ok(())
        };

        log::trace!(target: "citadel", "Calling kernel on_stop, but first awaiting HdpServer for clean shutdown ...");
        tokio::time::timeout(Duration::from_millis(300), shutdown).await;
        log::trace!(target: "citadel", "KernelExecutor confirmed HdpServer has been shut down");
        let stop_res = kernel.on_stop().await;
        // give precedence to the execution res
        exec_res.and(stop_res.map(|_| ()))
    }

    pub fn account_manager(&self) -> &AccountManager {
        &self.account_manager
    }
}
