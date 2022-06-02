use async_trait::async_trait;

use crate::error::NetworkError;
use crate::hdp::hdp_node::{NodeRemote, HdpServerResult};
use parking_lot::Mutex;
use crate::macros::SyncContextRequirements;
use std::marker::PhantomData;
use auto_impl::auto_impl;

/// The [NetKernel] is the thread-safe interface between the single-threaded OR multi-threaded async
/// protocol and your network application
#[async_trait]
#[auto_impl(Box)]
pub trait NetKernel: Send + Sync {
    /// when the kernel executes, it will be given a handle to the server
    fn load_remote(&mut self, node_remote: NodeRemote) -> Result<(), NetworkError>;
    /// After the server remote is passed to the kernel, this function will be called once to allow the application to make any initial calls
    async fn on_start(&self) -> Result<(), NetworkError>;
    /// When the server processes a valid entry, the value is sent here. Each call to 'on_server_message_received' is done
    /// *concurrently* (but NOT in *parallel*). This allows code inside this function to await without blocking new incoming
    /// messages
    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError>;
    /// When the system is ready to shutdown, this is called
    async fn on_stop(&mut self) -> Result<(), NetworkError>;
}

/// Allows chaining the execution of kernels and passing results
/// between the first and second kernel
pub struct ChainKernel<First: FirstKernelOnLoad, Second> {
    first: First,
    second: tokio::sync::RwLock<Option<Second>>,
    second_staging: parking_lot::Mutex<Option<Second>>,
    node_remote: Option<NodeRemote>,
    on_first_complete_tx: Option<tokio::sync::oneshot::Sender<First::FirstKernelSendResult>>,
    on_first_complete_rx: Mutex<Option<tokio::sync::oneshot::Receiver<First::FirstKernelSendResult>>>,
    _pd: PhantomData<fn() -> First::FirstKernelSendResult>
}

/// Once the implementation of the first kernel is deemed complete by the implementor, the send handle passed by
/// [`FirstKernelOnLoad::on_load_first_kernel`] should be sent a value, which in turn is received by the
/// [`SecondKernelOnBegin::on_begin_second_kernel`]
pub trait FirstKernelOnLoad: SyncContextRequirements {
    type FirstKernelSendResult: SyncContextRequirements;
    fn on_load_first_kernel(&mut self, call_to_begin_next_kernel: tokio::sync::oneshot::Sender<Self::FirstKernelSendResult>) -> Result<(), NetworkError>;
}

#[async_trait]
pub trait SecondKernelOnBegin<F: FirstKernelOnLoad>: SyncContextRequirements {
    /// When this is called, the [`NetKernel::load_remote`] has already been called. After this function is called,
    /// [`NetKernel::on_start`] is executed
    async fn on_begin_second_kernel(&mut self, first_kernel_result: F::FirstKernelSendResult) -> Result<(), NetworkError>;
}

impl<First: NetKernel + FirstKernelOnLoad, Second: NetKernel + SecondKernelOnBegin<First>> ChainKernel<First, Second> {
    #[allow(dead_code)]
    pub fn new(first: First, second: Second) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            first,
            second: tokio::sync::RwLock::new(None),
            second_staging: Mutex::new(Some(second)),
            node_remote: None,
            on_first_complete_tx: Some(tx),
            on_first_complete_rx: Mutex::new(Some(rx)),
            _pd: Default::default()
        }
    }
}

#[async_trait]
impl<First: NetKernel + FirstKernelOnLoad, Second: NetKernel + SecondKernelOnBegin<First>> NetKernel for ChainKernel<First, Second> {
    fn load_remote(&mut self, node_remote: NodeRemote) -> Result<(), NetworkError> {
        // the kernel executor will only call this once, implying we do not need to
        // interact with the second kernel here
        self.node_remote = Some(node_remote.clone());
        self.first.load_remote(node_remote)?;
        self.first.on_load_first_kernel(self.on_first_complete_tx.take().unwrap())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let begin_next_kernel_rx = {
            self.on_first_complete_rx.lock().take().unwrap()
        };

        let node_remote = self.node_remote.clone().ok_or_else(|| NetworkError::InternalError("Node remote not loaded"))?;

        let first_on_start = self.first.on_start();
        let begin_next = async move {
            let val = begin_next_kernel_rx.await.map_err(|_| NetworkError::msg("Unable to receive oneshot value"))?;
            // locking this will ensure all new messages get received by the second kernel
            let mut lock = self.second.write().await;
            let mut second = {
                self.second_staging.lock().take().unwrap()
            };

            second.load_remote(node_remote)?;
            second.on_begin_second_kernel(val).await?;
            // swap from staging to active to allow new message to be routed to the second kernel
            *lock = Some(self.second_staging.lock().take().unwrap());
            // downgrade to a read to ensure concurrent messages can be passed
            let lock = lock.downgrade();
            // holding the read lock here is okay since there will be no more
            // write calls past this point
            lock.as_ref().unwrap().on_start().await
        };

        tokio::try_join!(first_on_start, begin_next).map(|_| ())
    }

    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        if let Some(second) = self.second.read().await.as_ref() {
            second.on_node_event_received(message).await
        } else {
            self.first.on_node_event_received(message).await
        }
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        if let Some(second) = self.second.get_mut().as_mut() {
            second.on_stop().await
        } else {
            self.first.on_stop().await
        }
    }
}