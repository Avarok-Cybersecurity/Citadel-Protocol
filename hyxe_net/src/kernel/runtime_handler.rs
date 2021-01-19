use tokio::task::LocalSet;
use futures::Future;
use crate::error::NetworkError;
use std::pin::Pin;
use crate::hdp::AssertSendSafeFuture;
use crate::hdp::hdp_server::HdpServerRemote;
use crate::hdp::hdp_packet_processor::includes::Duration;

pub struct RuntimeHandler {
    inner: Option<LocalSet>,
    server_future: Option<Pin<Box<dyn Future<Output=Result<(), NetworkError>> + 'static>>>,
}

impl RuntimeHandler {
    pub fn load_server_future(&mut self, future: impl Future<Output=Result<(), NetworkError>> + 'static) {
        self.server_future = Some(Box::pin(future));
    }

    #[allow(unused_results, unused_must_use)]
    pub async fn execute_system(mut self, remote: HdpServerRemote, kernel: impl Future<Output=Result<(), NetworkError>> + 'static + Send) -> Result<(), NetworkError> {
        let server_future = unsafe { AssertSendSafeFuture::new(self.server_future.take().ok_or(NetworkError::InternalError("Kernel already executed; must reload server future"))?) };
        let thread_aware_server_future: Pin<Box<dyn Future<Output=Result<(), NetworkError>>>> = if let Some(local_set) = self.inner.take() {
            log::info!("Starting single-threaded HdpServer ...");
            Box::pin(async move { local_set.run_until(server_future).await })
        } else {
            log::info!("Starting multi-threaded HdpServer ...");
            //Box::pin(async move { tokio::task::spawn(server_future).await.map(|_| ()).map_err(|err| NetworkError::Generic(err.to_string())) })
            Box::pin(server_future)
        };

        let kernel_multithreaded_future = async move {
            tokio::task::spawn(kernel).await.map_err(|err| NetworkError::Generic(err.to_string()))?
        };

        let server = tokio::task::spawn(unsafe { AssertSendSafeFuture::new(thread_aware_server_future) });
        let res = kernel_multithreaded_future.await;
        /*
        let res = tokio::select! {
                res = kernel_multithreaded_future => res,
                res0 = thread_aware_server_future => res0
        };*/

        log::info!("DONE awaiting localset/multiset {:?}. Ensuring server shutdown ...", &res);
        remote.shutdown();

        if let Ok(Ok(Ok(()))) = tokio::time::timeout(Duration::from_millis(300), server).await {
            log::info!("Successfully shutdown HyperNode cleanly");
        }

        res
    }
}

impl From<Option<LocalSet>> for RuntimeHandler {
    fn from(inner: Option<LocalSet>) -> Self {
        Self { inner, server_future: None }
    }
}