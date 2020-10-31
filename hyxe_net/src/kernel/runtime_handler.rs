use tokio::task::LocalSet;
use futures::Future;
use crate::error::NetworkError;

pub struct RuntimeHandler {
    inner: Option<LocalSet>
}


impl RuntimeHandler {
    #[allow(unused_results)]
    /// Panics if not configured properly in crate::macros::*
    pub fn spawn<F>(&self, future: F) where F: Future + 'static, <F as Future>::Output: 'static {
        let local_set = self.inner.as_ref().unwrap();
        local_set.spawn_local(future);
    }

    #[allow(unused_results)]
    /// Panics if not configured properly in crate::macros::*
    pub fn spawn_multi<F>(&self, future: F) where F: Future + Send + 'static, <F as Future>::Output: Send + 'static {
        assert!(self.inner.is_none());
        tokio::task::spawn(future);
    }

    #[allow(unused_results)]
    pub async fn execute_kernel<F>(mut self, kernel: F) -> Result<(), NetworkError> where F: Future + Send + 'static, <F as Future>::Output: Send + 'static{
        if let Some(local_set) = self.inner.take() {
            // spawn kernel on multi-threaded context
            tokio::task::spawn(kernel);
            local_set.await;
            Ok(())
        } else {
            tokio::task::spawn(kernel).await.map_err(|err| NetworkError::Generic(err.to_string()))
                .map(|_| ())
        }
    }
}

impl From<Option<LocalSet>> for RuntimeHandler {
    fn from(inner: Option<LocalSet>) -> Self {
        Self { inner }
    }
}