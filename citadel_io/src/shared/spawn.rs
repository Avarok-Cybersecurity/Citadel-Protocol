use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct BlockingSpawnError {
    pub message: String,
}

pub enum BlockingSpawn<T> {
    Tokio(tokio::task::JoinHandle<T>),
    Wasm(Pin<Box<dyn Future<Output = Result<T, BlockingSpawnError>> + Send + 'static>>),
}

impl<T> Future for BlockingSpawn<T> {
    type Output = Result<T, BlockingSpawnError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            BlockingSpawn::Tokio(handle) => {
                Pin::new(handle).poll(cx).map_err(|err| BlockingSpawnError {
                    message: err.to_string(),
                })
            }
            BlockingSpawn::Wasm(future) => future.as_mut().poll(cx),
        }
    }
}
