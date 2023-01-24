use crate::shared::spawn::{BlockingSpawn, BlockingSpawnError};
pub use tokio::task::{spawn, spawn_local};

pub fn spawn_blocking<F, R>(f: F) -> BlockingSpawn<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let thread_handle = wasm_thread::spawn(f);
    BlockingSpawn::Wasm(Box::pin(async move {
        thread_handle
            .join_async()
            .await
            .map_err(|_| BlockingSpawnError {
                message: "Unable to async join the WASM thread".into(),
            })
    }))
}
