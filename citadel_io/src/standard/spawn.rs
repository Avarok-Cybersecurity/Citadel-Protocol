use crate::shared::spawn::BlockingSpawn;
pub use tokio::task::{spawn, spawn_local};

pub fn spawn_blocking<F, R>(f: F) -> BlockingSpawn<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    BlockingSpawn::Tokio(tokio::task::spawn_blocking(f))
}
