use crate::shared::spawn::BlockingSpawn;
pub use tokio::task::{spawn, spawn_local};

pub fn spawn_blocking<F, R>(_f: F) -> BlockingSpawn<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    panic!("Multi-threaded support not enabled on WASM (yet)")
}
