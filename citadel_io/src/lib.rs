#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(target_family = "wasm")]
pub use wasm::locks::*;

#[cfg(not(target_family = "wasm"))]
pub use standard::locks::*;

#[cfg(all(feature = "deadlock-detection", not(target_family = "wasm")))]
pub use parking_lot::deadlock;

#[cfg(not(target_family = "wasm"))]
pub use parking_lot::{const_mutex, const_rwlock};

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
}

#[cfg(not(target_family = "wasm"))]
pub use tokio;

#[cfg(target_family = "wasm")]
pub use tokio_wasm as tokio;

#[cfg(not(target_family = "wasm"))]
pub use tokio_util;

#[cfg(target_family = "wasm")]
pub use tokio_util_wasm as tokio_util;

#[cfg(not(target_family = "wasm"))]
pub use tokio_stream;

#[cfg(target_family = "wasm")]
pub use tokio_stream_wasm as tokio_stream;
