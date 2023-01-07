#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(target_family = "wasm")]
pub use wasm::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::UdpSocket,
};

#[cfg(not(target_family = "wasm"))]
pub use standard::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::UdpSocket,
};

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
}
