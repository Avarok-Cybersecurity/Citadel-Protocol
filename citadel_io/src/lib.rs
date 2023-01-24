#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

pub mod shared;

#[cfg(target_family = "wasm")]
pub use wasm::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::UdpSocket,
    spawn::{spawn, spawn_blocking, spawn_local},
};

#[cfg(not(target_family = "wasm"))]
pub use standard::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::UdpSocket,
    spawn::{spawn, spawn_blocking, spawn_local},
};

pub use shared::spawn::{BlockingSpawn, BlockingSpawnError};

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
}
