#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

pub mod shared;

#[cfg(target_family = "wasm")]
pub use wasm::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::{TcpListener, TcpStream, UdpSocket},
    spawn::{spawn, spawn_blocking, spawn_local},
};

#[cfg(not(target_family = "wasm"))]
pub use standard::{
    locks::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    spawn::{spawn, spawn_blocking, spawn_local},
};

pub use shared::spawn::{BlockingSpawn, BlockingSpawnError};

#[cfg(all(feature = "deadlock-detection", not(target_family = "wasm")))]
pub use parking_lot::deadlock;

#[cfg(not(target_family = "wasm"))]
pub use parking_lot::{const_mutex, const_rwlock};

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
}
