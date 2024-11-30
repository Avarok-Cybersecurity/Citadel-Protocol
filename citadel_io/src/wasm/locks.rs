//! WebAssembly-compatible synchronization primitives.
//!
//! This module provides synchronization primitives that work in WebAssembly environments
//! by wrapping the standard library's implementations. While WebAssembly is single-threaded,
//! these primitives are still useful for maintaining API compatibility with native code
//! and for potential future multi-threading support.

/// Type alias for WebAssembly-compatible RwLock implementation
pub type RwLock<T> = RwLockWasm<T>;
/// Type alias for WebAssembly-compatible read guard
pub type RwLockReadGuard<'a, T> = std::sync::RwLockReadGuard<'a, T>;
/// Type alias for WebAssembly-compatible write guard
pub type RwLockWriteGuard<'a, T> = std::sync::RwLockWriteGuard<'a, T>;

/// Type alias for WebAssembly-compatible Mutex implementation
pub type Mutex<T> = MutexWasm<T>;
/// Type alias for WebAssembly-compatible mutex guard
pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;

/// A WebAssembly-compatible reader-writer lock implementation.
///
/// This type wraps the standard library's RwLock to provide a WebAssembly-safe
/// synchronization primitive. While WebAssembly is currently single-threaded,
/// this implementation maintains API compatibility with native code.
#[derive(Default)]
pub struct RwLockWasm<T> {
    inner: std::sync::RwLock<T>,
}

/// A WebAssembly-compatible mutex implementation.
///
/// This type wraps the standard library's Mutex to provide a WebAssembly-safe
/// synchronization primitive. While WebAssembly is currently single-threaded,
/// this implementation maintains API compatibility with native code.
#[derive(Default)]
pub struct MutexWasm<T> {
    inner: std::sync::Mutex<T>,
}

impl<T> RwLockWasm<T> {
    /// Creates a new RwLock in an unlocked state ready for use.
    pub fn new(t: T) -> Self {
        Self {
            inner: std::sync::RwLock::new(t),
        }
    }

    /// Acquires a read lock, blocking the current thread until it is available.
    ///
    /// The lock will be automatically released when the returned guard is dropped.
    /// Since WebAssembly is single-threaded, this will never actually block.
    pub fn read(&self) -> RwLockReadGuard<T> {
        self.inner.read().unwrap()
    }

    /// Acquires a write lock, blocking the current thread until it is available.
    ///
    /// The lock will be automatically released when the returned guard is dropped.
    /// Since WebAssembly is single-threaded, this will never actually block.
    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.inner.write().unwrap()
    }
}

impl<T> MutexWasm<T> {
    /// Creates a new Mutex in an unlocked state ready for use.
    pub fn new(t: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(t),
        }
    }

    /// Acquires a mutex, blocking the current thread until it is available.
    ///
    /// The lock will be automatically released when the returned guard is dropped.
    /// Since WebAssembly is single-threaded, this will never actually block.
    pub fn lock(&self) -> MutexGuard<T> {
        self.inner.lock().unwrap()
    }
}
