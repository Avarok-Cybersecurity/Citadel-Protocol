//! Native platform synchronization primitives using parking_lot.
//!
//! This module provides high-performance synchronization primitives for native platforms
//! by re-exporting parking_lot's implementations. These primitives are more efficient
//! than the standard library's synchronization types.

/// A mutual exclusion primitive useful for protecting shared data.
/// Re-exported from parking_lot for better performance.
pub type Mutex<T> = parking_lot::Mutex<T>;

/// RAII guard for a mutex. The data protected by the mutex can be accessed
/// through this guard. The lock is automatically released when the guard is dropped.
pub type MutexGuard<'a, T> = parking_lot::MutexGuard<'a, T>;

/// A reader-writer lock, allowing multiple readers or a single writer at any point in time.
/// Re-exported from parking_lot for better performance.
pub type RwLock<T> = parking_lot::RwLock<T>;

/// RAII guard for read access to an RwLock. Multiple read guards can exist at the same time.
pub type RwLockReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;

/// RAII guard for write access to an RwLock. Only one write guard can exist at a time.
pub type RwLockWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;
