pub type Mutex<T> = parking_lot::Mutex<T>;
pub type MutexGuard<'a, T> = parking_lot::MutexGuard<'a, T>;
pub type RwLock<T> = parking_lot::RwLock<T>;
pub type RwLockReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;
pub type RwLockWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;
