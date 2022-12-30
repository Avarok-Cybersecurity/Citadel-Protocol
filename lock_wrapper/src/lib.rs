//! A wrapper crate that uses parking_lot when using std, and, a std-mutex when using wasm
#[cfg(not(feature = "wasm"))]
pub type RwLock<T> = parking_lot::RwLock<T>;
#[cfg(not(feature = "wasm"))]
pub type RwLockReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;
#[cfg(not(feature = "wasm"))]
pub type RwLockWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;

#[cfg(feature = "wasm")]
pub type RwLock<T> = RwLockWasm<T>;
#[cfg(feature = "wasm")]
pub type RwLockReadGuard<'a, T> = std::sync::RwLockReadGuard<'a, T>;
#[cfg(feature = "wasm")]
pub type RwLockWriteGuard<'a, T> = std::sync::RwLockWriteGuard<'a, T>;

#[cfg(not(feature = "wasm"))]
pub type Mutex<T> = parking_lot::Mutex<T>;
#[cfg(not(feature = "wasm"))]
pub type MutexGuard<'a, T> = parking_lot::MutexGuard<'a, T>;

#[cfg(feature = "wasm")]
pub type Mutex<T> = MutexWasm<T>;
#[cfg(feature = "wasm")]
pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;

#[cfg(feature = "wasm")]
pub struct RwLockWasm<T> {
    inner: std::sync::RwLock<T>,
}

#[cfg(feature = "wasm")]
pub struct MutexWasm<T> {
    inner: std::sync::Mutex<T>,
}

#[cfg(feature = "wasm")]
impl<T> RwLockWasm<T> {
    pub fn new(t: T) -> Self {
        Self {
            inner: std::sync::RwLock::new(t),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<T> {
        self.inner.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.inner.write().unwrap()
    }
}

#[cfg(feature = "wasm")]
impl<T> MutexWasm<T> {
    pub fn new(t: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(t),
        }
    }

    pub fn lock(&self) -> MutexGuard<T> {
        self.inner.lock().unwrap()
    }
}
