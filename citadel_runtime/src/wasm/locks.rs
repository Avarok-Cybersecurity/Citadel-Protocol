pub type RwLock<T> = RwLockWasm<T>;
pub type RwLockReadGuard<'a, T> = std::sync::RwLockReadGuard<'a, T>;
pub type RwLockWriteGuard<'a, T> = std::sync::RwLockWriteGuard<'a, T>;

pub type Mutex<T> = MutexWasm<T>;
pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;

pub struct RwLockWasm<T> {
    inner: std::sync::RwLock<T>,
}

pub struct MutexWasm<T> {
    inner: std::sync::Mutex<T>,
}

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
