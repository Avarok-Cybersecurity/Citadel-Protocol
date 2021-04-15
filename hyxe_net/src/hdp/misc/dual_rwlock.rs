use crate::macros::ContextRequirements;
use std::ops::Deref;

#[cfg(not(feature = "multi-threaded"))]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: std::cell::RefCell<T>
}

#[cfg(feature = "multi-threaded")]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: parking_lot::RwLock<T>
}

impl<T: ContextRequirements> DualRwLock<T> {
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: ContextRequirements> From<T> for DualRwLock<T> {
    fn from(inner: T) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
        {
            Self { inner: std::cell::RefCell::new(inner) }
        }

        #[cfg(feature = "multi-threaded")]
        {
            Self { inner: parking_lot::RwLock::new(inner) }
        }
    }
}

impl<T: ContextRequirements> Deref for DualRwLock<T> {
    #[cfg(feature = "multi-threaded")]
    type Target = parking_lot::RwLock<T>;
    #[cfg(not(feature = "multi-threaded"))]
    type Target = std::cell::RefCell<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}