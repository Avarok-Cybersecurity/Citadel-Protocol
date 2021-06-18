use crate::macros::ContextRequirements;
use std::ops::Deref;

#[cfg(not(feature = "multi-threaded"))]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: std::rc::Rc<std::cell::RefCell<T>>
}

#[cfg(feature = "multi-threaded")]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: std::sync::Arc<parking_lot::RwLock<T>>
}

impl<T: ContextRequirements> From<T> for DualRwLock<T> {
    fn from(inner: T) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
        {
            Self { inner: std::rc::Rc::new(std::cell::RefCell::new(inner)) }
        }

        #[cfg(feature = "multi-threaded")]
        {
            Self { inner: std::sync::Arc::new(parking_lot::RwLock::new(inner)) }
        }
    }
}

impl<T: ContextRequirements> Deref for DualRwLock<T> {
    #[cfg(feature = "multi-threaded")]
    type Target = parking_lot::RwLock<T>;
    #[cfg(not(feature = "multi-threaded"))]
    type Target = std::cell::RefCell<T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: ContextRequirements> Clone for DualRwLock<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}