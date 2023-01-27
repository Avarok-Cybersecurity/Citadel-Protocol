use crate::macros::{ContextRequirements, WeakBorrowType};
use std::ops::Deref;

#[cfg(not(feature = "multi-threaded"))]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: std::rc::Rc<std::cell::RefCell<T>>,
}

#[cfg(feature = "multi-threaded")]
pub struct DualRwLock<T: ContextRequirements> {
    pub inner: std::sync::Arc<citadel_io::RwLock<T>>,
}

impl<T: ContextRequirements> DualRwLock<T> {
    #[cfg(feature = "multi-threaded")]
    #[allow(dead_code)]
    pub fn as_weak(&self) -> WeakBorrowType<T> {
        std::sync::Arc::downgrade(&self.inner)
    }

    #[cfg(not(feature = "multi-threaded"))]
    #[allow(dead_code)]
    pub fn as_weak(&self) -> WeakBorrowType<T> {
        std::rc::Rc::downgrade(&self.inner)
    }

    #[allow(dead_code)]
    pub fn upgrade(this: &WeakBorrowType<T>) -> Option<DualRwLock<T>> {
        this.upgrade().map(|inner| Self { inner })
    }

    pub fn get(&self) -> T
    where
        T: Clone,
    {
        inner!(self).clone()
    }

    pub fn set(&self, t: T) {
        *inner_mut!(self) = t;
    }

    #[allow(dead_code)]
    pub fn take(&self) -> T
    where
        T: Default,
    {
        std::mem::take(&mut *inner_mut!(self))
    }
}

impl<T: ContextRequirements> From<T> for DualRwLock<T> {
    fn from(inner: T) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
        {
            Self {
                inner: std::rc::Rc::new(std::cell::RefCell::new(inner)),
            }
        }

        #[cfg(feature = "multi-threaded")]
        {
            Self {
                inner: std::sync::Arc::new(citadel_io::RwLock::new(inner)),
            }
        }
    }
}

impl<T: ContextRequirements> Deref for DualRwLock<T> {
    #[cfg(feature = "multi-threaded")]
    type Target = citadel_io::RwLock<T>;
    #[cfg(not(feature = "multi-threaded"))]
    type Target = std::cell::RefCell<T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: ContextRequirements> Clone for DualRwLock<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
