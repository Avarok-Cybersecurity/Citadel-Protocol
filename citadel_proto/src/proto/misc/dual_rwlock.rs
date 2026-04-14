//! Dual-Mode Read-Write Lock
//!
//! This module provides a read-write lock implementation that can operate in both
//! single-threaded and multi-threaded contexts. It automatically selects the
//! appropriate locking mechanism based on compile-time feature flags.
//!
//! # Features
//!
//! - Compile-time thread safety selection
//! - Multiple reader support
//! - Exclusive writer access
//! - Deadlock prevention
//! - Zero-cost abstraction
//!
//! # Important Notes
//!
//! - Uses RefCell in single-threaded mode
//! - Uses RwLock in multi-threaded mode
//! - No runtime overhead for thread safety
//! - Requires Send + Sync for multi-threaded use
//!
//! # Related Components
//!
//! - `dual_cell.rs`: Thread-safe cell
//! - `dual_late_init.rs`: Late initialization
//! - `lock_holder.rs`: Resource locking

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

#[cfg(feature = "multi-threaded")]
impl<T: ContextRequirements> DualRwLock<Option<T>> {
    #[allow(dead_code)]
    pub fn is_some(&self) -> bool {
        self.inner.read().is_some()
    }

    #[allow(dead_code)]
    pub fn is_none(&self) -> bool {
        self.inner.read().is_none()
    }

    /// Sets the value if it is currently None, otherwise returns the value that was passed to the function.
    pub fn atomic_set_if_none(&self, t: T) -> Option<T> {
        let mut inner = self.inner.write();
        if inner.is_none() {
            *inner = Some(t);
            None
        } else {
            Some(t)
        }
    }
}

#[cfg(not(feature = "multi-threaded"))]
impl<T: ContextRequirements> DualRwLock<Option<T>> {
    #[allow(dead_code)]
    pub fn is_some(&self) -> bool {
        self.inner.borrow().is_some()
    }

    #[allow(dead_code)]
    pub fn is_none(&self) -> bool {
        self.inner.borrow().is_none()
    }

    /// Sets the value if it is currently None, otherwise returns the value that was passed to the function.
    pub fn atomic_set_if_none(&self, t: T) -> Option<T> {
        let mut inner = self.inner.borrow_mut();
        if inner.is_none() {
            *inner = Some(t);
            None
        } else {
            Some(t)
        }
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
