//! Dual-Mode Cell Implementation
//!
//! This module provides a thread-safe cell type that can operate in both single-threaded
//! and multi-threaded contexts. It automatically selects the appropriate implementation
//! based on compile-time feature flags.
//!
//! # Features
//!
//! - Compile-time thread safety selection
//! - Interior mutability
//! - Zero-cost abstraction
//! - Automatic feature detection
//!
//! # Important Notes
//!
//! - Uses std::cell::Cell in single-threaded mode
//! - Uses atomic types in multi-threaded mode
//! - No runtime overhead for thread safety checks
//! - Requires Send + Sync for multi-threaded use
//!
//! # Related Components
//!
//! - `dual_rwlock.rs`: Read-write lock implementation
//! - `dual_late_init.rs`: Late initialization
//! - `lock_holder.rs`: Resource locking

use crate::macros::ContextRequirements;
use bytemuck::NoUninit;

pub struct DualCell<T: ContextRequirements> {
    #[cfg(not(feature = "multi-threaded"))]
    inner: std::rc::Rc<std::cell::Cell<T>>,
    #[cfg(feature = "multi-threaded")]
    inner: std::sync::Arc<atomic::Atomic<T>>,
}

impl<T: ContextRequirements> DualCell<T> {
    pub fn set(&self, new: T)
    where
        T: Copy + NoUninit,
    {
        #[cfg(not(feature = "multi-threaded"))]
        {
            self.inner.set(new);
        }
        #[cfg(feature = "multi-threaded")]
        {
            let _ = self.inner.swap(new, atomic::Ordering::SeqCst);
        }
    }

    pub fn get(&self) -> T
    where
        T: Copy + NoUninit,
    {
        #[cfg(not(feature = "multi-threaded"))]
        {
            self.inner.get()
        }
        #[cfg(feature = "multi-threaded")]
        {
            self.inner.load(atomic::Ordering::SeqCst)
        }
    }
}

impl<T: ContextRequirements> From<T> for DualCell<T> {
    fn from(inner: T) -> Self {
        #[cfg(not(feature = "multi-threaded"))]
        {
            Self {
                inner: std::rc::Rc::new(std::cell::Cell::new(inner)),
            }
        }
        #[cfg(feature = "multi-threaded")]
        {
            Self {
                inner: std::sync::Arc::new(atomic::Atomic::new(inner)),
            }
        }
    }
}

impl<T: ContextRequirements> Clone for DualCell<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
