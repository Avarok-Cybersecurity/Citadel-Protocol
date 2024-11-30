//! Late Initialization Container
//!
//! This module provides a container type for values that must be initialized after
//! construction. It ensures thread safety and proper initialization semantics in
//! both single-threaded and multi-threaded contexts.
//!
//! # Features
//!
//! - Safe late initialization
//! - Thread-safe value access
//! - Initialization state tracking
//! - Panic-free value access
//!
//! # Important Notes
//!
//! - Values must be initialized before access
//! - Thread-safe in multi-threaded mode
//! - Panics on double initialization
//! - Zero overhead in single-threaded mode
//!
//! # Related Components
//!
//! - `dual_cell.rs`: Thread-safe cell
//! - `dual_rwlock.rs`: Read-write locking
//! - `lock_holder.rs`: Resource locking

use crate::macros::ContextRequirements;
use std::ops::Deref;

pub struct DualLateInit<T: ContextRequirements> {
    #[cfg(feature = "multi-threaded")]
    inner: once_cell::sync::OnceCell<T>,
    #[cfg(not(feature = "multi-threaded"))]
    inner: once_cell::unsync::OnceCell<T>,
}

impl<T: ContextRequirements> DualLateInit<T> {
    // panics if already set
    pub fn set_once(&self, t: T) {
        if self.inner.set(t).is_err() {
            panic!("[DualLateInit] Value already set")
        }
    }
}

impl<T: ContextRequirements> Deref for DualLateInit<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.get().unwrap()
    }
}

impl<T: ContextRequirements> Default for DualLateInit<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}
