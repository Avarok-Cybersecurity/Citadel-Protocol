use std::ops::Deref;
use crate::macros::ContextRequirements;

pub struct DualLateInit<T: ContextRequirements> {
    #[cfg(feature = "multi-threaded")]
    inner: once_cell::sync::OnceCell<T>,
    #[cfg(not(feature = "multi-threaded"))]
    inner: once_cell::unsync::OnceCell<T>
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
        Self { inner: Default::default() }
    }
}