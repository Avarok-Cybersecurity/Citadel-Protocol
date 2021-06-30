use crate::macros::ContextRequirements;

pub struct DualCell<T: ContextRequirements> {
    #[cfg(not(feature = "multi-threaded"))]
    inner: std::rc::Rc<std::cell::Cell<T>>,
    #[cfg(feature = "multi-threaded")]
    inner: std::sync::Arc<atomic::Atomic<T>>
}

impl<T: ContextRequirements> DualCell<T> {
    pub fn new(value: T) -> Self {
        Self::from(value)
    }

    pub fn set(&self, new: T) where T: Copy {
        #[cfg(not(feature = "multi-threaded"))]
            {
                let _ = self.inner.set(new);
            }
        #[cfg(feature = "multi-threaded")]
            {
                let _ = self.inner.swap(new, atomic::Ordering::SeqCst);
            }
    }

    pub fn get(&self) -> T where T: Copy {
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
                Self { inner: std::rc::Rc::new(std::cell::Cell::new(inner)) }
            }
        #[cfg(feature = "multi-threaded")]
            {
                Self { inner: std::sync::Arc::new(atomic::Atomic::new(inner)) }
            }
    }
}

impl<T: ContextRequirements> Clone for DualCell<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}