pub struct DualCell<T: Copy> {
    #[cfg(not(feature = "multi-threaded"))]
    inner: std::rc::Rc<std::cell::Cell<Option<T>>>,
    #[cfg(feature = "multi-threaded")]
    inner: std::sync::Arc<atomic::Atomic<Option<T>>>
}

impl<T: Copy> DualCell<T> {
    pub fn new(value: Option<T>) -> Self {
        Self::from(value)
    }

    pub fn set(&self, new: Option<T>) {
        #[cfg(not(feature = "multi-threaded"))]
            {
                let _ = self.inner.set(new);
            }
        #[cfg(feature = "multi-threaded")]
            {
                let _ = self.inner.swap(new, atomic::Ordering::SeqCst);
            }
    }

    pub fn get(&self) -> Option<T> {
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

impl<T: Copy> From<Option<T>> for DualCell<T> {
    fn from(inner: Option<T>) -> Self {
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

impl<T: Copy> Clone for DualCell<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T: Copy> Default for DualCell<T> {
    fn default() -> Self {
        Self::new(None)
    }
}