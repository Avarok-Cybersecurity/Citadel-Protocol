#![allow(dead_code)]
use std::marker::PhantomData;

pub struct LockHolder<'a, T: 'a> {
    inner: Option<T>,
    _pd: PhantomData<&'a ()>,
}

impl<'a, T: 'a> LockHolder<'a, T> {
    pub fn new(inner: Option<T>) -> Self {
        Self {
            inner,
            _pd: Default::default(),
        }
    }

    /// Accesses the inner value. If not available, will get the inner value through `or_else`
    pub fn access_or_else<J>(
        &self,
        or_else: impl FnOnce() -> T,
        accessor: impl for<'z> FnOnce(&'z T) -> J,
    ) -> J {
        if let Some(ref t) = self.inner {
            accessor(t)
        } else {
            accessor(&or_else())
        }
    }

    /// Accesses the inner value. If not available, will get the inner value through `or_else`
    pub fn access_mut_or_else<J>(
        &mut self,
        or_else: impl FnOnce() -> T,
        accessor: impl for<'z> FnOnce(&'z mut T) -> J,
    ) -> J {
        if let Some(ref mut t) = self.inner {
            accessor(t)
        } else {
            accessor(&mut or_else())
        }
    }

    /// Accesses the inner value. If not available, will get the inner value through `or_else`
    pub fn access_consume_or_else<J>(
        self,
        or_else: impl FnOnce() -> T,
        accessor: impl FnOnce(T) -> J,
    ) -> J {
        if let Some(t) = self.inner {
            accessor(t)
        } else {
            accessor(or_else())
        }
    }

    /// Accesses the inner value. If not available, will get the inner value through `or_else`
    pub fn maybe_access_consume_or_else<J>(
        self,
        condition: bool,
        or_else: impl FnOnce() -> T,
        accessor: impl FnOnce(Option<T>) -> J,
    ) -> J {
        if condition {
            if let Some(t) = self.inner {
                accessor(Some(t))
            } else {
                accessor(Some(or_else()))
            }
        } else {
            accessor(None)
        }
    }

    pub fn get_ref(&self) -> LockHolder<'_, &'_ T> {
        LockHolder::new(self.inner.as_ref())
    }

    pub fn map<U: 'a, F: FnOnce(&'a T) -> U>(&'a self, transform: F) -> LockHolder<'a, U> {
        LockHolder::new(self.inner.as_ref().map(transform))
    }
}

impl<T> From<T> for LockHolder<'_, T> {
    fn from(inner: T) -> Self {
        Self::new(Some(inner))
    }
}

impl<T> Default for LockHolder<'_, T> {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod test {
    use crate::proto::misc::lock_holder::LockHolder;
    use citadel_io::{Mutex, MutexGuard};
    /*
    fn accessor(t: &u8) -> u8 {
        t.wrapping_add(1)
    }*/

    fn accessor2(t: &u8) -> u8 {
        t.wrapping_add(2)
    }

    #[test]
    fn reborrow() {
        /*
        let container = Reborrow::new(Some(100));
        assert_eq!(container.access_or_else(accessor, || 0), 101);

        let container2 = Reborrow::new(None);
        assert_eq!(container2.access_or_else(accessor, || 0), 1);*/
        let mutex = Mutex::new(150u8);
        let mut container3 = LockHolder::<MutexGuard<u8>>::new(None);
        assert_eq!(
            container3.access_mut_or_else(|| mutex.lock(), |r| accessor2(r)),
            152
        );

        let mutex = Mutex::new(150u8);

        let mut container3 = LockHolder::new(Some(mutex.lock()));
        let out = container3.access_mut_or_else(|| mutex.lock(), |r| accessor2(r));
        assert_eq!(out, 152);
    }
}
