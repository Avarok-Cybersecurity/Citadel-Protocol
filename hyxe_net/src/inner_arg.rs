use std::ops::{Deref, DerefMut};
use hyxe_user::re_imports::export::PhantomData;

pub struct InnerParameterMut<'a, T: 'a, K> {
    inner: &'a mut T,
    _pd: PhantomData<K>
}

pub trait ExpectedInnerTargetMut<K> where Self: Deref<Target=K>, Self: DerefMut<Target=K> {}

impl<K, T> ExpectedInnerTargetMut<K> for T where T: Deref<Target=K>, T: DerefMut<Target=K> {}


impl<'a, T: 'a, K> From<&'a mut T> for InnerParameterMut<'a, T, K> where T: Deref<Target=K>, T: DerefMut<Target=K> {
    fn from(inner: &'a mut T) -> Self {
        Self { inner, _pd: Default::default() }
    }
}

impl<'a, T: 'a, K> Deref for InnerParameterMut<'a, T, K> where T: Deref<Target=K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<'a, T: 'a, K> DerefMut for InnerParameterMut<'a, T, K> where T: DerefMut<Target=K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut()
    }
}

/*
    immutable version of above
*/

pub struct InnerParameter<'a, T: 'a + ?Sized, K> {
    inner: &'a T,
    _pd: PhantomData<K>
}

pub trait ExpectedInnerTarget<K> where Self: Deref<Target=K> {}

impl<K, T> ExpectedInnerTarget<K> for T where T: Deref<Target=K> {}


impl<'a, T: 'a, K> From<&'a T> for InnerParameter<'a, T, K> where T: Deref<Target=K> {
    fn from(inner: &'a T) -> Self {
        Self { inner, _pd: Default::default() }
    }
}

impl<'a, T: 'a, K> Deref for InnerParameter<'a, T, K> where T: Deref<Target=K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}