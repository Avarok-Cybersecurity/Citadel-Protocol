use crate::secure_buffer::sec_string::SecString;
use bytes::BytesMut;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::{Deref, DerefMut};

/// A memory-secure wrapper for shipping around Bytes
pub struct SecBuffer {
    inner: BytesMut,
}

impl SecBuffer {
    /// Creates an unlocked, empty buffer
    pub fn empty() -> Self {
        Self::with_capacity(0)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self::from(BytesMut::with_capacity(cap))
    }

    /// Returns the inner element without dropping the memory
    pub fn into_buffer(mut self) -> BytesMut {
        self.unlock();
        std::mem::take(&mut self.inner)
    }

    /// For accessing the inner element
    pub fn handle(&mut self) -> SecureBufMutHandle {
        SecureBufMutHandle::new(self)
    }

    /// returns the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn lock(&self) {
        unsafe { crate::misc::mlock(self.slice().as_ptr(), self.inner.len()) }
    }

    fn unlock(&self) {
        unsafe { crate::misc::munlock(self.slice().as_ptr(), self.inner.len()) }
    }

    fn zeroize(&mut self) {
        unsafe { crate::misc::zeroize(self.slice().as_ptr(), self.inner.len()) }
    }

    fn slice(&self) -> &[u8] {
        &self.inner[..]
    }
}

pub struct SecureBufMutHandle<'a> {
    inner: &'a mut SecBuffer,
}

impl<'a> SecureBufMutHandle<'a> {
    fn new(inner: &'a mut SecBuffer) -> SecureBufMutHandle<'a> {
        inner.unlock();
        Self { inner }
    }
}

impl Deref for SecureBufMutHandle<'_> {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.inner.inner
    }
}

impl DerefMut for SecureBufMutHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.inner
    }
}

impl Drop for SecureBufMutHandle<'_> {
    fn drop(&mut self) {
        self.inner.lock()
    }
}

impl AsRef<[u8]> for SecBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..]
    }
}

impl AsMut<[u8]> for SecBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl From<Vec<u8>> for SecBuffer {
    fn from(inner: Vec<u8>) -> Self {
        Self::from(&inner[..])
    }
}

impl From<SecString> for SecBuffer {
    fn from(inner: SecString) -> Self {
        Self::from(inner.into_buffer().into_bytes())
    }
}

impl From<BytesMut> for SecBuffer {
    fn from(inner: BytesMut) -> Self {
        let this = Self { inner };
        this.lock();
        this
    }
}

impl<const N: usize> From<[u8; N]> for SecBuffer {
    fn from(this: [u8; N]) -> Self {
        Self::from(&this as &[u8])
    }
}

impl From<&[u8]> for SecBuffer {
    fn from(this: &[u8]) -> Self {
        Self::from(BytesMut::from(this))
    }
}

impl From<&str> for SecBuffer {
    fn from(this: &str) -> Self {
        Self::from(BytesMut::from(this))
    }
}

impl Drop for SecBuffer {
    fn drop(&mut self) {
        self.unlock();
        self.zeroize();
    }
}

impl Debug for SecBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***SECRET***")
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for SecBuffer {
    fn eq(&self, other: &T) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Clone for SecBuffer {
    fn clone(&self) -> Self {
        self.unlock();
        let ret = SecBuffer::from(self.inner.clone());
        self.lock();
        ret
    }
}

impl Serialize for SecBuffer {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        self.unlock();
        let ret = self.inner.serialize(serializer);
        self.lock();
        ret
    }
}

impl<'de> Deserialize<'de> for SecBuffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from(BytesMut::deserialize(deserializer)?))
    }
}
