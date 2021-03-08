use crate::sec_string::SecString;
use std::fmt::Debug;
use std::fmt::Formatter;
use serde::{Serialize, Serializer, Deserialize, Deserializer};

/// A memory-secure wrapper for shipping around Bytes
pub struct SecBuffer {
    inner: Vec<u8>
}

impl SecBuffer {
    /// Creates a new SecBytes container
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Creates an unlocked, empty buffer
    pub fn empty() -> Self {
        Self { inner: Vec::with_capacity(0) }
    }

    /// Returns the inner element without dropping the memory
    pub fn into_buffer(mut self) -> Vec<u8> {
        self.unlock();
        std::mem::take(&mut self.inner)
    }

    /// returns the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn lock(&self) {
        unsafe { crate::misc::mlock(self.inner.as_ptr(), self.inner.len()) }
    }

    fn unlock(&self) {
        unsafe { crate::misc::munlock(self.inner.as_ptr(), self.inner.len()) }
    }

    fn zeroize(&mut self) {
        unsafe { crate::misc::zeroize(self.inner.as_ptr(), self.inner.len()) }
    }
}

impl AsRef<[u8]> for SecBuffer {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<T: Into<Vec<u8>>> From<T> for SecBuffer {
    fn from(inner: T) -> Self {
        let this = Self { inner: inner.into() };
        this.lock();
        this
    }
}

impl From<SecString> for SecBuffer {
    fn from(inner: SecString) -> Self {
        Self::from(inner.into_buffer().into_bytes())
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
        SecBuffer::from(self.as_ref())
    }
}

impl Serialize for SecBuffer {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for SecBuffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        Ok(Self::from(Vec::deserialize(deserializer)?))
    }
}