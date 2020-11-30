use crate::sec_string::SecString;

/// A memory-secure wrapper for shipping around Bytes
#[derive(Clone)]
pub struct SecBuffer {
    inner: Vec<u8>
}

impl SecBuffer {
    /// Creates a new SecBytes container
    pub fn new() -> Self {
        Self::from(Vec::new())
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