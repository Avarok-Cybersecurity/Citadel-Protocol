use std::ops::Deref;
use std::fmt::{Debug, Display};
use serde::export::Formatter;

/// Allows mutable access
pub struct SecString {
    inner: String
}

impl SecString {
    /// Creates a new instance SecString
    pub fn new() -> Self {
        Self::from(String::new())
    }

    /// Safely pushes a new character
    pub fn push(&mut self, val: char) {
        self.unlock();
        self.inner.push(val);
        self.lock();
    }

    /// Clears and zeroizes the vector. Keeps the allocation in-tact
    pub fn clear(&mut self) {
        self.unlock();
        self.zeroize();
        self.inner.clear();
        self.lock();
    }

    /// Inserts a char at `pos`
    pub fn insert(&mut self, pos: usize, val: char) {
        self.unlock();
        self.inner.insert(pos, val);
        self.lock();
    }

    /// removes a char at `pos`
    pub fn remove(&mut self, pos: usize) -> char {
        self.unlock();
        let val = self.inner.remove(pos);
        self.lock();
        val
    }

    /// Gets the inner string
    pub fn into_buffer(mut self) -> String {
        self.unlock();
        std::mem::take(&mut self.inner)
    }

    fn lock(&self) {
        let (ptr, len) = decompose(&self.inner);
        unsafe { crate::misc::mlock(ptr, len) }
    }

    fn unlock(&self) {
        let (ptr, len) = decompose(&self.inner);
        unsafe { crate::misc::munlock(ptr, len) }
    }

    fn zeroize(&mut self) {
        unsafe { crate::misc::zeroize(self.inner.as_ptr(), self.inner.len()) }
    }
}

impl From<String> for SecString {
    fn from(inner: String) -> Self {
        let this = Self { inner };
        this.lock();
        this
    }
}

impl Drop for SecString {
    fn drop(&mut self) {
        self.unlock();
        self.zeroize();
    }
}

impl Clone for SecString {
    fn clone(&self) -> Self {
        Self::from(self.inner.clone())
    }
}

impl Default for SecString {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SecString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for SecString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***SECRET***")
    }
}

impl Display for SecString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

fn decompose(input: &String) -> (*const u8, usize) {
    let ptr = input.as_ptr();
    let len = input.capacity();
    (ptr, len)
}