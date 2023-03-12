use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;
use std::fmt::{Debug, Display};
use std::ops::Deref;
use zeroize::Zeroizing;

/// Allows mutable access
pub struct SecString {
    inner: Zeroizing<String>,
}

impl SecString {
    /// Creates a new instance SecString
    pub fn new() -> Self {
        Self {
            inner: Zeroizing::new(String::new()),
        }
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
}

impl<T: Into<String>> From<T> for SecString {
    fn from(inner: T) -> Self {
        let this = Self {
            inner: inner.into().into(),
        };
        this.lock();
        this
    }
}

impl Drop for SecString {
    fn drop(&mut self) {
        self.unlock();
    }
}

impl Clone for SecString {
    fn clone(&self) -> Self {
        self.unlock();
        let ret = Self::from(self.inner.to_string());
        self.unlock();
        ret
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

impl Serialize for SecString {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        self.unlock();
        let res = serializer.serialize_bytes(self.as_ref());
        self.lock();
        res
    }
}

impl<'de> Deserialize<'de> for SecString {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from(String::deserialize(deserializer)?))
    }
}
