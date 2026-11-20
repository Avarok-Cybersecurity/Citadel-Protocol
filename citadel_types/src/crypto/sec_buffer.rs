//! [`SecBuffer`]: bytes whose whole allocation is kept out of swap while held and wiped before
//! it is freed.
//!
//! Locking and wiping cover the allocation's full capacity, not just its length, since a buffer
//! that shrank still holds its old bytes. A buffer only ever grows through [`SecBuffer::reserve`],
//! which wipes the old allocation before freeing it. Pages are locked through a count shared by
//! every buffer (`utils::page_locks`), so one buffer releasing a page never unlocks a neighbour's.

use crate::utils;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

/// A memory-secure wrapper for shipping around Bytes
pub struct SecBuffer {
    inner: BytesMut,
}

/// Set once the OS first refuses to lock a buffer, so the refusal is reported once, not per buffer.
static LOCK_REFUSAL_REPORTED: AtomicBool = AtomicBool::new(false);

impl SecBuffer {
    /// Creates an empty buffer
    pub fn empty() -> Self {
        Self::with_capacity(0)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self::from(BytesMut::with_capacity(cap))
    }

    /// Returns the inner element without wiping it: the caller takes over its secrecy.
    pub fn into_buffer(mut self) -> BytesMut {
        self.unlock();
        std::mem::take(&mut self.inner)
    }

    /// For changing the contents. Growth goes through [`Self::reserve`].
    pub fn handle(&mut self) -> SecureBufMutHandle<'_> {
        SecureBufMutHandle { inner: self }
    }

    /// returns the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes the allocation spans, held or not.
    fn region(&self) -> (*const u8, usize) {
        (self.inner.as_ptr(), self.inner.capacity())
    }

    /// Locks the allocation's pages out of swap. When the OS refuses (past `RLIMIT_MEMLOCK`, or on
    /// a system that does not allow it), the buffer is used anyway: the refusal is logged once per
    /// process and the node carries on. This is the chosen behaviour, not a fallback: failing would
    /// take a node down over an OS limit, and the buffer is still wiped on every path.
    fn lock(&self) {
        let (ptr, capacity) = self.region();
        if let Err(code) = utils::mem::lock(ptr, capacity) {
            if !LOCK_REFUSAL_REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!(target: "citadel", "The OS refused to lock secret memory (error {code}); secrets may reach swap. Raise the memory-lock limit (RLIMIT_MEMLOCK) to keep them out.");
            }
        }
    }

    fn unlock(&self) {
        let (ptr, capacity) = self.region();
        utils::mem::unlock(ptr, capacity)
    }

    /// Wipes the whole allocation, including any bytes past the current length.
    fn wipe(&mut self) {
        let (ptr, capacity) = self.region();
        // SAFETY: `ptr..ptr + capacity` is the allocation this buffer uniquely owns.
        unsafe { utils::mem::zeroize(ptr, capacity) }
    }

    pub fn reserve(&mut self, additional: usize) {
        let required = self.inner.len().saturating_add(additional);
        if required <= self.inner.capacity() {
            // Sufficient capacity already; no reallocation, so no secrets can be left behind.
            return;
        }
        // Grow manually so the old, secret-bearing allocation is wiped BEFORE it is freed.
        // Delegating to BytesMut::reserve would reallocate and free the old buffer in the clear.
        //
        // Grow with amortized headroom (at least double the current capacity) rather than to the
        // exact size, so a sequence of incremental reservations stays amortized O(1).
        let new_capacity = required.max(self.inner.capacity().saturating_mul(2));
        let mut grown = BytesMut::with_capacity(new_capacity);
        grown.extend_from_slice(&self.inner[..]);
        self.unlock();
        self.wipe();
        self.inner = grown;
        self.lock();
    }
}

/// Mutable access to a [`SecBuffer`]. It can change bytes and the length, and it grows the
/// buffer only through [`SecBuffer::reserve`].
pub struct SecureBufMutHandle<'a> {
    inner: &'a mut SecBuffer,
}

impl SecureBufMutHandle<'_> {
    pub fn extend_from_slice(&mut self, extend: &[u8]) {
        self.inner.reserve(extend.len());
        self.inner.inner.extend_from_slice(extend);
    }

    pub fn put_bytes(&mut self, val: u8, count: usize) {
        self.inner.reserve(count);
        self.inner.inner.put_bytes(val, count);
    }

    /// Shortens the buffer. The bytes past the new length stay in the allocation until the
    /// buffer drops, which wipes them.
    pub fn truncate(&mut self, len: usize) {
        self.inner.inner.truncate(len);
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }
}

impl Deref for SecureBufMutHandle<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner.inner[..]
    }
}

impl DerefMut for SecureBufMutHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.inner[..]
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
        Self::from(BytesMut::from(Bytes::from(inner)))
    }
}

impl From<BytesMut> for SecBuffer {
    fn from(inner: BytesMut) -> Self {
        let this = Self { inner };
        this.lock();
        this
    }
}

impl From<Bytes> for SecBuffer {
    fn from(inner: Bytes) -> Self {
        // Zero-copy when the `Bytes` uniquely owns its allocation (e.g. came from a
        // `Vec`/`BytesMut`); otherwise reclaims by copying. Mirrors the `Vec<u8>` path.
        Self::from(BytesMut::from(inner))
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
        self.wipe();
    }
}

impl Debug for SecBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***SECRET***")
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for SecBuffer {
    fn eq(&self, other: &T) -> bool {
        // Constant time comparison to prevent timing attacks
        utils::const_time_compare(self.as_ref(), other.as_ref())
    }
}

impl Clone for SecBuffer {
    fn clone(&self) -> Self {
        SecBuffer::from(&self.inner[..])
    }
}

impl Serialize for SecBuffer {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
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

#[cfg(test)]
#[path = "sec_buffer_tests.rs"]
mod tests;
