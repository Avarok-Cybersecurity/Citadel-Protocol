//! In-place buffer operations with window-based access control.
//!
//! This module provides utilities for performing memory-efficient and secure
//! in-place buffer operations. It features:
//!
//! - Window-based buffer access control
//! - Zero-copy buffer manipulation
//! - Support for both `Vec<u8>` and `BytesMut` types
//! - Memory-safe buffer operations
//!
//! # Examples
//!
//! ```
//! use citadel_pqcrypto::bytes_in_place::{InPlaceBuffer, EzBuffer};
//! use aes_gcm::aead::Buffer;
//!
//! // Create a buffer with window-based access
//! let mut data = vec![0u8; 32];
//! let window = 0..16;
//! let mut buffer = InPlaceBuffer::new(&mut data, window).unwrap();
//!
//! // Perform operations only on the windowed portion
//! Buffer::extend_from_slice(&mut buffer, &[1, 2, 3]).unwrap();
//!
//! // Use EzBuffer trait for efficient operations
//! let mut buf = vec![0u8; 32];
//! let second_half = buf.split_off(16);
//! ```
//!
//! # Security Considerations
//!
//! - All buffer operations are bounds-checked
//! - Window-based access prevents buffer overflow
//! - In-place operations minimize data copying
//! - Memory is properly managed to prevent leaks
use std::ops::Range;

use aes_gcm::aead::{Buffer, Error as AesError};
use bytes::{BufMut, BytesMut};
use citadel_types::errors::Error;

pub struct InPlaceBuffer<'a, T> {
    inner: &'a mut T,
    window: Range<usize>,
}

impl<'a, T: EzBuffer> InPlaceBuffer<'a, T> {
    /// `window`: agnostic to the length. The window may be greater than the length, but MUST be less than the capacity
    pub fn new<'b: 'a>(inner: &'b mut T, window: Range<usize>) -> Option<InPlaceBuffer<'a, T>> {
        if window.end > inner.capacity() {
            None
        } else {
            Some(Self { inner, window })
        }
    }
}

impl<T: EzBuffer> Buffer for InPlaceBuffer<'_, T> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), AesError> {
        let start = self.window.start;
        let new_end = self.window.end + other.len();
        self.window = start..new_end;
        self.inner.extend_from_slice(other).map_err(|_| AesError)?;
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        let start = self.window.start;
        self.window = start..len;
        self.inner.truncate(len);
    }
}

impl<T: EzBuffer> AsMut<[u8]> for InPlaceBuffer<'_, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[self.window.clone()]
    }
}

impl<T: EzBuffer> AsRef<[u8]> for InPlaceBuffer<'_, T> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.as_ref()[self.window.clone()]
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait EzBuffer: AsRef<[u8]> + AsMut<[u8]> + BufMut {
    fn len(&self) -> usize;
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error>;
    fn truncate(&mut self, len: usize);
    fn capacity(&self) -> usize;
    fn split_off(&mut self, idx: usize) -> Self;
    fn unsplit(&mut self, other: Self);
    fn split_to(&mut self, idx: usize) -> Self;

    fn subset(&self, range: Range<usize>) -> &[u8] {
        &self.as_ref()[range]
    }
    fn subset_mut(&mut self, range: Range<usize>) -> &mut [u8] {
        &mut self.as_mut()[range]
    }

    fn try_truncate(&mut self, len: usize) -> Result<(), Error> {
        if len > self.len() {
            Err(Error::Other(format!(
                "Cannot truncate len={} when buffer len={}",
                len,
                self.len()
            )))
        } else {
            self.truncate(len);
            Ok(())
        }
    }
}

impl EzBuffer for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn split_off(&mut self, idx: usize) -> Self {
        self.split_off(idx)
    }

    fn unsplit(&mut self, other: Self) {
        self.extend_from_slice(other.as_slice());
    }

    fn split_to(&mut self, idx: usize) -> Self {
        let mut tail = self.split_off(idx);
        // swap head into tail
        std::mem::swap(self, &mut tail);
        tail // now, is the head
    }
}

impl EzBuffer for BytesMut {
    fn len(&self) -> usize {
        self.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn split_off(&mut self, idx: usize) -> Self {
        self.split_off(idx)
    }

    fn unsplit(&mut self, other: Self) {
        self.unsplit(other);
    }

    fn split_to(&mut self, idx: usize) -> Self {
        self.split_to(idx)
    }
}
