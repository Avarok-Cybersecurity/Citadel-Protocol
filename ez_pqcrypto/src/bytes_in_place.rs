use std::ops::Range;

use aes_gcm_siv::aead::{Buffer, Error};
use bytes::{BufMut, BytesMut};

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

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.inner.extend_from_slice(other)?;
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.inner.truncate(len)
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

pub struct InPlaceByteSliceMut<'a> {
    pub(crate) inner: &'a mut [u8],
    truncated_len: usize,
}

impl InPlaceByteSliceMut<'_> {
    pub fn get_finished_len(&self) -> usize {
        self.truncated_len
    }
}

impl<'a> From<&'a mut [u8]> for InPlaceByteSliceMut<'a> {
    fn from(inner: &'a mut [u8]) -> Self {
        Self {
            inner,
            truncated_len: 0,
        }
    }
}

impl AsMut<[u8]> for InPlaceByteSliceMut<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner
    }
}

impl AsRef<[u8]> for InPlaceByteSliceMut<'_> {
    fn as_ref(&self) -> &[u8] {
        self.inner
    }
}

impl Buffer for InPlaceByteSliceMut<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        if self.inner.len() >= other.len() {
            self.inner[..other.len()].copy_from_slice(other);
            // hack for ByteSliceMut only:
            self.truncated_len = other.len();
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.truncated_len = len;
    }
}

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
