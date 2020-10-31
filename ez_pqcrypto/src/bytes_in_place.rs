use std::ops::Range;
#[cfg(feature = "chacha20")]
use chacha20poly1305::aead::{Buffer, Error};

#[cfg(not(feature = "chacha20"))]
use aes_gcm_siv::aead::{Buffer, Error};
use bytes::BytesMut;

pub struct InPlaceBytesMut<'a> {
    inner: &'a mut BytesMut,
    window: Range<usize>,
}

impl<'a> InPlaceBytesMut<'a> {
    /// `window`: agnostic to the length. The window may be greater than the length, but MUST be less than the capacity
    pub fn new<'b: 'a>(inner: &'b mut BytesMut, window: Range<usize>) -> Option<InPlaceBytesMut<'a>> {
        if window.end > inner.capacity() {
            None
        } else {
            Some(Self { inner, window })
        }
    }
}

impl Buffer for InPlaceBytesMut<'_> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.inner.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.inner.truncate(len)
    }
}

impl AsMut<[u8]> for InPlaceBytesMut<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.window.clone()]
    }
}

impl AsRef<[u8]> for InPlaceBytesMut<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.inner[self.window.clone()]
    }
}