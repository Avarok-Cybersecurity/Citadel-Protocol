use std::io;

use bytes::{Bytes, BytesMut};
use bytes::BufMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::constants::CODEC_MIN_BUFFER;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct BytesCodec(usize);

impl BytesCodec {
    /// Creates a new `BytesCodec` for shipping around raw bytes.
    pub fn new(buffer_capacity: usize) -> BytesCodec {
        BytesCodec(buffer_capacity)
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if buf.capacity() < CODEC_MIN_BUFFER {
            buf.reserve(self.0 - buf.capacity());
        }
        if !buf.is_empty() {
            let len = buf.len();
            let ret = buf.split_to(len);
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}