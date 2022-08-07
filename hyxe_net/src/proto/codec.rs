use std::io;

use bytes::BufMut;
use bytes::{Bytes, BytesMut};
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

#[cfg(test)]
mod tests {
    use crate::constants::CODEC_BUFFER_CAPACITY;
    use crate::proto::codec::BytesCodec;
    use bytes::{BufMut, Bytes, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn test_bytes_codec() {
        lusna_logging::setup_log();

        let mut codec = BytesCodec::new(CODEC_BUFFER_CAPACITY);
        let mut buf = BytesMut::new();

        let mut ret = BytesMut::new();

        for x in 0..(CODEC_BUFFER_CAPACITY * 2) {
            let val = (x % 255) as u8;
            ret.put_u8(val);

            let slice = &[val];
            let data = Bytes::copy_from_slice(slice as &[u8]);
            codec.encode(data, &mut buf).unwrap();
        }

        if let Ok(Some(data)) = codec.decode(&mut buf) {
            assert_eq!(data, ret);
            assert!(codec.decode(&mut buf).unwrap().is_none());
        } else {
            panic!("Failed test");
        }
    }
}
