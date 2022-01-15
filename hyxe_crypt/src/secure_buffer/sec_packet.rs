use crate::secure_buffer::partitioned_sec_buffer::{PartitionedSecBuffer, SliceHandle};
use bytes::BytesMut;
use std::fmt::{Debug, Formatter};
use byteorder::{BigEndian, ByteOrder};

/// An optimized unit designed for one-time only allocation between creating the packet and sending outbound
#[derive(Debug)]
pub struct SecurePacket {
    /// There are three parts to the packet:
    /// [0]: The header
    /// [1]: The payload
    /// [2]: The extended payload (anything else that needs to be written, like metadata)
    inner: PartitionedSecBuffer<3>
}

const HEADER_PART: usize = 0;
const PAYLOAD_PART: usize = 1;
const PAYLOAD_EXT: usize = 2;

impl SecurePacket {
    pub fn new() -> Self {
        Self { inner: PartitionedSecBuffer::<3>::new().unwrap() }
    }

    pub fn prepare_header(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(HEADER_PART, len)
    }

    pub fn header(&mut self) -> std::io::Result<SliceHandle> {
        self.inner.partition_window(HEADER_PART)
    }

    pub fn prepare_payload(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(PAYLOAD_PART, len)
    }

    pub fn payload(&mut self) -> std::io::Result<SliceHandle> {
        self.inner.partition_window(PAYLOAD_PART)
    }

    pub fn prepare_extended_payload(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(PAYLOAD_EXT, len)
    }

    pub fn extended_payload(&mut self) -> std::io::Result<SliceHandle> {
        self.inner.partition_window(PAYLOAD_EXT)
    }

    pub fn into_packet(self) -> BytesMut {
        self.inner.into_buffer()
    }
}

impl Default for SecurePacket {
    fn default() -> Self {
        Self::new()
    }
}

/// Used for handling the flow of writing a packet that must first receive its payload from the user, then its header from the protocol, and finally the extended payload appended to the end from the protocol
pub enum SecureMessagePacket<const N: usize> {
    PayloadNext(SecurePacket),
    HeaderNext(SecurePacket),
    FinalPayloadExt(SecurePacket)
}

impl<const N: usize> SecureMessagePacket<N> {
    pub fn new() -> std::io::Result<Self> {
        let mut init = SecurePacket::new();
        init.prepare_header(N as _)?;
        Ok(Self::PayloadNext(init))
    }

    /// Takes a raw input and splits it into the payload and payload-extension
    pub fn decompose_payload_raw(input: &mut BytesMut) -> std::io::Result<(BytesMut, BytesMut)> {
        let payload = Self::extract_payload(input)?;
        Ok((payload, input.split()))
    }

    /// Takes a raw input and splits it into the payload and payload-extension
    pub fn extract_payload(input: &mut BytesMut) -> std::io::Result<BytesMut> {
        if input.len() < 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bad size"))
        }

        let len_field = input.split_to(4);
        let payload_len = BigEndian::read_u32(&len_field);

        if input.len() < payload_len as _ {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bad payload len size"))
        }

        let payload = input.split_to(payload_len as _);
        Ok(payload)
    }

    /// The first write to the buffer should be the payload
    pub fn write_payload(&mut self, len: u32, fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> std::io::Result<()> {
        match self {
            Self::PayloadNext(packet) => {
                packet.prepare_payload(len + 4)?; // adds 4 for length field
                let mut payload = packet.payload()?;
                BigEndian::write_u32(&mut payload[0..4], len);
                let ret = (fx)(&mut payload[4..]);
                *self = SecureMessagePacket::HeaderNext(std::mem::take(packet));
                ret
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }

    /// The second write to the buffer should be the header
    pub fn write_header(&mut self, fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> std::io::Result<()> {
        match self {
            Self::HeaderNext(packet) => {
                let ret = (fx)(&mut *packet.header()?);
                *self = SecureMessagePacket::FinalPayloadExt(std::mem::take(packet));
                ret
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }

    /// The final write to the buffer should be the payload extension. This consumes self and returns bytes
    pub fn write_payload_extension(self, len: u32, fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> std::io::Result<BytesMut> {
        match self {
            Self::FinalPayloadExt(mut packet) => {
                packet.prepare_extended_payload(len)?;
                (fx)(&mut *packet.extended_payload()?)?;
                Ok(packet.into_packet())
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }

    pub fn message_len(&self) -> usize {
        match self {
            Self::FinalPayloadExt(p) | Self::HeaderNext(p) | Self::PayloadNext(p) => p.inner.layout()[PAYLOAD_PART] as _
        }
    }
}

impl<const N: usize> Debug for SecureMessagePacket<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", match self { Self::PayloadNext(p) | Self::HeaderNext(p) | Self::FinalPayloadExt(p) => p })
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_buffer::sec_packet::SecureMessagePacket;

    #[test]
    fn secure_packet() {
        let mut packet = SecureMessagePacket::<4>::new().unwrap();
        packet.write_payload(10, |slice| Ok(slice.fill(9))).unwrap();
        packet.write_header(|header| Ok(header.fill(3))).unwrap();
        let mut output = packet.write_payload_extension(5, |ext| Ok(ext.fill(4))).unwrap();
        let header = output.split_to(4);
        let (payload, payload_ext) = SecureMessagePacket::<4>::decompose_payload_raw(&mut output).unwrap();
        assert_eq!(header, &vec![3,3,3,3]);
        assert_eq!(payload, &vec![9,9,9,9,9,9,9,9,9,9]);
        assert_eq!(payload_ext, &vec![4,4,4,4,4]);
    }
}