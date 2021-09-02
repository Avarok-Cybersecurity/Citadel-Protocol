use crate::secure_buffer::partitioned_sec_buffer::{PartitionedSecBuffer, SliceHandle};
use bytes::BytesMut;

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

    /// The first write to the buffer should be the payload
    pub fn write_payload(&mut self, len: u32, fx: impl FnOnce(SliceHandle) -> std::io::Result<()>) -> std::io::Result<()> {
        match self {
            Self::PayloadNext(packet) => {
                packet.prepare_payload(len)?;
                let ret = (fx)(packet.payload()?);
                *self = SecureMessagePacket::HeaderNext(std::mem::take(packet));
                ret
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }

    /// The second write to the buffer should be the header
    pub fn write_header(&mut self, fx: impl FnOnce(SliceHandle) -> std::io::Result<()>) -> std::io::Result<()> {
        match self {
            Self::HeaderNext(packet) => {
                let ret = (fx)(packet.header()?);
                *self = SecureMessagePacket::FinalPayloadExt(std::mem::take(packet));
                ret
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }

    /// The final write to the buffer should be the payload extension. This consumes self and returns bytes
    pub fn write_payload_extension(self, len: u32, fx: impl FnOnce(SliceHandle) -> std::io::Result<()>) -> std::io::Result<BytesMut> {
        match self {
            Self::FinalPayloadExt(mut packet) => {
                packet.prepare_extended_payload(len)?;
                (fx)(packet.extended_payload()?)?;
                Ok(packet.into_packet())
            }

            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid packet construction flow"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_buffer::sec_packet::SecureMessagePacket;

    #[test]
    fn secure_packet() {
        let mut packet = SecureMessagePacket::<4>::new().unwrap();
        packet.write_payload(10, |mut slice| Ok(slice.fill(9))).unwrap();
        packet.write_header(|mut header| Ok(header.fill(3))).unwrap();
        let output = packet.write_payload_extension(5, |mut ext| Ok(ext.fill(4))).unwrap();
        assert_eq!(output, &vec![3,3,3,3,9,9,9,9,9,9,9,9,9,9,4,4,4,4,4])
    }
}