//! Secure Packet Buffer Implementation
//!
//! This module provides specialized buffer implementations for handling secure
//! network packets. It supports structured packet layouts with header, payload,
//! and extended payload sections while maintaining memory safety and efficiency.
//!
//! # Features
//!
//! - Three-part packet structure (header, payload, extension)
//! - Zero-copy packet construction
//! - Memory-safe section access
//! - Ordered write operations
//! - Automatic buffer cleanup
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::secure_buffer::sec_packet::SecureMessagePacket;
//!
//! const N: usize = 32;
//!
//! // Create a new packet
//! let mut packet = SecureMessagePacket::<N>::new().unwrap();
//!
//! // Write payload first
//! packet.write_payload(64, |buf| {
//!     buf.copy_from_slice(&[0u8; 64]);
//!     Ok(())
//! }).unwrap();
//!
//! // Write header second
//! packet.write_header(|buf| {
//!     buf.copy_from_slice(&[0u8; N]);
//!     Ok(())
//! }).unwrap();
//!
//! // Write extension last and get final bytes
//! let bytes = packet.write_payload_extension(10, |buf| {
//!     buf.copy_from_slice(&[0u8; 10]);
//!     Ok(())
//! }).unwrap();
//! ```
//!
//! # Important Notes
//!
//! - Writes must occur in order: payload, header, extension
//! - All sections are automatically zeroed on drop
//! - Buffer sizes are fixed after reservation
//! - Thread-safe implementation available
//!
//! # Related Components
//!
//! - [`PartitionedSecBuffer`] - Underlying buffer implementation
//! - [`crate::packet_vector`] - Packet vector operations
//! - [`crate::scramble::streaming_crypt_scrambler`] - Streaming encryption
//!

use crate::secure_buffer::partitioned_sec_buffer::{PartitionedSecBuffer, SliceHandle};
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

/// An optimized unit designed for one-time only allocation between creating the packet and sending outbound
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurePacket {
    /// There are three parts to the packet:
    /// [0]: The header
    /// [1]: The payload
    /// [2]: The extended payload (anything else that needs to be written, like metadata)
    inner: PartitionedSecBuffer<3>,
}

const HEADER_PART: usize = 0;
const PAYLOAD_PART: usize = 1;
const PAYLOAD_EXT: usize = 2;

impl SecurePacket {
    /// Creates a new secure packet.
    pub fn new() -> Self {
        Self {
            inner: PartitionedSecBuffer::<3>::new().unwrap(),
        }
    }

    /// Prepares the header section for writing.
    pub fn prepare_header(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(HEADER_PART, len)
    }

    /// Returns a mutable reference to the header section.
    pub fn header(&mut self) -> std::io::Result<SliceHandle<'_>> {
        self.inner.partition_window(HEADER_PART)
    }

    /// Prepares the payload section for writing.
    pub fn prepare_payload(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(PAYLOAD_PART, len)
    }

    /// Returns a mutable reference to the payload section.
    pub fn payload(&mut self) -> std::io::Result<SliceHandle<'_>> {
        self.inner.partition_window(PAYLOAD_PART)
    }

    /// Prepares the extended payload section for writing.
    pub fn prepare_extended_payload(&mut self, len: u32) -> std::io::Result<()> {
        self.inner.reserve_partition(PAYLOAD_EXT, len)
    }

    /// Returns a mutable reference to the extended payload section.
    pub fn extended_payload(&mut self) -> std::io::Result<SliceHandle<'_>> {
        self.inner.partition_window(PAYLOAD_EXT)
    }

    /// Consumes the packet and returns the underlying buffer.
    pub fn into_raw_packet(self) -> BytesMut {
        self.inner.into_buffer()
    }
}

impl Default for SecurePacket {
    fn default() -> Self {
        Self::new()
    }
}

/// Used for handling the flow of writing a packet that must first receive its payload from the user, then its header from the protocol, and finally the extended payload appended to the end from the protocol
#[derive(Serialize, Deserialize)]
pub enum SecureMessagePacket<const N: usize> {
    PayloadNext(SecurePacket),
    HeaderNext(SecurePacket),
    FinalPayloadExt(SecurePacket),
}

impl<const N: usize> SecureMessagePacket<N> {
    /// Creates a new secure message packet.
    pub fn new() -> std::io::Result<Self> {
        let mut init = SecurePacket::new();
        init.prepare_header(N as _)?;
        Ok(Self::PayloadNext(init))
    }

    /// Takes a raw input and splits it into the payload and payload-extension.
    pub fn decompose_payload_raw(input: &mut BytesMut) -> std::io::Result<(BytesMut, BytesMut)> {
        let payload = Self::extract_payload(input)?;
        Ok((payload, input.split()))
    }

    /// Takes a raw input and splits it into the payload and payload-extension.
    pub fn extract_payload(input: &mut BytesMut) -> std::io::Result<BytesMut> {
        if input.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bad size",
            ));
        }

        let len_field = input.split_to(4);
        let payload_len = BigEndian::read_u32(&len_field);

        if input.len() < payload_len as _ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bad payload len size",
            ));
        }

        let payload = input.split_to(payload_len as _);
        Ok(payload)
    }

    /// The first write to the buffer should be the payload.
    pub fn write_payload(
        &mut self,
        len: u32,
        fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        match self {
            Self::PayloadNext(packet) => {
                packet.prepare_payload(len + 4)?; // adds 4 for length field
                let mut payload = packet.payload()?;
                BigEndian::write_u32(&mut payload[0..4], len);
                let ret = (fx)(&mut payload[4..]);
                *self = SecureMessagePacket::HeaderNext(std::mem::take(packet));
                ret
            }

            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid packet construction flow",
            )),
        }
    }

    /// The second write to the buffer should be the header.
    pub fn write_header(
        &mut self,
        fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        match self {
            Self::HeaderNext(packet) => {
                let ret = (fx)(&mut packet.header()?);
                *self = SecureMessagePacket::FinalPayloadExt(std::mem::take(packet));
                ret
            }

            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid packet construction flow",
            )),
        }
    }

    pub fn finish(self) -> std::io::Result<BytesMut> {
        self.write_payload_extension(0, |_| Ok(()))
    }

    /// The final write to the buffer should be the payload extension. This consumes self and returns bytes.
    pub fn write_payload_extension(
        self,
        len: u32,
        fx: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
    ) -> std::io::Result<BytesMut> {
        match self {
            Self::FinalPayloadExt(mut packet) => {
                if len == 0 {
                    return Ok(packet.into_raw_packet());
                }

                packet.prepare_extended_payload(len)?;
                (fx)(&mut packet.extended_payload()?)?;
                Ok(packet.into_raw_packet())
            }

            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid packet construction flow",
            )),
        }
    }

    /// Returns the length of the message.
    pub fn message_len(&self) -> usize {
        match self {
            Self::FinalPayloadExt(p) | Self::HeaderNext(p) | Self::PayloadNext(p) => {
                p.inner.layout()[PAYLOAD_PART] as _
            }
        }
    }
}

impl<const N: usize> Debug for SecureMessagePacket<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secure message packet of length {}", self.message_len(),)
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_buffer::sec_packet::SecureMessagePacket;

    #[test]
    fn secure_packet() {
        let mut packet = SecureMessagePacket::<4>::new().unwrap();
        packet
            .write_payload(10, |slice| {
                slice.fill(9);
                Ok(())
            })
            .unwrap();
        packet
            .write_header(|header| {
                header.fill(3);
                Ok(())
            })
            .unwrap();
        let mut output = packet
            .write_payload_extension(5, |ext| {
                ext.fill(4);
                Ok(())
            })
            .unwrap();
        let header = output.split_to(4);
        let (payload, payload_ext) =
            SecureMessagePacket::<4>::decompose_payload_raw(&mut output).unwrap();
        assert_eq!(header, &vec![3, 3, 3, 3]);
        assert_eq!(payload, &vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(payload_ext, &vec![4, 4, 4, 4, 4]);
    }
}
