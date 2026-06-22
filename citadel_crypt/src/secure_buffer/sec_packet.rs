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
                // Reserve `len` bytes plus the 4-byte big-endian length prefix. Use a checked add
                // so a near-`u32::MAX` `len` returns a clean error instead of overflowing: in debug
                // `len + 4` panics, and in release it wraps to a tiny reservation, after which the
                // `payload[0..4]` length-prefix write below panics with an out-of-bounds slice.
                let reserve_len = len.checked_add(4).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "payload length overflows u32 with the 4-byte length prefix",
                    )
                })?;
                packet.prepare_payload(reserve_len)?; // adds 4 for length field
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

    #[test]
    fn finish_and_message_len_and_debug() {
        let mut p = SecureMessagePacket::<4>::new().unwrap();
        assert_eq!(p.message_len(), 0);
        p.write_payload(6, |s| {
            s.fill(1);
            Ok(())
        })
        .unwrap();
        assert!(p.message_len() > 0);
        assert!(format!("{p:?}").contains("Secure message packet"));
        p.write_header(|h| {
            h.fill(2);
            Ok(())
        })
        .unwrap();
        // finish() is write_payload_extension(0): no extension appended.
        assert!(!p.finish().unwrap().is_empty());
    }

    #[test]
    fn invalid_construction_flow_errors() {
        // header before payload is rejected
        let mut p = SecureMessagePacket::<4>::new().unwrap();
        assert!(p.write_header(|_| Ok(())).is_err());
        // a second payload write is rejected (state already advanced)
        let mut p2 = SecureMessagePacket::<4>::new().unwrap();
        p2.write_payload(3, |s| {
            s.fill(0);
            Ok(())
        })
        .unwrap();
        assert!(p2
            .write_payload(3, |s| {
                s.fill(0);
                Ok(())
            })
            .is_err());
        // extension before header is rejected
        let p3 = SecureMessagePacket::<4>::new().unwrap();
        assert!(p3.write_payload_extension(1, |_| Ok(())).is_err());
    }

    #[test]
    fn write_payload_rejects_length_prefix_overflow() {
        // `len + 4` (payload + 4-byte length prefix) must not overflow u32. For any `len` in
        // `(u32::MAX - 4, u32::MAX]` the add overflows; the API must return an InvalidInput error
        // instead of panicking (debug overflow / release wrap -> out-of-bounds prefix write).
        for len in [u32::MAX, u32::MAX - 1, u32::MAX - 3] {
            let mut p = SecureMessagePacket::<4>::new().unwrap();
            let err = p
                .write_payload(len, |_| Ok(()))
                .expect_err("overflowing payload length must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn extract_payload_rejects_bad_input() {
        use bytes::BytesMut;
        let mut tiny = BytesMut::from(&[1u8, 2][..]);
        assert!(SecureMessagePacket::<4>::extract_payload(&mut tiny).is_err());
        let mut bad = BytesMut::from(&[0u8, 0, 0, 200, 1, 2][..]);
        assert!(SecureMessagePacket::<4>::extract_payload(&mut bad).is_err());
    }
}
