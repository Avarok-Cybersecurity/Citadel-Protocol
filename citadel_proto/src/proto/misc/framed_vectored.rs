//! Vectored, copy-free framing for the primary outbound stream.
//!
//! The standard `LengthDelimitedCodec` write path copies every packet body into the
//! codec's internal encode buffer before flushing it to the socket. This writer bypasses
//! that copy: it frames each packet as `[u32-BE length | body]` and writes the length
//! prefix together with the body buffer(s) directly to the underlying `AsyncWrite` using
//! vectored I/O (`writev`). For a [`OutboundPacket::Split`] packet the header and the
//! (shared, ref-counted) ciphertext payload are written as two separate buffers, removing
//! the per-chunk copy that concatenating them into one contiguous packet would require.
//!
//! The on-wire bytes are byte-identical to the `LengthDelimitedCodec` configuration used
//! by the reader (`length_field_offset(0)`, `u32` big-endian length field, no length
//! adjustment, 64 MB max frame) — only the in-process assembly differs. On transports
//! whose `AsyncWrite` does not implement true vectored writes (TLS/QUIC/WASM), the buffers
//! are written sequentially via the `advance_slices` loop, which remains correct (the same
//! bytes reach the wire) while raw TCP gets a single `writev` syscall.

use crate::macros::ContextRequirements;
use crate::proto::outbound_sender::OutboundPacket;
use crate::proto::packet::HeaderObfuscator;
use bytes::Bytes;
use citadel_io::tokio::io::{AsyncWrite, AsyncWriteExt};
use std::io::{self, IoSlice};

/// Length prefix width — matches `LengthDelimitedCodec::builder().length_field_type::<u32>()`.
const LEN_PREFIX_LEN: usize = 4;

/// Writes length-delimited frames to `W` using vectored I/O, avoiding the codec encode copy.
pub struct VectoredFrameWriter<W: AsyncWrite + Unpin + ContextRequirements + 'static> {
    write: Option<W>,
}

impl<W: AsyncWrite + Unpin + ContextRequirements + 'static> VectoredFrameWriter<W> {
    pub fn new(write: W) -> Self {
        Self { write: Some(write) }
    }

    #[inline]
    fn writer(&mut self) -> &mut W {
        self.write
            .as_mut()
            .expect("VectoredFrameWriter used after close")
    }

    /// Frame and write a queued outbound packet. The header obfuscator cipher is applied in
    /// place to the header region before writing. Does not flush.
    pub async fn write_packet(
        &mut self,
        packet: OutboundPacket,
        header_obfuscator: &HeaderObfuscator,
    ) -> io::Result<()> {
        let body_len = packet.body_len();
        let len_prefix = (body_len as u32).to_be_bytes();
        match packet {
            OutboundPacket::Contiguous(buf) => {
                // `prepare_outbound` applies the cipher in place and freezes (no copy).
                let body = header_obfuscator.prepare_outbound(buf);
                write_all_vectored(self.writer(), &[&len_prefix, &body]).await
            }
            OutboundPacket::Split {
                mut header,
                payload,
            } => {
                header_obfuscator.obfuscate_header(&mut header);
                write_all_vectored(self.writer(), &[&len_prefix, &header, &payload]).await
            }
        }
    }

    /// Write an already-final frame body (e.g. the header-obfuscator key packet) with the
    /// length prefix, without applying the cipher. Does not flush.
    pub async fn write_raw_frame(&mut self, body: Bytes) -> io::Result<()> {
        let len_prefix = (body.len() as u32).to_be_bytes();
        write_all_vectored(self.writer(), &[&len_prefix, &body]).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer().flush().await
    }
}

impl<W: AsyncWrite + Unpin + ContextRequirements + 'static> Drop for VectoredFrameWriter<W> {
    fn drop(&mut self) {
        if let Some(mut write) = self.write.take() {
            // Mirror `CleanShutdownSink`: gracefully shut down the write half (sends the
            // TLS close_notify / TCP FIN) on a detached task so drop stays synchronous.
            let shutdown_future = async move {
                let _ = write.shutdown().await;
            };
            spawn!(shutdown_future);
        }
    }
}

/// Write every buffer in `bufs` (in order) to `w` using vectored writes, looping until all
/// bytes are flushed. `LEN_PREFIX_LEN` is referenced to keep the framing contract explicit.
async fn write_all_vectored<W: AsyncWrite + Unpin>(w: &mut W, bufs: &[&[u8]]) -> io::Result<()> {
    debug_assert!(
        bufs.first().map(|b| b.len()).unwrap_or(0) == LEN_PREFIX_LEN,
        "first buffer must be the {LEN_PREFIX_LEN}-byte length prefix"
    );
    let mut slices: Vec<IoSlice<'_>> = bufs
        .iter()
        .filter(|b| !b.is_empty())
        .map(|b| IoSlice::new(b))
        .collect();
    let mut remaining: &mut [IoSlice<'_>] = &mut slices;
    while !remaining.is_empty() {
        let n = w.write_vectored(remaining).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        IoSlice::advance_slices(&mut remaining, n);
    }
    Ok(())
}
