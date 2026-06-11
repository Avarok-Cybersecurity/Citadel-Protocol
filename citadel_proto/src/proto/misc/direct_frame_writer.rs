//! Direct, copy-free framing for the primary outbound stream.
//!
//! The standard `LengthDelimitedCodec` write path copies every packet body into the
//! codec's internal encode buffer before flushing it to the socket. This writer bypasses
//! that copy: it frames each packet as `[u32-BE length | body]` and writes the length
//! prefix and the body buffer(s) **directly** to the underlying `AsyncWrite`. For a
//! [`OutboundPacket::Split`] packet the header and the (shared, ref-counted) ciphertext
//! payload are written as two separate buffers, removing the per-chunk copy that
//! concatenating them into one contiguous packet would require.
//!
//! The on-wire bytes are byte-identical to the `LengthDelimitedCodec` configuration used
//! by the reader (`length_field_offset(0)`, `u32` big-endian length field, no length
//! adjustment, 64 MB max frame) — only the in-process assembly differs.
//!
//! Buffers are written sequentially with `write_all` (which uses `poll_write`), **not** a
//! single `write_vectored`. quinn's QUIC `poll_write_vectored` can return `Pending` under
//! stream flow-control backpressure without re-arming the task waker, which permanently
//! stalled P2P transfers (the outbound writer parked forever mid-stream). `poll_write` is
//! the exact primitive the previous `FramedWrite` path used and handles backpressure
//! correctly on every transport. The per-burst `flush` in the outbound loop coalesces
//! these writes on buffered transports (TLS/QUIC), so the copy-elimination win is kept
//! without the vectored-write hazard.

use crate::macros::ContextRequirements;
use crate::proto::outbound_sender::OutboundPacket;
use crate::proto::packet::HeaderObfuscator;
use bytes::Bytes;
use citadel_io::tokio::io::{AsyncWrite, AsyncWriteExt};
use std::io;

/// Length prefix width — matches `LengthDelimitedCodec::builder().length_field_type::<u32>()`.
const LEN_PREFIX_LEN: usize = 4;

/// Writes length-delimited frames to `W` directly, avoiding the codec encode copy.
pub struct DirectFrameWriter<W: AsyncWrite + Unpin + ContextRequirements + 'static> {
    write: Option<W>,
}

impl<W: AsyncWrite + Unpin + ContextRequirements + 'static> DirectFrameWriter<W> {
    pub fn new(write: W) -> Self {
        Self { write: Some(write) }
    }

    #[inline]
    fn writer(&mut self) -> &mut W {
        self.write
            .as_mut()
            .expect("DirectFrameWriter used after close")
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
                write_frame_buffers(self.writer(), &[&len_prefix, &body]).await
            }
            OutboundPacket::Split {
                mut header,
                payload,
            } => {
                header_obfuscator.obfuscate_header(&mut header);
                write_frame_buffers(self.writer(), &[&len_prefix, &header, &payload]).await
            }
        }
    }

    /// Write an already-final frame body (e.g. the header-obfuscator key packet) with the
    /// length prefix, without applying the cipher. Does not flush.
    pub async fn write_raw_frame(&mut self, body: Bytes) -> io::Result<()> {
        let len_prefix = (body.len() as u32).to_be_bytes();
        write_frame_buffers(self.writer(), &[&len_prefix, &body]).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer().flush().await
    }
}

impl<W: AsyncWrite + Unpin + ContextRequirements + 'static> Drop for DirectFrameWriter<W> {
    fn drop(&mut self) {
        if let Some(mut write) = self.write.take() {
            // Gracefully shut down the write half (sends the TLS close_notify / TCP FIN /
            // QUIC stream finish) on a detached task so drop stays synchronous.
            let shutdown_future = async move {
                let _ = write.shutdown().await;
            };
            spawn!(shutdown_future);
        }
    }
}

/// Write every buffer in `bufs` (in order) directly to `w` via `write_all`. The first
/// buffer is always the `LEN_PREFIX_LEN`-byte length prefix. Sequential `write_all` (i.e.
/// `poll_write`) is used deliberately instead of `write_vectored` — see the module docs:
/// quinn's QUIC vectored write can stall under flow-control backpressure.
async fn write_frame_buffers<W: AsyncWrite + Unpin>(w: &mut W, bufs: &[&[u8]]) -> io::Result<()> {
    debug_assert!(
        bufs.first().map(|b| b.len()).unwrap_or(0) == LEN_PREFIX_LEN,
        "first buffer must be the {LEN_PREFIX_LEN}-byte length prefix"
    );
    for (i, buf) in bufs.iter().enumerate() {
        if !buf.is_empty() {
            // [QHANG] per-buffer trace: a "buf#i write" with no matching "done" in a hung
            // log identifies the exact poll_write that stalled (0=len, 1=header, 2=payload).
            log::info!(target: "citadel", "[QHANG] buf#{i} write len={}", buf.len());
            w.write_all(buf).await?;
            log::info!(target: "citadel", "[QHANG] buf#{i} done");
        }
    }
    Ok(())
}
