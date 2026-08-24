use crate::config::MediaConfig;
use crate::error::MediaError;
use crate::frame::{FrameHeader, MediaFrame};
use crate::time::MediaInstant;
use crate::wire::{self, FragmentHeader, WireMessage};
use bytes::{Bytes, BytesMut};

/// Result of feeding one datagram to the [`Reassembler`].
#[derive(Debug, PartialEq)]
pub enum ReassembleOutcome {
    Complete(MediaFrame),
    Partial {
        received: u16,
        expected: u16,
    },
    Duplicate,
    /// The datagram was a control message; the TLV body is returned for the caller to demux.
    Control(Bytes),
    Rejected(MediaError),
}

#[derive(Debug)]
struct Pending {
    header: FrameHeader,
    total_len: u32,
    frag_count: u16,
    received: u16,
    seen: Vec<bool>,
    buf: BytesMut,
    first_seen: MediaInstant,
}

/// Rebuilds frames from fragments. One zeroed allocation per frame; O(1) fragment placement.
#[derive(Debug)]
pub struct Reassembler {
    config: MediaConfig,
    pending: Vec<Pending>,
}

impl Reassembler {
    pub fn new(config: MediaConfig) -> Result<Self, MediaError> {
        config.validate()?;
        Ok(Self {
            config,
            pending: Vec::new(),
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Parses then pushes a raw datagram. Control messages are surfaced, not consumed.
    pub fn push(&mut self, datagram: &[u8], now: MediaInstant) -> ReassembleOutcome {
        match wire::parse(datagram) {
            Ok(WireMessage::Fragment { header, payload }) => {
                self.push_fragment(header, payload, now)
            }
            Ok(WireMessage::Control(body)) => {
                ReassembleOutcome::Control(Bytes::copy_from_slice(body))
            }
            Err(e) => ReassembleOutcome::Rejected(e),
        }
    }

    pub fn push_fragment(
        &mut self,
        header: FragmentHeader,
        payload: &[u8],
        now: MediaInstant,
    ) -> ReassembleOutcome {
        if let Err(e) = self.validate_fragment(&header, payload) {
            return ReassembleOutcome::Rejected(e);
        }
        let slot = match self.find_or_insert(&header, now) {
            Ok(slot) => slot,
            Err(e) => return ReassembleOutcome::Rejected(e),
        };
        let pending = &mut self.pending[slot];
        let idx = header.frag_index as usize;
        if pending.seen[idx] {
            return ReassembleOutcome::Duplicate;
        }
        let start = idx * self.config.max_fragment_payload;
        pending.buf[start..start + payload.len()].copy_from_slice(payload);
        pending.seen[idx] = true;
        pending.received += 1;
        if pending.received < pending.frag_count {
            return ReassembleOutcome::Partial {
                received: pending.received,
                expected: pending.frag_count,
            };
        }
        let done = self.pending.swap_remove(slot);
        ReassembleOutcome::Complete(MediaFrame {
            header: done.header,
            payload: done.buf.freeze(),
        })
    }

    /// Drops partial frames whose first fragment arrived more than `jitter_depth_micros` ago.
    /// Returns the number of frames evicted.
    pub fn evict_stale(&mut self, now: MediaInstant) -> usize {
        let depth = self.config.jitter_depth_micros;
        let before = self.pending.len();
        self.pending
            .retain(|p| now.micros_since(p.first_seen) < depth);
        before - self.pending.len()
    }

    fn validate_fragment(&self, h: &FragmentHeader, payload: &[u8]) -> Result<(), MediaError> {
        let total = h.total_len as usize;
        if total > self.config.max_frame_bytes {
            return Err(MediaError::FrameTooLarge {
                len: total,
                max: self.config.max_frame_bytes,
            });
        }
        let expected_count = self.config.fragment_count_for(total);
        if expected_count != h.frag_count as usize {
            return Err(MediaError::TotalLenMismatch {
                expected: expected_count as u32,
                actual: h.frag_count as u32,
            });
        }
        let max = self.config.max_fragment_payload;
        let start = h.frag_index as usize * max;
        let expected_len = total.saturating_sub(start).min(max);
        if payload.len() != expected_len {
            return Err(MediaError::PayloadLenMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }
        Ok(())
    }

    fn find_or_insert(
        &mut self,
        h: &FragmentHeader,
        now: MediaInstant,
    ) -> Result<usize, MediaError> {
        let key = (h.frame.track, h.frame.sequence);
        if let Some(i) = self
            .pending
            .iter()
            .position(|p| (p.header.track, p.header.sequence) == key)
        {
            let p = &self.pending[i];
            if p.total_len != h.total_len {
                return Err(MediaError::TotalLenMismatch {
                    expected: p.total_len,
                    actual: h.total_len,
                });
            }
            if p.header != h.frame {
                return Err(MediaError::FrameHeaderMismatch);
            }
            return Ok(i);
        }
        if self.pending.len() >= self.config.max_pending_frames {
            self.evict_oldest();
        }
        self.pending.push(Pending {
            header: h.frame,
            total_len: h.total_len,
            frag_count: h.frag_count,
            received: 0,
            seen: vec![false; h.frag_count as usize],
            buf: BytesMut::zeroed(h.total_len as usize),
            first_seen: now,
        });
        Ok(self.pending.len() - 1)
    }

    fn evict_oldest(&mut self) {
        if let Some(i) = (0..self.pending.len()).min_by_key(|&i| self.pending[i].first_seen) {
            self.pending.swap_remove(i);
        }
    }
}
