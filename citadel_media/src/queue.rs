use crate::error::MediaError;
use crate::frame::MediaFrame;
use std::collections::VecDeque;

/// Bounded FIFO of outgoing frames. When full, drops in priority order:
/// oldest `DISCARDABLE && !KEYFRAME` → oldest `!KEYFRAME` → oldest of all.
#[derive(Debug)]
pub struct SendQueue {
    capacity: usize,
    frames: VecDeque<MediaFrame>,
}

impl SendQueue {
    pub fn new(capacity: usize) -> Result<Self, MediaError> {
        if capacity == 0 {
            return Err(MediaError::InvalidConfig("send queue capacity must be > 0"));
        }
        Ok(Self {
            capacity,
            frames: VecDeque::with_capacity(capacity),
        })
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Enqueues `frame`, evicting one frame by policy if the queue is full.
    /// Returns the evicted frame, if any.
    pub fn push(&mut self, frame: MediaFrame) -> Option<MediaFrame> {
        let evicted = if self.frames.len() >= self.capacity {
            let idx = self.victim_index();
            self.frames.remove(idx)
        } else {
            None
        };
        self.frames.push_back(frame);
        evicted
    }

    pub fn pop(&mut self) -> Option<MediaFrame> {
        self.frames.pop_front()
    }

    pub fn iter(&self) -> impl Iterator<Item = &MediaFrame> {
        self.frames.iter()
    }

    fn victim_index(&self) -> usize {
        let position = |pred: fn(&MediaFrame) -> bool| self.frames.iter().position(pred);
        position(|f| f.header.flags.is_discardable() && !f.header.flags.is_keyframe())
            .or_else(|| position(|f| !f.header.flags.is_keyframe()))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameFlags, FrameHeader, TrackId, TrackKind};
    use bytes::Bytes;

    fn frame(seq: u32, flags: FrameFlags) -> MediaFrame {
        MediaFrame {
            header: FrameHeader {
                track: TrackId(0),
                kind: TrackKind::Video,
                sequence: seq,
                timestamp: seq,
                flags,
            },
            payload: Bytes::new(),
        }
    }

    fn seqs(q: &SendQueue) -> Vec<u32> {
        q.iter().map(|f| f.header.sequence).collect()
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            SendQueue::new(0),
            Err(MediaError::InvalidConfig(_))
        ));
    }

    #[test]
    fn fifo_under_capacity() {
        let mut q = SendQueue::new(3).unwrap();
        assert!(q.push(frame(0, FrameFlags::NONE)).is_none());
        assert!(q.push(frame(1, FrameFlags::NONE)).is_none());
        assert_eq!(q.pop().unwrap().header.sequence, 0);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn drops_oldest_discardable_first() {
        let mut q = SendQueue::new(3).unwrap();
        q.push(frame(0, FrameFlags::KEYFRAME));
        q.push(frame(1, FrameFlags::NONE));
        q.push(frame(2, FrameFlags::DISCARDABLE));
        let evicted = q.push(frame(3, FrameFlags::DISCARDABLE)).unwrap();
        assert_eq!(evicted.header.sequence, 2);
        assert_eq!(seqs(&q), vec![0, 1, 3]);
    }

    #[test]
    fn then_oldest_non_keyframe() {
        let mut q = SendQueue::new(3).unwrap();
        q.push(frame(0, FrameFlags::KEYFRAME));
        q.push(frame(1, FrameFlags::NONE));
        q.push(frame(2, FrameFlags::NONE));
        let evicted = q.push(frame(3, FrameFlags::NONE)).unwrap();
        assert_eq!(evicted.header.sequence, 1);
        assert_eq!(seqs(&q), vec![0, 2, 3]);
    }

    #[test]
    fn then_oldest_of_all() {
        let mut q = SendQueue::new(2).unwrap();
        q.push(frame(0, FrameFlags::KEYFRAME));
        q.push(frame(1, FrameFlags::KEYFRAME));
        let evicted = q.push(frame(2, FrameFlags::KEYFRAME)).unwrap();
        assert_eq!(evicted.header.sequence, 0);
        assert_eq!(seqs(&q), vec![1, 2]);
    }

    #[test]
    fn discardable_keyframe_is_not_first_victim() {
        let mut q = SendQueue::new(2).unwrap();
        q.push(frame(0, FrameFlags::KEYFRAME | FrameFlags::DISCARDABLE));
        q.push(frame(1, FrameFlags::NONE));
        let evicted = q.push(frame(2, FrameFlags::NONE)).unwrap();
        assert_eq!(evicted.header.sequence, 1);
    }
}
