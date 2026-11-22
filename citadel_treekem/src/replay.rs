//! Which frames a member has opened, so none is opened twice.
//!
//! Per `(epoch, sender leaf, incarnation)` a member keeps the highest generation opened and a bitmap of the
//! [`WINDOW`] generations below it. A generation already marked, or older than the window, is
//! refused. Entries live only for the epochs a member can still read.

use crate::signing::FrameId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How far behind the highest generation opened from one sender a frame may arrive.
pub const WINDOW: u32 = 128;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct SenderWindow {
    highest: u32,
    /// Bit `i` set: generation `highest - i` was opened.
    seen: u128,
}

/// The generations opened per `(epoch, sender leaf, incarnation)`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenedFrames {
    windows: HashMap<(u64, u32, u64), SenderWindow>,
}

impl OpenedFrames {
    /// Whether `frame` may be opened: not opened yet and within the window.
    pub fn is_fresh(&self, frame: FrameId) -> bool {
        let generation = frame.generation;
        match self
            .windows
            .get(&(frame.epoch, frame.sender, frame.incarnation))
        {
            None => true,
            Some(w) if generation > w.highest => true,
            Some(w) => {
                let behind = w.highest - generation;
                behind < WINDOW && w.seen & (1u128 << behind) == 0
            }
        }
    }

    /// Records `frame` as opened. Call only after [`Self::is_fresh`].
    pub fn mark(&mut self, frame: FrameId) {
        let generation = frame.generation;
        let key = (frame.epoch, frame.sender, frame.incarnation);
        let w = self.windows.entry(key).or_insert(SenderWindow {
            highest: generation,
            seen: 0,
        });
        if generation > w.highest {
            let shift = generation - w.highest;
            w.seen = if shift >= WINDOW { 0 } else { w.seen << shift };
            w.highest = generation;
        }
        w.seen |= 1u128 << (w.highest - generation);
    }

    /// Forgets every epoch `keep` rejects.
    pub fn retain_epochs(&mut self, keep: impl Fn(u64) -> bool) {
        self.windows.retain(|(epoch, _, _), _| keep(*epoch));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(epoch: u64, sender: u32, incarnation: u64, generation: u32) -> FrameId {
        FrameId {
            epoch,
            sender,
            incarnation,
            generation,
        }
    }

    #[test]
    fn a_generation_is_opened_once_and_late_ones_within_the_window() {
        let mut opened = OpenedFrames::default();
        for generation in [0, 1, 5, 3] {
            assert!(opened.is_fresh(f(1, 0, 0, generation)));
            opened.mark(f(1, 0, 0, generation));
            assert!(!opened.is_fresh(f(1, 0, 0, generation)));
        }
        assert!(
            opened.is_fresh(f(1, 0, 0, 4)),
            "unopened, inside the window"
        );
        assert!(
            opened.is_fresh(f(1, 1, 0, 0)),
            "another sender's are its own"
        );
        assert!(
            opened.is_fresh(f(2, 0, 0, 0)),
            "another epoch's are its own"
        );
        assert!(
            opened.is_fresh(f(1, 0, 9, 0)),
            "another incarnation's are its own"
        );
        opened.mark(f(1, 0, 0, 5 + WINDOW));
        assert!(!opened.is_fresh(f(1, 0, 0, 4)), "older than the window");
        assert!(!opened.is_fresh(f(1, 0, 0, 5 + WINDOW)));
        opened.retain_epochs(|epoch| epoch != 1);
        assert!(opened.is_fresh(f(1, 0, 0, 4)));
    }
}
