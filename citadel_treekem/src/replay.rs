//! Which frames a member has opened, so none is opened twice.
//!
//! Per `(epoch, sender leaf)` a member keeps the highest generation opened and a bitmap of the
//! [`WINDOW`] generations below it. A generation already marked, or older than the window, is
//! refused. Entries live only for the epochs a member can still read.

use std::collections::HashMap;

/// How far behind the highest generation opened from one sender a frame may arrive.
pub const WINDOW: u32 = 128;

#[derive(Clone, Copy, Debug, Default)]
struct SenderWindow {
    highest: u32,
    /// Bit `i` set: generation `highest - i` was opened.
    seen: u128,
}

/// The generations opened per `(epoch, sender leaf)`.
#[derive(Clone, Debug, Default)]
pub struct OpenedFrames {
    windows: HashMap<(u64, u32), SenderWindow>,
}

impl OpenedFrames {
    /// Whether `(epoch, sender, generation)` may be opened: not opened yet and within the window.
    pub fn is_fresh(&self, epoch: u64, sender: u32, generation: u32) -> bool {
        match self.windows.get(&(epoch, sender)) {
            None => true,
            Some(w) if generation > w.highest => true,
            Some(w) => {
                let behind = w.highest - generation;
                behind < WINDOW && w.seen & (1u128 << behind) == 0
            }
        }
    }

    /// Records `(epoch, sender, generation)` as opened. Call only after [`Self::is_fresh`].
    pub fn mark(&mut self, epoch: u64, sender: u32, generation: u32) {
        let w = self.windows.entry((epoch, sender)).or_insert(SenderWindow {
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
        self.windows.retain(|(epoch, _), _| keep(*epoch));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generation_is_opened_once_and_late_ones_within_the_window() {
        let mut opened = OpenedFrames::default();
        for generation in [0, 1, 5, 3] {
            assert!(opened.is_fresh(1, 0, generation));
            opened.mark(1, 0, generation);
            assert!(!opened.is_fresh(1, 0, generation));
        }
        assert!(
            opened.is_fresh(1, 0, 4),
            "an unopened generation inside the window"
        );
        assert!(
            opened.is_fresh(1, 1, 0),
            "another sender's generations are its own"
        );
        assert!(
            opened.is_fresh(2, 0, 0),
            "another epoch's generations are its own"
        );
        opened.mark(1, 0, 5 + WINDOW);
        assert!(!opened.is_fresh(1, 0, 4), "older than the window");
        assert!(!opened.is_fresh(1, 0, 5 + WINDOW));
        opened.retain_epochs(|epoch| epoch != 1);
        assert!(opened.is_fresh(1, 0, 4));
    }
}
