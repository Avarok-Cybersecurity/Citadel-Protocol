//! The moment an attempt stops being one side's to abandon.
//!
//! Each side bounds an attempt with its own timer. That is safe only while
//! neither side has told the other which socket pair to use: once the winner
//! has sent `Winner`, the loser may take the pair and return with it, and once
//! the loser has sent `WinnerCanEnd`, the winner may do the same. A side whose
//! timer fires after that point and moves to the next attempt leaves the peer
//! holding a socket nobody answers, and retries against a peer that has gone.
//!
//! So the side about to speak first commits, and its timer then finishes the
//! attempt instead of abandoning it. The two can race on different tasks
//! (`drive` is spawned), so exactly one of them decides: an attempt whose timer
//! has already expired it cannot commit, and one that has committed cannot
//! expire. Its peer moving on to the next attempt still ends it.

use futures::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

const OPEN: u8 = 0;
const COMMITTED: u8 = 1;
const EXPIRED: u8 = 2;

/// Shared by an attempt's timer and the dual-stack punch it bounds.
#[derive(Clone, Debug)]
pub struct AttemptCommit(Arc<AtomicU8>);

impl AttemptCommit {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(OPEN)))
    }

    /// Called just before this side tells the peer which pair to use. `false`
    /// when the attempt's timer has already expired it: the attempt is being
    /// abandoned, and the peer must not be told anything it could act on.
    pub fn commit(&self) -> bool {
        self.settle(COMMITTED)
    }

    /// Called when the attempt's timer fires. `false` when the attempt has
    /// already committed, and must be finished rather than abandoned.
    fn expire(&self) -> bool {
        self.settle(EXPIRED)
    }

    fn settle(&self, outcome: u8) -> bool {
        match self
            .0
            .compare_exchange(OPEN, outcome, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(settled) => settled == outcome,
        }
    }
}

impl Default for AttemptCommit {
    fn default() -> Self {
        Self::new()
    }
}

/// `task`'s output, or `None` if `timer` elapsed while the attempt was still
/// uncommitted. A committed attempt runs to its end; the caller's overall
/// deadline still bounds it.
pub(crate) async fn until_committed<F: Future>(
    timer: Duration,
    commit: &AttemptCommit,
    task: F,
) -> Option<F::Output> {
    futures::pin_mut!(task);
    if let Ok(output) = citadel_io::time::timeout(timer, &mut task).await {
        return Some(output);
    }
    if commit.expire() {
        None
    } else {
        Some(task.await)
    }
}

#[cfg(test)]
#[path = "attempt_commit_tests.rs"]
mod tests;
