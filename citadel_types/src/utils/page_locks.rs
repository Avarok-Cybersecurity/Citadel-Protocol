//! Memory locking that counts its holders.
//!
//! The OS locks whole pages and keeps no count, so unlocking one buffer's range also unlocks
//! every page that range shares with a neighbour still holding secrets. [`PageCounts`] counts the
//! buffers holding each page and asks the OS to lock a page when its first holder arrives and to
//! unlock it when its last holder leaves. The counting is pure; the OS calls sit behind
//! [`PageLocker`].

use std::collections::HashMap;
use std::ops::Range;

/// The OS side: lock or unlock `len` bytes from `start`, both page-aligned.
pub(crate) trait PageLocker {
    /// The OS error code when the pages could not be locked.
    fn lock(&self, start: usize, len: usize) -> Result<(), i32>;
    fn unlock(&self, start: usize, len: usize);
}

/// How many buffers hold each page.
pub(crate) struct PageCounts {
    page_size: usize,
    holders: HashMap<usize, usize>,
}

/// The indices of the pages `[ptr, ptr + len)` touches.
fn pages(ptr: usize, len: usize, page_size: usize) -> Range<usize> {
    if len == 0 {
        return 0..0;
    }
    let last = ptr.saturating_add(len - 1);
    ptr / page_size..last / page_size + 1
}

/// Calls `run` once per maximal run of consecutive pages in `pages` for which `pick` holds.
fn runs(
    pages: Range<usize>,
    mut pick: impl FnMut(usize) -> bool,
    mut run: impl FnMut(Range<usize>),
) {
    let mut start = None;
    for page in pages.clone() {
        match (pick(page), start) {
            (true, None) => start = Some(page),
            (false, Some(first)) => {
                run(first..page);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(first) = start {
        run(first..pages.end);
    }
}

impl PageCounts {
    pub(crate) fn new(page_size: usize) -> Self {
        Self {
            page_size,
            holders: HashMap::new(),
        }
    }

    /// Records a holder for every page of `[ptr, ptr + len)` and locks the pages it is the first
    /// holder of. The pages stay counted even if the OS refuses, so [`Self::release`] balances.
    pub(crate) fn acquire(
        &mut self,
        ptr: usize,
        len: usize,
        os: &impl PageLocker,
    ) -> Result<(), i32> {
        let page_size = self.page_size;
        let span = pages(ptr, len, page_size);
        let holders = &mut self.holders;
        let mut first_holder = |page: usize| {
            let count = holders.entry(page).or_insert(0);
            *count += 1;
            *count == 1
        };
        let mut outcome = Ok(());
        runs(span, &mut first_holder, |run| {
            if let Err(code) = os.lock(run.start * page_size, run.len() * page_size) {
                outcome = Err(code);
            }
        });
        outcome
    }

    /// Drops a holder from every page of `[ptr, ptr + len)` and unlocks the pages it was the last
    /// holder of.
    pub(crate) fn release(&mut self, ptr: usize, len: usize, os: &impl PageLocker) {
        let page_size = self.page_size;
        let span = pages(ptr, len, page_size);
        let holders = &mut self.holders;
        let last_holder = |page: usize| match holders.get_mut(&page) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => {
                holders.remove(&page);
                true
            }
            None => false,
        };
        runs(span, last_holder, |run| {
            os.unlock(run.start * page_size, run.len() * page_size)
        });
    }

    #[cfg(test)]
    pub(crate) fn holders_of(&self, page: usize) -> usize {
        self.holders.get(&page).copied().unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "page_locks_tests.rs"]
mod tests;
