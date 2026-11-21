use super::*;
use std::cell::RefCell;

const PAGE: usize = 4096;

/// Records what the counter asks of the OS (the OS port is the only thing replaced here).
#[derive(Default)]
struct Recorder {
    locked: RefCell<Vec<Range<usize>>>,
    unlocked: RefCell<Vec<Range<usize>>>,
    refuse: bool,
}

impl PageLocker for Recorder {
    fn lock(&self, start: usize, len: usize) -> Result<(), i32> {
        self.locked.borrow_mut().push(start..start + len);
        if self.refuse {
            Err(12)
        } else {
            Ok(())
        }
    }

    fn unlock(&self, start: usize, len: usize) {
        self.unlocked.borrow_mut().push(start..start + len);
    }
}

#[test]
fn a_neighbour_leaving_does_not_unlock_a_shared_page() {
    let os = Recorder::default();
    let mut counts = PageCounts::new(PAGE);
    // Two buffers in the same page.
    counts.acquire(PAGE + 16, 32, &os).unwrap();
    counts.acquire(PAGE + 64, 32, &os).unwrap();
    assert_eq!(*os.locked.borrow(), vec![PAGE..2 * PAGE], "locked once");

    counts.release(PAGE + 16, 32, &os);
    assert!(os.unlocked.borrow().is_empty(), "still held by the other");
    assert_eq!(counts.holders_of(1), 1);

    counts.release(PAGE + 64, 32, &os);
    assert_eq!(*os.unlocked.borrow(), vec![PAGE..2 * PAGE]);
    assert_eq!(counts.holders_of(1), 0);
}

#[test]
fn a_buffer_across_pages_locks_and_unlocks_them_as_runs() {
    let os = Recorder::default();
    let mut counts = PageCounts::new(PAGE);
    counts.acquire(2 * PAGE + 100, 32, &os).unwrap(); // holds page 2
    counts.acquire(PAGE + 10, 3 * PAGE, &os).unwrap(); // pages 1..=4
    assert_eq!(
        *os.locked.borrow(),
        vec![2 * PAGE..3 * PAGE, PAGE..2 * PAGE, 3 * PAGE..5 * PAGE]
    );
    counts.release(PAGE + 10, 3 * PAGE, &os);
    assert_eq!(
        *os.unlocked.borrow(),
        vec![PAGE..2 * PAGE, 3 * PAGE..5 * PAGE],
        "page 2 is still held"
    );
}

#[test]
fn an_empty_range_touches_nothing() {
    let os = Recorder::default();
    let mut counts = PageCounts::new(PAGE);
    counts.acquire(PAGE, 0, &os).unwrap();
    counts.release(PAGE, 0, &os);
    assert!(os.locked.borrow().is_empty() && os.unlocked.borrow().is_empty());
}

#[test]
fn a_refused_lock_is_reported_and_still_balanced() {
    let os = Recorder {
        refuse: true,
        ..Default::default()
    };
    let mut counts = PageCounts::new(PAGE);
    assert_eq!(counts.acquire(PAGE, 8, &os), Err(12));
    counts.release(PAGE, 8, &os);
    assert_eq!(counts.holders_of(1), 0);
}
