//! What a decode allocates for an oversized length prefix: a 16-byte input claiming 256 MiB.
//!
//! One test function, so the peak this binary's allocator records is the decode's own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Peak;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Peak {
    // SAFETY: forwards to the system allocator unchanged; only counts.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        let _ = PEAK.fetch_max(live, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    // SAFETY: forwards to the system allocator unchanged; only counts.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Peak = Peak;

const CLAIM: u64 = 256 * 1024 * 1024;
/// What a refused decode may allocate: serde reserves at most 1 MiB for a sequence it has not
/// read yet, and nothing here is larger.
const CEILING: usize = 2 * 1024 * 1024;

fn bomb() -> Vec<u8> {
    let mut bytes = 7u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&CLAIM.to_le_bytes());
    bytes
}

/// The peak allocation above the baseline while `decode` runs.
fn peak_of(decode: impl FnOnce()) -> usize {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    decode();
    PEAK.load(Ordering::SeqCst) - base
}

#[test]
fn a_claimed_length_is_not_allocated_for() {
    let bomb = bomb();
    let from_reader = peak_of(|| {
        let decoded: bincode::Result<(u64, String)> =
            citadel_io::decode::deserialize_from(&bomb[..], bomb.len());
        assert!(decoded.is_err());
    });
    assert!(
        from_reader < CEILING,
        "a reader decode allocated {from_reader} bytes for a {CLAIM}-byte claim"
    );
    for (what, peak) in [
        (
            "a string",
            peak_of(|| {
                let decoded: bincode::Result<(u64, String)> =
                    citadel_io::decode::deserialize(&bomb);
                assert!(decoded.is_err());
            }),
        ),
        (
            "bytes",
            peak_of(|| {
                let decoded: bincode::Result<(u64, Vec<u8>)> =
                    citadel_io::decode::deserialize(&bomb);
                assert!(decoded.is_err());
            }),
        ),
        (
            "u64s",
            peak_of(|| {
                let decoded: bincode::Result<(u64, Vec<u64>)> =
                    citadel_io::decode::deserialize(&bomb);
                assert!(decoded.is_err());
            }),
        ),
    ] {
        assert!(
            peak < CEILING,
            "a slice decode of {what} allocated {peak} bytes for a {CLAIM}-byte claim"
        );
    }
}
