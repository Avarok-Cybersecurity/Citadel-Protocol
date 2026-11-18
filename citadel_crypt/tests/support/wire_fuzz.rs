//! Seeded mutation fuzzing for the tests that feed received bytes into this crate.
//!
//! A campaign derives its inputs from genuine encodings (so most of them get past the outer
//! decoder and reach the checks behind it) plus raw random bytes, runs each input under
//! `catch_unwind`, and runs the whole campaign on a worker thread under a deadline, so an input
//! that panics, or one that makes the code under test spin, fails the test instead of hanging it.
//! The seed is fixed so a failure reproduces; the failing input is printed in hex.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::Duration;

/// Fixed so that a failing campaign reproduces exactly on every run.
const SEED: u64 = 0x0000_C17A_DE15_EED5;

/// Values that sit on the edges of the integer fields decoders read.
const EDGES: [u64; 6] = [
    0,
    1,
    u32::MAX as u64,
    u32::MAX as u64 + 1,
    u64::MAX / 2,
    u64::MAX,
];

/// SplitMix64: a small deterministic generator, so the campaigns need no RNG crate features.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`; `bound` must be non-zero.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// One mutation of `seed`: random bytes, flipped bytes, a truncation, an insertion, or an integer
/// field overwritten with an edge value.
pub fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    match rng.below(5) {
        0 => {
            let len = rng.below(seed.len() * 2 + 65);
            out = (0..len).map(|_| rng.byte()).collect();
        }
        1 if !out.is_empty() => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(out.len());
                out[at] = rng.byte();
            }
        }
        2 => out.truncate(rng.below(seed.len() + 1)),
        3 => {
            let at = rng.below(out.len() + 1);
            let extra: Vec<u8> = (0..1 + rng.below(32)).map(|_| rng.byte()).collect();
            out.splice(at..at, extra);
        }
        _ if out.len() >= 8 => {
            let at = rng.below(out.len() - 7);
            let edge = EDGES[rng.below(EDGES.len())];
            let width = if rng.below(2) == 0 { 8 } else { 4 };
            out[at..at + width].copy_from_slice(&edge.to_le_bytes()[..width]);
        }
        _ => out.push(rng.byte()),
    }
    out
}

/// Runs `case` over `cases` mutations of `seeds` (and the seeds themselves). Fails if any input
/// panics or if the campaign does not finish within `deadline`.
pub fn campaign<F>(
    name: &'static str,
    seeds: Vec<Vec<u8>>,
    cases: usize,
    deadline: Duration,
    case: F,
) where
    F: Fn(&[u8]) + Send + 'static,
{
    assert!(
        !seeds.is_empty(),
        "{name}: a campaign needs at least one seed"
    );
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut rng = Rng::new(SEED);
        let inputs = seeds
            .iter()
            .cloned()
            .chain((0..cases).map(|i| mutate(&mut rng, &seeds[i % seeds.len()])));
        for input in inputs {
            if catch_unwind(AssertUnwindSafe(|| case(&input))).is_err() {
                let _ = tx.send(Err(hex(&input)));
                return;
            }
        }
        let _ = tx.send(Ok(()));
    });
    match rx.recv_timeout(deadline) {
        Ok(Ok(())) => {}
        Ok(Err(input)) => panic!("{name}: an input panicked: {input}"),
        Err(_) => panic!("{name}: the campaign did not finish within {deadline:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
