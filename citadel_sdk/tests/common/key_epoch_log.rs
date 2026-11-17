//! Counts the log lines that say a frame failed authentication (the cross-version decryption
//! signature), across every node in the test process.

use std::sync::atomic::{AtomicUsize, Ordering};

static FAILURES: AtomicUsize = AtomicUsize::new(0);

const SIGNATURES: [&str; 2] = ["AEAD decrypt_in_place failed", "AES-GCM stage failed"];

pub struct AeadFailures;

struct Counter;

impl log::Log for Counter {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = record.args().to_string();
        if SIGNATURES.iter().any(|signature| line.contains(signature)) {
            FAILURES.fetch_add(1, Ordering::SeqCst);
        }
        eprintln!("{} {}: {line}", record.level(), record.target());
    }

    fn flush(&self) {}
}

impl AeadFailures {
    /// Installs the counter as the process's `log` logger. Call before `setup_log`, which then
    /// leaves it in place.
    pub fn install() -> Self {
        log::set_logger(&Counter).expect("the first logger of this test process");
        log::set_max_level(log::LevelFilter::Warn);
        AeadFailures
    }

    pub fn count(&self) -> usize {
        FAILURES.load(Ordering::SeqCst)
    }
}
