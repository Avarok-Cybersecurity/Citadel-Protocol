use std::fmt::Formatter;

#[derive(Copy, Clone)]
pub struct TimeTracker;

impl TimeTracker {
    pub fn new() -> Self { Self }

    // This should work for about a hundred years before modulo'ing around back to zero
    pub fn get_global_time_ns(&self) -> i64 {
        (std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos() % i64::MAX as u128) as i64
    }
}

impl std::fmt::Debug for TimeTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Time tracker current global time: {}ns", self.get_global_time_ns())
    }
}
