/// A caller-supplied monotonic timestamp in microseconds.
///
/// The crate never reads a clock; every time-dependent operation takes a
/// `MediaInstant` from the caller so the logic stays pure and testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaInstant(u64);

impl MediaInstant {
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub const fn saturating_add_micros(self, micros: u64) -> Self {
        Self(self.0.saturating_add(micros))
    }

    /// Microseconds elapsed from `earlier` to `self`; zero if `earlier` is later.
    pub const fn micros_since(self, earlier: MediaInstant) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_is_saturating() {
        let a = MediaInstant::from_micros(10);
        let b = MediaInstant::from_micros(25);
        assert_eq!(b.micros_since(a), 15);
        assert_eq!(a.micros_since(b), 0);
        assert_eq!(
            MediaInstant::from_micros(u64::MAX).saturating_add_micros(1),
            MediaInstant::from_micros(u64::MAX)
        );
        assert!(a < b);
    }
}
