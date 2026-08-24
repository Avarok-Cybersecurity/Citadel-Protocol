use crate::error::MediaError;

/// Tunables for the media layer. Every field is mandatory; construct explicitly
/// and call [`MediaConfig::validate`] before use. No defaults are provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaConfig {
    /// Maximum payload bytes per fragment (excluding the 20-byte wire header).
    pub max_fragment_payload: usize,
    /// Maximum bytes of a single logical frame; larger frames are rejected before allocation.
    pub max_frame_bytes: usize,
    /// Frames older than `next_expected - max_reorder_window` are TooOld; within it, Late.
    pub max_reorder_window: u32,
    /// How long a gap is tolerated before the jitter buffer skips past it.
    pub jitter_depth_micros: u64,
    /// Upper bound on partially reassembled frames held at once (DoS bound).
    pub max_pending_frames: usize,
}

impl MediaConfig {
    pub const fn validate(&self) -> Result<(), MediaError> {
        if self.max_fragment_payload == 0 {
            return Err(MediaError::InvalidConfig(
                "max_fragment_payload must be > 0",
            ));
        }
        if self.max_frame_bytes == 0 {
            return Err(MediaError::InvalidConfig("max_frame_bytes must be > 0"));
        }
        if self.max_reorder_window == 0 {
            return Err(MediaError::InvalidConfig("max_reorder_window must be > 0"));
        }
        if self.jitter_depth_micros == 0 {
            return Err(MediaError::InvalidConfig("jitter_depth_micros must be > 0"));
        }
        if self.max_pending_frames == 0 {
            return Err(MediaError::InvalidConfig("max_pending_frames must be > 0"));
        }
        if self.max_frame_bytes > self.max_fragment_payload.saturating_mul(u16::MAX as usize) {
            return Err(MediaError::InvalidConfig(
                "max_frame_bytes exceeds max_fragment_payload * u16::MAX",
            ));
        }
        if self.max_frame_bytes > u32::MAX as usize {
            return Err(MediaError::InvalidConfig(
                "max_frame_bytes exceeds u32::MAX",
            ));
        }
        Ok(())
    }

    /// Number of fragments needed for `len` payload bytes (at least 1 so empty frames travel).
    pub const fn fragment_count_for(&self, len: usize) -> usize {
        if len == 0 {
            1
        } else {
            len.div_ceil(self.max_fragment_payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Test-only baseline (PCND: production callers must construct explicitly).
    pub(crate) const VALID: MediaConfig = MediaConfig {
        max_fragment_payload: 1100,
        max_frame_bytes: 1 << 20,
        max_reorder_window: 64,
        jitter_depth_micros: 50_000,
        max_pending_frames: 32,
    };

    #[test]
    fn valid_config_passes() {
        assert_eq!(VALID.validate(), Ok(()));
    }

    #[rstest]
    #[case(MediaConfig { max_fragment_payload: 0, ..VALID })]
    #[case(MediaConfig { max_frame_bytes: 0, ..VALID })]
    #[case(MediaConfig { max_reorder_window: 0, ..VALID })]
    #[case(MediaConfig { jitter_depth_micros: 0, ..VALID })]
    #[case(MediaConfig { max_pending_frames: 0, ..VALID })]
    #[case(MediaConfig { max_fragment_payload: 1, max_frame_bytes: u16::MAX as usize + 1, ..VALID })]
    fn invalid_configs_fail(#[case] cfg: MediaConfig) {
        assert!(matches!(cfg.validate(), Err(MediaError::InvalidConfig(_))));
    }

    #[test]
    fn fragment_count() {
        assert_eq!(VALID.fragment_count_for(0), 1);
        assert_eq!(VALID.fragment_count_for(1100), 1);
        assert_eq!(VALID.fragment_count_for(1101), 2);
        assert_eq!(VALID.fragment_count_for(3 * 1100 + 1), 4);
    }
}
