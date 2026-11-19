//! The most security layers a node builds a link with.
//!
//! A security level is the number of stacked ratchet layers minus one, and every layer costs a
//! full key exchange to build and one more seal on every packet. A level read from a peer or a
//! server therefore decides how much work this node does, so a node states the most it will
//! build ([`MaxSecurityLevel`]) and refuses anything above it before building anything.

use super::SecurityLevel;
use std::fmt::{Display, Formatter};

/// The highest level a stacked ratchet can carry at all: its layer count (level + 1) must stay
/// below `u8::MAX`. No configured maximum may exceed it.
pub const STRUCTURAL_MAX_LEVEL: u8 = u8::MAX - 2;

/// The most security layers this node builds a link with, from any offer, stamp or transfer.
/// Required node configuration: there is no default.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MaxSecurityLevel(u8);

/// A level above a node's maximum, or above what a ratchet can carry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LevelAboveMaximum {
    /// The refused level's value.
    pub level: u8,
    pub maximum: u8,
}

impl Display for LevelAboveMaximum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "security level {:?} is above this node's maximum, {:?}",
            SecurityLevel::from(self.level),
            SecurityLevel::from(self.maximum)
        )
    }
}

impl std::error::Error for LevelAboveMaximum {}

impl MaxSecurityLevel {
    /// Fails on a maximum no ratchet can be built at.
    pub fn new(level: SecurityLevel) -> Result<Self, LevelAboveMaximum> {
        if level.value() > STRUCTURAL_MAX_LEVEL {
            return Err(LevelAboveMaximum {
                level: level.value(),
                maximum: STRUCTURAL_MAX_LEVEL,
            });
        }
        Ok(Self(level.value()))
    }

    pub fn level(self) -> SecurityLevel {
        SecurityLevel::from(self.0)
    }

    pub fn admits(self, level: SecurityLevel) -> bool {
        level.value() <= self.0
    }

    pub fn check(self, level: SecurityLevel) -> Result<(), LevelAboveMaximum> {
        if self.admits(level) {
            Ok(())
        } else {
            Err(LevelAboveMaximum {
                level: level.value(),
                maximum: self.0,
            })
        }
    }
}

/// Whether a ratchet of `level` can be built at all, whatever a node allows.
pub fn check_structural(level: SecurityLevel) -> Result<(), LevelAboveMaximum> {
    MaxSecurityLevel(STRUCTURAL_MAX_LEVEL).check(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_maximum_admits_itself_and_below_and_nothing_above() {
        let max = MaxSecurityLevel::new(SecurityLevel::Extreme).unwrap();
        assert!(max.admits(SecurityLevel::Standard));
        assert!(max.admits(SecurityLevel::Extreme));
        assert!(!max.admits(SecurityLevel::Custom(5)));
        assert!(!max.admits(SecurityLevel::Custom(254)));
        assert_eq!(
            max.check(SecurityLevel::Custom(254)),
            Err(LevelAboveMaximum {
                level: 254,
                maximum: 4
            })
        );
    }

    #[test]
    fn no_maximum_exceeds_what_a_ratchet_can_carry() {
        assert!(MaxSecurityLevel::new(SecurityLevel::Custom(STRUCTURAL_MAX_LEVEL)).is_ok());
        assert!(MaxSecurityLevel::new(SecurityLevel::Custom(254)).is_err());
        assert!(MaxSecurityLevel::new(SecurityLevel::Custom(255)).is_err());
        assert!(check_structural(SecurityLevel::Custom(253)).is_ok());
        assert!(check_structural(SecurityLevel::Custom(254)).is_err());
    }
}
