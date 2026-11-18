//! The message floor of a negotiated key epoch (§5.3 C1, C4, C5).
//!
//! Once the peer retires an epoch it has said it will send nothing more under that epoch's
//! version, so a later message frame under an older version is not a straggler but a violation
//! (C4). The same holds for a message frame below the agreed level (C5): a peer that agreed
//! Extreme cannot quietly keep sending Standard. Ratchet control frames are exempt; they carry
//! their own version logic. A refused frame keeps its place in both orderings of the channel, so
//! the frames after it are not held back, and the application never sees it.

use crate::proto::session::UserMessage;
use citadel_crypt::messaging::MessengerLayerOrderedMessage;
use citadel_crypt::ratchets::ratchet_manager::RatchetMessage;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::Mutex;
use citadel_negotiation::ViolationKind;
use citadel_types::crypto::{SecBuffer, SecurityLevel};

type Frame = RatchetMessage<MessengerLayerOrderedMessage<UserMessage>>;

/// The oldest version and the lowest level a message frame from the peer may still use.
#[derive(Copy, Clone, Debug)]
pub struct Floor {
    pub version: u32,
    pub level: SecurityLevel,
}

/// A message frame the floor refused.
#[derive(Copy, Clone, Debug)]
pub struct FloorViolation {
    pub kind: ViolationKind,
    /// The version and level the refused frame's (authenticated) header named.
    pub version: u32,
    pub level: SecurityLevel,
}

// `SecurityLevel` has no `PartialEq`; levels compare by `value()`, as everywhere else.
impl PartialEq for Floor {
    fn eq(&self, other: &Self) -> bool {
        (self.version, self.level.value()) == (other.version, other.level.value())
    }
}

impl Eq for Floor {}

impl PartialEq for FloorViolation {
    fn eq(&self, other: &Self) -> bool {
        (self.kind, self.version, self.level.value())
            == (other.kind, other.version, other.level.value())
    }
}

impl Eq for FloorViolation {}

/// Whether a message frame under `version` at `level` is above `floor`. Pure.
pub fn check(
    floor: Option<Floor>,
    version: u32,
    level: SecurityLevel,
) -> Result<(), ViolationKind> {
    let Some(floor) = floor else {
        return Ok(());
    };
    if version < floor.version {
        return Err(ViolationKind::BelowFloor);
    }
    if level.value() < floor.level.value() {
        return Err(ViolationKind::LevelBelowAgreed);
    }
    Ok(())
}

/// C1: the level a message is sealed at under a version with `layers` layers. On a link whose
/// level was negotiated, a message queued at the previous epoch's higher level can be sealed
/// after a lowered epoch took over; it goes out at the agreed level, which is all the version
/// carries. Elsewhere the requested level is kept, and a level the ratchet cannot carry stays the
/// error it always was.
pub fn seal_level(requested: SecurityLevel, layers: usize, negotiated: bool) -> SecurityLevel {
    let carried = u8::try_from(layers.saturating_sub(1)).unwrap_or(u8::MAX);
    if negotiated && requested.value() > carried {
        SecurityLevel::from(carried)
    } else {
        requested
    }
}

/// One connection's floor, raised as the peer retires epochs, and the violations it refused.
pub struct MessageFloor {
    floor: Mutex<Option<Floor>>,
    violations_tx: UnboundedSender<FloorViolation>,
    violations_rx: Mutex<Option<UnboundedReceiver<FloorViolation>>>,
}

impl MessageFloor {
    pub fn new() -> Self {
        let (violations_tx, violations_rx) = unbounded_channel();
        Self {
            floor: Mutex::new(None),
            violations_tx,
            violations_rx: Mutex::new(Some(violations_rx)),
        }
    }

    pub fn get(&self) -> Option<Floor> {
        *self.floor.lock()
    }

    /// Moves the floor to a newer version's; an older or equal version leaves it as it is.
    pub fn raise(&self, floor: Floor) {
        let mut current = self.floor.lock();
        if current.is_none_or(|current| floor.version > current.version) {
            *current = Some(floor);
        }
    }

    /// Every refused frame, once (`None` after the first call).
    pub fn take_violations(&self) -> Option<UnboundedReceiver<FloorViolation>> {
        self.violations_rx.lock().take()
    }

    /// Screens one inbound frame: a user message below the floor is emptied and marked refused
    /// in place, and the violation reported.
    pub fn screen(&self, version: u32, level: SecurityLevel, frame: &mut Frame) {
        let message = match frame {
            RatchetMessage::JustMessage(message)
            | RatchetMessage::AliceToBob {
                attached_payload: Some(message),
                ..
            } => &mut message.message,
            _ => return,
        };
        if let Err(kind) = check(self.get(), version, level) {
            log::warn!(target: "citadel", "Refusing a message frame under v{version} at {level:?}: {kind:?} (floor {:?})", self.get());
            message.refused = true;
            message.packet = SecBuffer::empty();
            let _ = self.violations_tx.send(FloorViolation {
                kind,
                version,
                level,
            });
        }
    }
}

impl Default for MessageFloor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGREED: Floor = Floor {
        version: 7,
        level: SecurityLevel::Extreme,
    };

    #[test]
    fn without_a_floor_everything_passes() {
        assert_eq!(check(None, 0, SecurityLevel::Standard), Ok(()));
    }

    #[test]
    fn a_version_below_the_floor_is_refused() {
        assert_eq!(
            check(Some(AGREED), 6, SecurityLevel::Extreme),
            Err(ViolationKind::BelowFloor)
        );
    }

    #[test]
    fn a_level_below_the_agreed_one_is_refused() {
        assert_eq!(
            check(Some(AGREED), 7, SecurityLevel::High),
            Err(ViolationKind::LevelBelowAgreed)
        );
    }

    #[test]
    fn the_floor_and_above_pass() {
        assert_eq!(check(Some(AGREED), 7, SecurityLevel::Extreme), Ok(()));
        assert_eq!(check(Some(AGREED), 9, SecurityLevel::Custom(6)), Ok(()));
    }

    #[test]
    fn the_floor_only_rises() {
        let floor = MessageFloor::new();
        floor.raise(AGREED);
        floor.raise(Floor {
            version: 3,
            level: SecurityLevel::Standard,
        });
        assert_eq!(floor.get(), Some(AGREED));
        let lowered = Floor {
            version: 8,
            level: SecurityLevel::Standard,
        };
        floor.raise(lowered);
        assert_eq!(
            floor.get(),
            Some(lowered),
            "a later, lowered epoch moves it"
        );
    }

    #[test]
    fn a_queued_higher_level_is_sealed_at_what_a_lowered_epoch_carries() {
        let sealed =
            |requested, layers, negotiated| seal_level(requested, layers, negotiated).value();
        assert_eq!(sealed(SecurityLevel::Extreme, 1, true), 0);
        assert_eq!(sealed(SecurityLevel::High, 5, true), 2);
        assert_eq!(
            sealed(SecurityLevel::Extreme, 1, false),
            4,
            "a link that negotiated nothing keeps the error a too-high level always was"
        );
    }
}
