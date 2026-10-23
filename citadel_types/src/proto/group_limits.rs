//! The caps a server holds a group's messages to, and the refusal a sender gets over one.
//!
//! A group created with [`GroupMessageLimits`] has every `GroupBroadcast::Message` checked by its
//! server before the fan-out: one larger than `max_message_bytes` (the end-to-end ciphertext the
//! server relays, which it can measure and never decrypts) or beyond a sender's
//! `max_messages_per_second` is refused, and the sender is told why with a
//! [`GroupMessageRefusal`]. A group without limits is relayed as before.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// The per-group caps on message size and rate, enforced by the server.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UncheckedGroupMessageLimits")]
pub struct GroupMessageLimits {
    max_message_bytes: u32,
    max_messages_per_second: u32,
}

/// Why [`GroupMessageLimits::new`] refused its arguments.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum GroupMessageLimitsError {
    /// A size cap of zero would refuse every message.
    ZeroMessageBytes,
    /// A rate cap of zero would refuse every message.
    ZeroMessagesPerSecond,
}

impl Display for GroupMessageLimitsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMessageBytes => write!(f, "max_message_bytes must be at least 1"),
            Self::ZeroMessagesPerSecond => write!(f, "max_messages_per_second must be at least 1"),
        }
    }
}

impl std::error::Error for GroupMessageLimitsError {}

impl GroupMessageLimits {
    /// Caps each message at `max_message_bytes` of relayed ciphertext, and each sender at
    /// `max_messages_per_second` messages in any one-second window. Neither may be zero.
    pub fn new(
        max_message_bytes: u32,
        max_messages_per_second: u32,
    ) -> Result<Self, GroupMessageLimitsError> {
        if max_message_bytes == 0 {
            return Err(GroupMessageLimitsError::ZeroMessageBytes);
        }
        if max_messages_per_second == 0 {
            return Err(GroupMessageLimitsError::ZeroMessagesPerSecond);
        }
        Ok(Self {
            max_message_bytes,
            max_messages_per_second,
        })
    }

    pub fn max_message_bytes(&self) -> u32 {
        self.max_message_bytes
    }

    pub fn max_messages_per_second(&self) -> u32 {
        self.max_messages_per_second
    }
}

/// The wire shape, validated into [`GroupMessageLimits`] as it is read.
#[derive(Deserialize)]
struct UncheckedGroupMessageLimits {
    max_message_bytes: u32,
    max_messages_per_second: u32,
}

impl TryFrom<UncheckedGroupMessageLimits> for GroupMessageLimits {
    type Error = GroupMessageLimitsError;

    fn try_from(value: UncheckedGroupMessageLimits) -> Result<Self, Self::Error> {
        Self::new(value.max_message_bytes, value.max_messages_per_second)
    }
}

/// Why the server refused to relay a group message. The message reached nobody.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupMessageRefusal {
    /// The message's relayed ciphertext was `bytes` long; the group allows `max_bytes`.
    TooLarge { bytes: u64, max_bytes: u32 },
    /// The sender already sent `max_per_second` messages to the group in this one-second window.
    RateLimited { max_per_second: u32 },
}

impl Display for GroupMessageRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes, max_bytes } => write!(
                f,
                "the group message is {bytes} bytes; the group allows at most {max_bytes}"
            ),
            Self::RateLimited { max_per_second } => write!(
                f,
                "the group allows each sender at most {max_per_second} messages per second"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_refuse_a_zero_cap() {
        assert_eq!(
            GroupMessageLimits::new(0, 4),
            Err(GroupMessageLimitsError::ZeroMessageBytes)
        );
        assert_eq!(
            GroupMessageLimits::new(16, 0),
            Err(GroupMessageLimitsError::ZeroMessagesPerSecond)
        );
        let limits = GroupMessageLimits::new(16, 4).unwrap();
        assert_eq!(
            (limits.max_message_bytes(), limits.max_messages_per_second()),
            (16, 4)
        );
    }

    #[test]
    fn limits_are_validated_as_they_are_read() {
        let valid = bincode::serialize(&GroupMessageLimits::new(16, 4).unwrap()).unwrap();
        let read: GroupMessageLimits = bincode::deserialize(&valid).unwrap();
        assert_eq!(read, GroupMessageLimits::new(16, 4).unwrap());
        let zero = bincode::serialize(&(0u32, 4u32)).unwrap();
        assert!(bincode::deserialize::<GroupMessageLimits>(&zero).is_err());
    }
}
