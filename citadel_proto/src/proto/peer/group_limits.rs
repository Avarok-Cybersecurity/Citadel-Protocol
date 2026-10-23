//! Server-side admission of a group message against its group's [`GroupMessageLimits`].
//!
//! The size cap applies to the ciphertext the server relays (it never decrypts a group message).
//! The rate cap applies to each sender on its own, so one busy member cannot spend the others'
//! allowance: a sender may send `max_messages_per_second` messages in a window that opens with
//! its first message and lasts one second. A refused message does not count against the rate.
//! Pure: no I/O, and the clock is the caller's.

use citadel_io::time::{Duration, Instant};
use citadel_types::proto::{GroupMessageLimits, GroupMessageRefusal};
use std::collections::HashMap;

const WINDOW: Duration = Duration::from_secs(1);

#[derive(Copy, Clone, Debug)]
struct SenderWindow {
    opened: Instant,
    sent: u32,
}

/// Each sender's current rate window in one group. Holds only windows still open, so it is
/// bounded by the senders active in the last second.
#[derive(Default, Debug)]
pub(crate) struct GroupRateLedger {
    windows: HashMap<u64, SenderWindow>,
}

/// Whether `sender` may send a message of `bytes` to a group with `limits` at `now`; when it may,
/// the message is counted against the sender's rate.
pub(crate) fn admit(
    limits: Option<&GroupMessageLimits>,
    ledger: &mut GroupRateLedger,
    sender: u64,
    bytes: usize,
    now: Instant,
) -> Result<(), GroupMessageRefusal> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let max_bytes = limits.max_message_bytes();
    if bytes as u64 > u64::from(max_bytes) {
        return Err(GroupMessageRefusal::TooLarge {
            bytes: bytes as u64,
            max_bytes,
        });
    }
    ledger
        .windows
        .retain(|_, window| now.saturating_duration_since(window.opened) < WINDOW);
    let window = ledger.windows.entry(sender).or_insert(SenderWindow {
        opened: now,
        sent: 0,
    });
    let max_per_second = limits.max_messages_per_second();
    if window.sent >= max_per_second {
        return Err(GroupMessageRefusal::RateLimited { max_per_second });
    }
    window.sent += 1;
    Ok(())
}

#[cfg(test)]
#[path = "group_limits_tests.rs"]
mod tests;
