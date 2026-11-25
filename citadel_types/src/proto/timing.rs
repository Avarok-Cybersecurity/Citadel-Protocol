//! The protocol's connect and stage timers, in one place (`ROBUST-CONNECTION-MANAGER.md` S-P5,
//! S-W1). Each value used to be written where it was read, across three crates, and the ones
//! derived from another (the posting TTL from the connect wait) were derived by hand.

use std::time::Duration;

/// One transport connect step to a server: a TCP connect, a TLS handshake, a QUIC upgrade, a
/// WebSocket handshake.
pub const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// A connect to a TURN server, which may sit across the internet rather than beside the Citadel
/// server: two and a half transport steps.
pub const TURN_CONNECT_TIMEOUT: Duration =
    Duration::from_millis(TRANSPORT_CONNECT_TIMEOUT.as_millis() as u64 * 5 / 2);

/// One P2P path stage planned without a stamped plan (the hole punch with its QUIC handshake, or
/// one TURN attempt), and the wait for the peer at a retry's rendezvous.
pub const P2P_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a P2P dial waits for the peer's answer through the server.
pub const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the server holds a dial's posting beyond the dialler's own wait, so the answer to a
/// dial still waited for is never refused for want of its posting.
pub const POSTING_SLACK: Duration = Duration::from_secs(5);

/// How long the server holds a P2P dial's posting.
pub const POSTING_TTL: Duration = Duration::from_millis(
    P2P_CONNECT_TIMEOUT.as_millis() as u64 + POSTING_SLACK.as_millis() as u64,
);

/// The deadline, 15 s, for the receiver to answer one file-transfer group's header. Past it the
/// sender fails the transfer with `ErrorCode::FileTransferStalled`. The clock runs only while no
/// earlier group of the session is still in flight: every header and payload of a session
/// shares one primary stream, so a header queued behind another group's payload is not the
/// receiver's to answer until that payload has drained.
///
/// What it is sized against. The header travels on a channel that is already established, and
/// the receiver answers it as soon as it reads it, so the wait is one round trip on that channel.
/// The worst round trip assumed is that of a relayed link across the internet. The protocol
/// keeps no measured round-trip time or per-packet ack timeout to size this against (its
/// keep-alive timeout is 45 minutes, sized for idle sessions, not for answers), so the yardstick
/// is [`TURN_CONNECT_TIMEOUT`] (10 s): the time this protocol already allows a TURN connect across
/// the internet, which is two and a half handshake round trips over the same kind of path. One
/// round trip on an established relayed channel therefore fits well inside 10 s; the deadline is
/// half again as long, for a loaded relay.
///
/// The latest the failure is reported is this deadline plus one [`FILE_GROUP_CHECK_PERIOD`]
/// (1 s): [`FILE_GROUP_HEADER_UNANSWERED_FAILS_WITHIN`], 16 s.
///
/// How long a header can stay queued. It waits only while an earlier group of the session is in
/// flight, and each of those is bounded in turn: it completes, or its own unanswered header
/// fails within 16 s once first in line, or, answered, it is failed once its acks stop for
/// `GROUP_EXPIRE_TIME_MS` (60 s) on a silent session or ten times that (600 s) on a busy one. The
/// earlier groups run those clocks at the same time, not one after another, so a header queued
/// behind groups that have all stalled is failed at most about 600 s + 16 s after it was sent.
/// Behind groups that keep moving it waits as long as they move: that is a queue, not a stall.
pub const FILE_GROUP_HEADER_ACK_DEADLINE: Duration =
    Duration::from_millis(TURN_CONNECT_TIMEOUT.as_millis() as u64 * 3 / 2);

/// How often a sender checks each of its outbound file-transfer groups: 1 s. A check is a map
/// lookup and two clock reads per group (plus, while the header is unanswered, a scan of the
/// session's few outbound groups), so a short period is cheap, and it keeps the time to report
/// a missed deadline close to the deadline itself.
pub const FILE_GROUP_CHECK_PERIOD: Duration = Duration::from_secs(1);

/// The worst case for reporting an unanswered group header, counted from when the header was
/// first in line: [`FILE_GROUP_HEADER_ACK_DEADLINE`] (15 s) plus one [`FILE_GROUP_CHECK_PERIOD`]
/// (1 s), because the deadline can pass just after a check: 16 s. This is the figure the
/// workspace UI's idle timeout for a file send (30 s, the parent repository's
/// `TIMEOUT.FILE_SEND_MS`) must exceed, so the coded failure is what a person sees; it leaves
/// 14 s between them. The SDK cannot read the UI's constant; the parent asserts the ordering.
pub const FILE_GROUP_HEADER_UNANSWERED_FAILS_WITHIN: Duration = Duration::from_millis(
    FILE_GROUP_HEADER_ACK_DEADLINE.as_millis() as u64 + FILE_GROUP_CHECK_PERIOD.as_millis() as u64,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derived_timers_keep_their_values() {
        assert_eq!(TURN_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(POSTING_TTL, Duration::from_secs(65));
        assert!(POSTING_TTL > P2P_CONNECT_TIMEOUT);
        assert_eq!(FILE_GROUP_HEADER_ACK_DEADLINE, Duration::from_secs(15));
        assert!(FILE_GROUP_HEADER_ACK_DEADLINE > TURN_CONNECT_TIMEOUT);
        assert_eq!(FILE_GROUP_CHECK_PERIOD, Duration::from_secs(1));
        assert_eq!(
            FILE_GROUP_HEADER_UNANSWERED_FAILS_WITHIN,
            Duration::from_secs(16)
        );
    }
}
