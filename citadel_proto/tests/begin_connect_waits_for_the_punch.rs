//! BEGIN_CONNECT must not be answered before this side's own hole punch has
//! resolved.
//!
//! The preconnect SUCCESS handler sets `pre_connect_state.success` from the
//! PEER's packet, and the connect STAGE0 gate asks only for that. Inbound
//! packets are processed concurrently, so without a wait the STAGE0 handler that
//! installs the UDP one-shot is still pending when this side replies — and the
//! initiator's connect STAGE0 then takes a receiver that was never installed.
//!
//! Two consequences, only one of which is a test failure: the peer asserts a UDP
//! channel this side never had (an intermittent citadel_sdk failure, three times
//! in thirty days), and the late install hands a fresh pair to nobody while the
//! loader sends into it through an unbounded channel — every datagram
//! accumulating unread for the session's lifetime.
//!
//! WHY A SOURCE SCAN, AND WHAT IT DOES NOT DO.
//!
//! The behavioural test wants a `PlatformOps` whose `c2s_hole_punch` returns
//! late — nine associated types and twenty-one methods of delegation — and it is
//! recorded as the better instrument. This is the cheap half: it catches the
//! wait being DELETED, which is the realistic regression, and it cannot catch a
//! wait that is present and wrong. Stated here rather than implied, because a
//! guard that is believed to do more than it does is worse than one that is
//! known to do less.
//!
//! The manual control that established the fix: a 50ms sleep between the punch
//! and the install made 4 of 6 `test_single_connection_transient` cases fail
//! without the wait and 6 of 6 pass with it. Note the placement — a delay BEFORE
//! the punch stalls the initiator too, which is why an earlier investigation
//! recorded this hypothesis as "DISPROVEN".

use std::fs;
use std::path::Path;

#[test]
fn the_preconnect_success_handler_waits_for_the_local_punch() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proto/packet_processor/preconnect_packet.rs");
    let text = fs::read_to_string(&source).expect("preconnect_packet.rs must be readable");

    // Comments describe the wait; they do not perform it.
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for needle in [
        // The signal both branches of the STAGE0 handler set.
        "PUNCH_RESOLVE_WAIT",
        // The re-check, which is what makes it a wait rather than one look.
        "PUNCH_RESOLVE_POLL",
        // The condition itself: this side's own stage, not the peer's flag.
        "do_preconnect::SUCCESS",
    ] {
        assert!(
            code.contains(needle),
            "preconnect_packet.rs no longer mentions `{needle}` in code.\n\
             The SUCCESS handler must wait for this side's hole punch to resolve \
             before answering BEGIN_CONNECT, or the initiator's connect STAGE0 \
             takes a UDP receiver that has not been installed yet — an \
             intermittent test failure and an unbounded channel nobody drains.",
        );
    }

    // The wait has to be AWAITED. A constant that nothing sleeps on is the
    // shape this file exists to prevent.
    assert!(
        code.contains("sleep(PUNCH_RESOLVE_POLL).await"),
        "PUNCH_RESOLVE_POLL is named but never awaited, so the handler does not wait.",
    );
}

#[test]
fn both_punch_outcomes_still_set_the_stage_the_wait_reads() {
    // The wait keys on `last_stage == SUCCESS`, and it is bounded — so a branch
    // that stopped setting it would not hang, it would silently spend the whole
    // timeout and then answer anyway, restoring the race with a five-second
    // pause in front of it. That is worse than the original.
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proto/packet_processor/preconnect_packet.rs");
    let text = fs::read_to_string(&source).expect("preconnect_packet.rs must be readable");
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // The TCP-only fallback sets it directly.
    assert!(
        code.contains("pre_connect_state.last_stage =") && code.contains("do_preconnect::SUCCESS"),
        "the TCP-only fallback no longer records that the punch resolved",
    );
    // The success path sets it inside handle_success_as_receiver.
    let handler = code
        .split("fn handle_success_as_receiver")
        .nth(1)
        .expect("handle_success_as_receiver must exist");
    assert!(
        handler.contains("last_stage = packet_flags::cmd::aux::do_preconnect::SUCCESS"),
        "handle_success_as_receiver no longer records that the punch resolved, \
         so the wait above it can only ever time out",
    );
}
