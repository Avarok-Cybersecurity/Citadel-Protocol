//! A session that ends abruptly must resolve the caller's `disconnect()`, not
//! the kernel's ticket.
//!
//! `send_session_dc_signal` fires ONCE per session — `try_c2s_disconnect` sees
//! to that — and it routes by `(ticket, cid)`. So whichever path signals first
//! decides which subscription hears about it, and every later path is silently
//! suppressed as a duplicate.
//!
//! `execute`'s error arm passed `Some(kernel_ticket)`, which takes the
//! `(Some(explicit), _)` branch and skips `pending_c2s_disconnect_ticket` — the
//! field that exists for exactly this case, whose own comment says an
//! application-initiated disconnect must resolve with ITS ticket even when the
//! session ends abruptly. So when the stream ended between `disconnect()`
//! sending STAGE0 and the FINAL being processed, the signal went to a key nobody
//! held, the FINAL handler's correct signal was suppressed, and the caller's
//! subscription received nothing for thirty seconds.
//!
//! WHAT THIS TEST DOES NOT DO.
//!
//! The behavioural test needs a lost FINAL staged on a live session, which the
//! harness cannot currently express. This is a source scan: it catches the arm
//! being changed BACK, which is the realistic regression, and it cannot catch a
//! `None` that reaches a different match. Said here rather than implied, because
//! the fix it guards was itself found only after an earlier refutation of mine
//! checked the happy path and stopped.

use std::fs;
use std::path::Path;

fn session_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proto/session.rs");
    let text = fs::read_to_string(&path).expect("session.rs must be readable");
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_stream_ending_does_not_claim_the_disconnect_ticket() {
    let code = session_source();
    assert!(
        code.contains(r#"send_session_dc_signal(None, false, "Inbound stream ending")"#),
        "the inbound-stream-ending signal no longer passes None.\n\
         Passing Some(kernel_ticket) takes the (Some(explicit), _) branch, which skips \
         pending_c2s_disconnect_ticket — so an application's disconnect() is answered on a \
         ticket nobody holds, and try_c2s_disconnect then suppresses the FINAL handler's \
         correct signal as a duplicate. The caller waits out its 30s budget and reports \
         RemoteDisconnectEventMissing.",
    );
}

#[test]
fn the_pending_ticket_fallback_still_exists_for_it_to_reach() {
    // The arm above is only correct while the fallback is there to catch it.
    // Removing the (None, Some(pending)) branch would leave `None` resolving to
    // the kernel ticket — the same defect, reached from the other side.
    let code = session_source();
    assert!(
        code.contains("pending_c2s_disconnect_ticket.take()"),
        "the pending-disconnect ticket is no longer consumed when the signal is sent",
    );
    assert!(
        code.contains("(None, Some(pending)) => (pending, true)"),
        "the fallback that resolves an application disconnect on ITS ticket is gone, \
         so passing None now resolves to the kernel ticket instead",
    );
}

#[test]
fn the_signal_is_still_once_per_session() {
    // The whole hazard rests on this. If the gate were ever removed the ordering
    // would stop mattering and these assertions would be guarding nothing — a
    // change that makes this file pointless should say so out loud.
    let code = session_source();
    assert!(
        code.contains("disconnect_tracker.try_c2s_disconnect(session_ticket)"),
        "the once-per-session gate is gone; if that is deliberate, this file's \
         premise no longer holds and it should be revisited rather than left passing",
    );
}
