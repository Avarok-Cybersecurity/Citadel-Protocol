//! A session that ENDED keeps its resume token for the admission grace: its client's
//! reconnect within it is not asked the check again; after it, or with the token spent, it is.
//! Every instant is explicit, so none of this waits on a clock.
use super::*;

const GRACE: Duration = Duration::from_secs(900);
const CID: u64 = 7;

fn ended(token: ResumeToken, at: Instant) -> EndedSessions {
    let mut ended = EndedSessions::default();
    ended.on_session_end(CID, token, at, GRACE);
    ended
}

#[test]
fn a_resume_within_the_grace_is_recognised() {
    let token = ResumeToken::generate();
    let at = Instant::now();
    let ended = ended(token, at);
    assert!(ended.recognises(CID, &token, at));
    assert!(ended.recognises(CID, &token, at + GRACE - Duration::from_millis(1)));
}

#[test]
fn after_the_grace_it_is_not() {
    let token = ResumeToken::generate();
    let at = Instant::now();
    let ended = ended(token, at);
    assert!(!ended.recognises(CID, &token, at + GRACE));
    assert!(!ended.recognises(CID, &token, at + GRACE + Duration::from_secs(1)));
}

#[test]
fn a_token_is_spent_once_a_session_for_its_cid_is_admitted() {
    let first = ResumeToken::generate();
    let at = Instant::now();
    let mut ended = ended(first, at);
    ended.on_session_admitted(CID);
    assert!(
        !ended.recognises(CID, &first, at),
        "a spent token was honoured"
    );

    // The session the resume admitted ends in turn: only ITS token counts, never the first.
    let second = ResumeToken::generate();
    ended.on_session_end(CID, second, at, GRACE);
    assert!(ended.recognises(CID, &second, at));
    assert!(
        !ended.recognises(CID, &first, at),
        "a reused token was honoured"
    );
}

#[test]
fn a_token_counts_only_for_its_own_cid() {
    let token = ResumeToken::generate();
    let at = Instant::now();
    let ended = ended(token, at);
    assert!(!ended.recognises(CID + 1, &token, at));
    assert!(!ended.recognises(CID, &ResumeToken::generate(), at));
}

#[test]
fn a_zero_grace_remembers_nothing() {
    let token = ResumeToken::generate();
    let at = Instant::now();
    let mut ended = EndedSessions::default();
    ended.on_session_end(CID, token, at, Duration::ZERO);
    assert!(!ended.recognises(CID, &token, at));
    assert_eq!(ended.len(), 0);
}

#[test]
fn expired_entries_are_dropped_on_the_next_end() {
    let at = Instant::now();
    let mut ended = ended(ResumeToken::generate(), at);
    ended.on_session_end(CID + 1, ResumeToken::generate(), at + GRACE, GRACE);
    assert_eq!(ended.len(), 1, "an expired entry outlived its grace");
}

#[test]
fn an_ended_session_keeps_its_own_token_not_the_one_it_resumed_from() {
    let older = ResumeToken::generate();
    let issued = ResumeToken::generate();
    let held = HeldSessionResume::admitted(issued, Some(older));
    assert!(held.issued().is_some_and(|token| token.same_as(&issued)));
}
