//! A party to a commit wait whose session is replaced (a reconnect under the same cid).

use super::tests::{set, KEY};
use super::*;
use std::time::Duration;

/// Two sessions of one cid: `replaced`, then the one that replaced it.
fn sessions() -> (Instant, Instant) {
    let replaced = Instant::now();
    (replaced, replaced + Duration::from_millis(1))
}

/// A member is replaced mid-commit and the new session never acknowledges the earlier Commit:
/// it never received it, and it rejoins at the current epoch. The wait was on the session the
/// Commit was delivered to, so that session's end settles it, whenever it lands; it does not
/// wait on the replacement.
#[test]
fn a_member_replaced_mid_commit_settles_the_wait_when_its_old_session_ends() {
    let (replaced, replacement) = sessions();
    let mut gates = CommitGates::default();
    let awaiting = HashMap::from([(2, Some(replaced)), (3, None)]);
    assert_eq!(gates.open(KEY, 3, None, awaiting), None);
    assert_eq!(
        gates.applied(KEY, 3, 3),
        None,
        "member 2 has not applied it"
    );
    assert_eq!(
        gates.session_ended(2, replacement),
        vec![],
        "the replacement was never waited on: its end settles nothing"
    );
    assert_eq!(
        gates.session_ended(2, replaced),
        vec![Settled { key: KEY, epoch: 3 }],
        "the wait stayed stuck on a session that is gone"
    );
}

/// The other side: a Commit made after the replacement waits on the replacement, and the
/// replaced session's late end leaves that wait alone.
#[test]
fn a_replaced_members_late_end_leaves_its_replacements_wait() {
    let (replaced, replacement) = sessions();
    let mut gates = CommitGates::default();
    let _ = gates.open(KEY, 4, None, HashMap::from([(2, Some(replacement))]));
    assert_eq!(gates.session_ended(2, replaced), vec![]);
    assert_eq!(
        gates.applied(KEY, 4, 2),
        Some(Settled { key: KEY, epoch: 4 })
    );
}

/// An owner's waits end with the session that made the Commit, not with another of its.
#[test]
fn an_owners_waits_end_with_the_session_that_made_the_commit() {
    let (replaced, replacement) = sessions();
    let mut gates = CommitGates::default();
    let _ = gates.open(KEY, 4, Some(replacement), set(&[2]));
    assert_eq!(gates.session_ended(KEY.cid, replaced), vec![]);
    assert_eq!(
        gates.applied(KEY, 4, 2),
        Some(Settled { key: KEY, epoch: 4 }),
        "the replaced owner's end dropped its replacement's wait"
    );
    let _ = gates.open(KEY, 5, Some(replaced), set(&[2]));
    assert_eq!(gates.session_ended(KEY.cid, replaced), vec![]);
    assert_eq!(gates.applied(KEY, 5, 2), None, "its own end ends it");
}
