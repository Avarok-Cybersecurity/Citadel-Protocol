//! A grant is bound to how its account signs in: any change to that refuses every grant issued
//! before it, and nothing else does.

use super::record::PqAuthRecord;
use super::tests::register;
use super::tests_record::key;
use super::tests_resume::{issued, presented, refusal, DAY, HOUR_S, NOW};
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::SignInPolicy;

/// Control: leave a field out of `PqAuthRecord::resume_binding`.
#[tokio::test]
async fn a_change_to_the_accounts_sign_in_revokes_every_grant_before_it() {
    let mut record = register("pw").await;
    let enrolled = record.add(key(1), NOW);
    let credential = issued(&record, HOUR_S);
    let other = register("another password").await;
    let key_of_other = other.factors()[0].ek.clone();
    let revoked = Some(ErrorCode::ResumeCredentialRevoked);
    let after = |change: &dyn Fn(&mut PqAuthRecord)| {
        let mut changed = record.clone();
        change(&mut changed);
        refusal(DAY, &changed, presented(&credential), NOW + 1)
    };

    let new_password =
        |r: &mut PqAuthRecord| r.set_password(key_of_other.clone(), r.salt_user, r.ksf, 9);
    assert_eq!(after(&new_password), revoked, "a new password");
    let new_salt = |r: &mut PqAuthRecord| r.salt_user[0] ^= 1;
    assert_eq!(after(&new_salt), revoked, "a new password salt");
    let new_policy = |r: &mut PqAuthRecord| r.policy = SignInPolicy::KeyOnly;
    assert_eq!(after(&new_policy), revoked, "a new policy");
    let new_phrase = |r: &mut PqAuthRecord| r.replace_recovery_phrase(key_of_other.clone(), 9);
    assert_eq!(after(&new_phrase), revoked, "a new factor");

    let added = |r: &mut PqAuthRecord| {
        let _ = r.add(key(2), 9);
    };
    let removed = |r: &mut PqAuthRecord| r.remove(enrolled).unwrap();
    let replaced = |r: &mut PqAuthRecord| {
        r.remove(enrolled).unwrap();
        let _ = r.add(key(2), 9);
    };
    assert_eq!(
        [after(&added), after(&removed), after(&replaced)],
        [revoked; 3],
        "a security key added, removed, or replaced by another"
    );

    assert_eq!(after(&|_| ()), None, "the unchanged account resumes");
    let renamed = |r: &mut PqAuthRecord| r.rename(1, "Renamed".into()).unwrap();
    assert_eq!(after(&renamed), None, "a label is not the sign-in");
    let used = |r: &mut PqAuthRecord| r.record_use(&[1], 9).unwrap();
    assert_eq!(after(&used), None, "nor is when a factor was last used");
}
