//! The server's side of a resume credential: issuing a grant after a full sign-in, and checking
//! one that is presented. Everything it needs is in the grant, the account's record and this
//! server's settings; the time is the caller's to pass.

use super::login::{AccountAuth, Expected, VerifiedLogin};
use super::PqAuthServerSettings;
use crate::auth::pq::kem::encapsulate;
use crate::auth::pq::messages::{
    ChallengeBody, FactorChallenge, FactorChallenges, LoginChallenge, LoginStart,
};
use crate::auth::pq::random_32;
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::resume::{
    PresentedResume, ResumeGrant, ResumeGrantBody, ResumeRequest, GRANT_VERSION, RESUME_FACTOR_ID,
};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorKind, SessionScope};

/// Says nothing about which check failed, as any failed sign-in.
fn failed() -> AccountError {
    error!(ErrorCode::PqSignInFailed)
}

/// The grant a verified sign-in is given, if it earned one: its own factors proved it (a resumed
/// sign-in is never given another, or a credential would never expire) and it has the whole
/// account (a recovery session has not).
pub fn grant_after(
    settings: &PqAuthServerSettings,
    cid: u64,
    record: &PqAuthRecord,
    verified: &VerifiedLogin,
    request: &ResumeRequest,
    now_ms: u64,
) -> Option<ResumeGrant> {
    let earned = verified.by_factors && verified.scope == SessionScope::Full;
    earned
        .then(|| issue_grant(settings, cid, record, request, now_ms))
        .flatten()
}

/// The grant itself: bound to the account's sign-in as it stands and to the device's key, living
/// for what was asked or this server's maximum, whichever is shorter. `None` when this server
/// issues none or no time was asked for.
pub(crate) fn issue_grant(
    settings: &PqAuthServerSettings,
    cid: u64,
    record: &PqAuthRecord,
    request: &ResumeRequest,
    now_ms: u64,
) -> Option<ResumeGrant> {
    let lifetime_ms = settings.resume()?.granted_ms(request.lifetime_s);
    if lifetime_ms == 0 {
        return None;
    }
    let body = ResumeGrantBody {
        version: GRANT_VERSION,
        cid,
        issued_at_utc: now_ms,
        valid_until_utc: now_ms.saturating_add(lifetime_ms),
        state_hash: record.resume_binding(),
        device_fpr: request.device_ek.fingerprint(),
    };
    Some(ResumeGrant::seal(settings.oprf_seed(), body))
}

/// The record a presented grant must match, once the grant is known to be this server's, this
/// account's, this key's and unexpired.
fn check<'a>(
    settings: &PqAuthServerSettings,
    cid: u64,
    account: AccountAuth<'a>,
    presented: &PresentedResume,
    now_ms: u64,
) -> Result<&'a PqAuthRecord, AccountError> {
    let policy = settings.resume().ok_or_else(failed)?;
    let AccountAuth::PostQuantum(record) = account else {
        return Err(failed());
    };
    let body = &presented.grant.body;
    let genuine = presented.grant.authentic(settings.oprf_seed())
        && body.version == GRANT_VERSION
        && body.cid == cid
        && body.device_fpr == presented.device_ek.fingerprint();
    if !genuine {
        return Err(failed());
    }
    if now_ms >= policy.honoured_until(body.issued_at_utc, body.valid_until_utc) {
        return Err(error!(ErrorCode::ResumeCredentialExpired));
    }
    Ok(record)
}

/// The challenge for a sign-in that presents a resume credential: one fresh encapsulation to the
/// device's key, which the client answers as it answers any factor.
///
/// Refused as [`ErrorCode::ResumeCredentialExpired`] past the grant's expiry, as
/// [`ErrorCode::ResumeCredentialRevoked`] when the account's sign-in has changed since it was
/// issued, and as an ordinary failed sign-in for anything else. Only a genuine grant can be told
/// it is expired or revoked.
pub fn build_resume_challenge(
    settings: &PqAuthServerSettings,
    cid: u64,
    account: AccountAuth<'_>,
    start: &LoginStart,
    now_ms: u64,
) -> Result<(LoginChallenge, Expected), AccountError> {
    let presented = start.resume_credential.as_ref().ok_or_else(failed)?;
    if start.oprf_blinded.is_some() || start.recovery.is_some() {
        return Err(error!(ErrorCode::PqSignInMalformed, "a resume start"));
    }
    let record = check(settings, cid, account, presented, now_ms)?;
    if presented.grant.body.state_hash != record.resume_binding() {
        return Err(error!(ErrorCode::ResumeCredentialRevoked));
    }
    let (ct, secret) = encapsulate(&presented.device_ek)?;
    let challenge = LoginChallenge {
        server_nonce: random_32(),
        body: ChallengeBody::Factors(FactorChallenges {
            oprf_evaluated: None,
            salt_user: record.salt_user,
            prf_eval_salt: record.prf_eval_salt,
            ksf: record.ksf,
            challenges: vec![FactorChallenge {
                factor_id: RESUME_FACTOR_ID,
                kind: FactorKind::ResumeKey,
                credential_id: None,
                ct,
            }],
        }),
    };
    Ok((challenge, Expected::resume(secret)))
}

/// After a session changed its own account's sign-in: the grant it held, bound to the account as
/// it now stands. `held` must be genuine, unexpired and bound to the account as it stood `before`
/// the change. Nothing else in it changes, so the new grant expires exactly when the old one did.
pub fn reissue_grant(
    settings: &PqAuthServerSettings,
    cid: u64,
    before: &PqAuthRecord,
    after: &PqAuthRecord,
    held: &PresentedResume,
    now_ms: u64,
) -> Option<ResumeGrant> {
    let account = AccountAuth::PostQuantum(before);
    let before = check(settings, cid, account, held, now_ms).ok()?;
    if held.grant.body.state_hash != before.resume_binding() {
        return None;
    }
    let body = ResumeGrantBody {
        state_hash: after.resume_binding(),
        ..held.grant.body
    };
    Some(ResumeGrant::seal(settings.oprf_seed(), body))
}
