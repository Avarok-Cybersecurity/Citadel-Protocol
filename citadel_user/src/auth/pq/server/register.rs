use super::PqAuthServerSettings;
use crate::auth::pq::messages::{RegFinish, RegReply, RegStart};
use crate::auth::pq::oprf;
use crate::auth::pq::random_32;
use crate::auth::pq::record::{KsfParams, PqAuthRecord, RecoverySecret};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// What the server remembers between [`RegReply`] and [`RegFinish`].
#[derive(Debug)]
pub struct PendingRegistration {
    username: String,
    salt_user: [u8; 32],
    prf_eval_salt: [u8; 32],
    ksf: KsfParams,
}

/// The server's answer to [`RegStart`] (and to the blinded element of a legacy login that is
/// offered an upgrade): the OPRF evaluation and fresh salts.
pub fn registration_reply(
    settings: &PqAuthServerSettings,
    start: &RegStart,
) -> Result<(RegReply, PendingRegistration), AccountError> {
    let oprf_evaluated =
        oprf::server_evaluate(settings.oprf_seed(), &start.username, &start.oprf_blinded)?;
    let pending = PendingRegistration {
        username: start.username.clone(),
        salt_user: random_32(),
        prf_eval_salt: random_32(),
        ksf: settings.ksf(),
    };
    let reply = RegReply {
        oprf_evaluated,
        salt_user: pending.salt_user,
        prf_eval_salt: pending.prf_eval_salt,
        ksf: pending.ksf,
    };
    Ok((reply, pending))
}

impl PendingRegistration {
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The fresh salt and the parameters a new password factor is stretched with.
    pub fn password_parts(&self) -> ([u8; 32], KsfParams) {
        (self.salt_user, self.ksf)
    }

    /// The new account record. No password hashing happens here: the client sent keys.
    pub fn finish(self, finish: RegFinish, now_ms: u64) -> Result<PqAuthRecord, AccountError> {
        let recovery = match finish.recovery_phrase_ek {
            Some(phrase) => RecoverySecret::Phrase(phrase),
            None => RecoverySecret::Codes(Vec::new()),
        };
        let mut seen = vec![finish.password_ek.fingerprint()];
        for ek in recovery.keys() {
            let fp = ek.fingerprint();
            if seen.contains(&fp) {
                return Err(error!(
                    ErrorCode::PqSignInMalformed,
                    "a repeated factor key"
                ));
            }
            seen.push(fp);
        }
        Ok(PqAuthRecord::new(
            self.salt_user,
            self.prf_eval_salt,
            self.ksf,
            finish.password_ek,
            recovery,
            now_ms,
        ))
    }
}
