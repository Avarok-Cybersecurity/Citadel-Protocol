use super::PqAuthServerSettings;
use crate::auth::pq::messages::{RegFinish, RegReply, RegStart};
use crate::auth::pq::oprf;
use crate::auth::pq::random_32;
use crate::auth::pq::record::{KsfParams, PqAuthRecord};
use crate::auth::pq::recovery::RECOVERY_CODE_COUNT;
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

    /// The new account record. No password hashing happens here: the client sent keys.
    pub fn finish(self, finish: RegFinish, now_ms: u64) -> Result<PqAuthRecord, AccountError> {
        let codes = finish.recovery_eks.len();
        if codes != 0 && codes != RECOVERY_CODE_COUNT {
            return Err(error!(
                ErrorCode::PqSignInMalformed,
                "the recovery code count"
            ));
        }
        let mut seen = vec![finish.password_ek.fingerprint()];
        for ek in &finish.recovery_eks {
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
            finish.recovery_eks,
            now_ms,
        ))
    }
}
