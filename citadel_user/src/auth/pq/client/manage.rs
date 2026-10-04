//! The client's side of sign-in management.

use super::login::{ClientLogin, ClientProof, SecurityKeyAnswer, SecurityKeyRequest};
use crate::auth::pq::kem::{EncapsulationKey, FactorKeypair};
use crate::auth::pq::management_transcript;
use crate::auth::pq::messages::{
    transcript_bytes, ChallengeBody, EnrolChallenge, EnrolProof, LoginFinish, LoginProof,
    ManagementBegin, ManagementChallenge, ManagementCommit,
};
use crate::auth::pq::proof::{factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::{recovery_seed, security_key_seed, PrfOutput};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SignInManagementOp;
use citadel_types::crypto::SecBuffer;

/// A change between `Begin` and `Commit`.
pub struct ClientManagement {
    login: ClientLogin,
    begin: ManagementBegin,
    codes: Vec<RecoveryCode>,
}

impl ClientManagement {
    /// `password` is the step-up's password, when the account's policy asks for one. New recovery
    /// codes are generated here, for `RegenerateRecoveryCodes`.
    pub fn begin(
        username: &str,
        op: SignInManagementOp,
        password: Option<&SecBuffer>,
    ) -> Result<(ManagementBegin, Self), AccountError> {
        let (step_up, login) = ClientLogin::start(username, password, None)?;
        let codes = match op {
            SignInManagementOp::RegenerateRecoveryCodes => RecoveryCode::generate_set(),
            _ => Vec::new(),
        };
        let recovery_eks = codes
            .iter()
            .map(|code| {
                FactorKeypair::derive(&recovery_seed(code)).map(|kp| kp.encapsulation_key().clone())
            })
            .collect::<Result<_, _>>()?;
        let begin = ManagementBegin {
            op,
            step_up,
            recovery_eks,
        };
        Ok((
            begin.clone(),
            Self {
                login,
                begin,
                codes,
            },
        ))
    }

    /// The touch the step-up needs, if the account's policy includes a key.
    pub fn step_up_key_request(challenge: &ManagementChallenge) -> Option<SecurityKeyRequest> {
        ClientLogin::security_key_request(&challenge.step_up)
    }

    /// `AddSecurityKey`: what to ask the new key for, now that the challenge has given the
    /// account's PRF salt.
    pub fn new_key_request(&self, challenge: &ManagementChallenge) -> Option<SecurityKeyRequest> {
        let SignInManagementOp::AddSecurityKey { credential_id, .. } = &self.begin.op else {
            return None;
        };
        let ChallengeBody::Factors(factors) = &challenge.step_up.body else {
            return None;
        };
        Some(SecurityKeyRequest {
            credential_ids: vec![credential_id.clone()],
            prf_eval_salt: factors.prf_eval_salt,
        })
    }

    pub async fn commit(
        self,
        cid: u64,
        challenge: &ManagementChallenge,
        step_up_key: Option<SecurityKeyAnswer>,
        new_key_prf: Option<PrfOutput>,
    ) -> Result<(ManagementCommit, ClientCommitted), AccountError> {
        let new_key = match (&self.begin.op, new_key_prf) {
            (SignInManagementOp::AddSecurityKey { credential_id, .. }, Some(prf)) => Some(
                FactorKeypair::derive(&security_key_seed(&prf, credential_id))?,
            ),
            (SignInManagementOp::AddSecurityKey { .. }, None) => {
                return Err(error!(
                    ErrorCode::PqSignInFactorMissing,
                    "the new key's PRF output"
                ))
            }
            _ => None,
        };
        let new_key_ek: Option<EncapsulationKey> =
            new_key.as_ref().map(|kp| kp.encapsulation_key().clone());
        let transcript = management_transcript(cid, &self.begin, challenge, new_key_ek.as_ref());
        let challenged = match &challenge.step_up.body {
            ChallengeBody::Factors(factors) => !factors.challenges.is_empty(),
            ChallengeBody::Legacy { .. } => true,
        };
        let step_up = if challenged {
            match self
                .login
                .respond(&challenge.step_up, &transcript, step_up_key)
                .await?
            {
                ClientProof::Factors {
                    proof: LoginProof::Factors(finish),
                    ..
                } => finish,
                _ => return Err(error!(ErrorCode::PqSignInMalformed, "a legacy step-up")),
            }
        } else {
            // A recovery session: the server proves nothing again.
            LoginFinish { tags: Vec::new() }
        };
        let commit = ManagementCommit {
            step_up,
            new_key_ek,
        };
        let committed = ClientCommitted {
            transcript,
            new_key,
            codes: self.codes,
        };
        Ok((commit, committed))
    }
}

/// A change the client has committed to.
pub struct ClientCommitted {
    transcript: TranscriptHash,
    new_key: Option<FactorKeypair>,
    codes: Vec<RecoveryCode>,
}

impl ClientCommitted {
    /// The proof that this client holds the key it is adding.
    pub fn enrol_proof(
        &self,
        cid: u64,
        challenge: &EnrolChallenge,
    ) -> Result<EnrolProof, AccountError> {
        let key = self.new_key.as_ref().ok_or_else(|| {
            error!(
                ErrorCode::PqSignInMalformed,
                "an enrolment challenge for no key"
            )
        })?;
        let k = key.decapsulate(&challenge.ct)?;
        let transcript = TranscriptHash::new(
            TranscriptPurpose::StepUp,
            cid,
            &[self.transcript.as_bytes(), &transcript_bytes(challenge)],
        );
        Ok(EnrolProof {
            tag: factor_tag(&k, ENROL_LABEL, 0, &transcript),
        })
    }

    /// The new recovery codes (`RegenerateRecoveryCodes`), to show the user once.
    pub fn into_recovery_codes(self) -> Vec<RecoveryCode> {
        self.codes
    }
}
