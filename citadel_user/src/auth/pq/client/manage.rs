//! The client's side of sign-in management.

use super::key_request::{RelyingParty, SecurityKeyCeremony, SecurityKeyRequest};
use super::login::{ClientLogin, ClientProof, SecurityKeyAnswer};
use crate::auth::pq::kem::FactorKeypair;
use crate::auth::pq::messages::{
    key_binding, transcript_bytes, ChallengeBody, CommitCeremony, EnrolChallenge, EnrolProof,
    LoginFinish, LoginProof, ManagementBegin, ManagementChallenge, ManagementCommit, ManagementOp,
    NewSecurityKey, SignInLayout,
};
use crate::auth::pq::proof::{factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::{recovery_seed, security_key_seed};
use crate::auth::pq::{management_transcript, random_32};
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
            op: op.into(),
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
    pub fn step_up_key_request(
        challenge: &ManagementChallenge,
    ) -> Result<Option<SecurityKeyRequest>, AccountError> {
        ClientLogin::security_key_request(
            &challenge.step_up,
            RelyingParty::of_management(challenge),
        )
    }

    /// `AddSecurityKey`: the credential to create, now that the challenge has given the relying
    /// party, the account's PRF salt and the keys it already has.
    pub fn new_key_request(
        &self,
        challenge: &ManagementChallenge,
    ) -> Result<Option<SecurityKeyRequest>, AccountError> {
        let ManagementOp::AddSecurityKey { .. } = &self.begin.op else {
            return Ok(None);
        };
        let ChallengeBody::Factors(factors) = &challenge.step_up.body else {
            return Ok(None);
        };
        let rp_id = RelyingParty::of_management(challenge).for_register()?;
        let exclude_credential_ids = challenge
            .ceremony
            .as_ref()
            .map(|ceremony| ceremony.exclude_credentials.clone())
            .unwrap_or_default();
        Ok(Some(SecurityKeyRequest {
            rp_id: Some(rp_id),
            prf_eval_salt: factors.prf_eval_salt,
            ceremony: SecurityKeyCeremony::Register {
                // A random handle: the credential is not discoverable, so nothing looks it up.
                user_id: random_32().to_vec(),
                user_name: self.begin.step_up.username.clone(),
                exclude_credential_ids,
            },
        }))
    }

    pub async fn commit(
        self,
        cid: u64,
        challenge: &ManagementChallenge,
        step_up_key: Option<SecurityKeyAnswer>,
        new_key: Option<SecurityKeyAnswer>,
    ) -> Result<(ManagementCommit, ClientCommitted), AccountError> {
        let layout = challenge.layout();
        if self
            .begin
            .op
            .layout()
            .is_some_and(|needed| needed != layout)
        {
            return Err(error!(
                ErrorCode::PqSignInMalformed,
                "a challenge in another layout than the change"
            ));
        }
        let new_key = match (&self.begin.op, new_key) {
            (ManagementOp::AddSecurityKey { .. }, Some(answer)) => {
                let seed = security_key_seed(&answer.prf, &answer.credential_id);
                Some((answer.credential_id, FactorKeypair::derive(&seed)?))
            }
            (ManagementOp::AddSecurityKey { .. }, None) => {
                return Err(error!(ErrorCode::PqSignInFactorMissing, "the new key"))
            }
            _ => None,
        };
        let ceremony = match layout {
            SignInLayout::V0_12_2 => None,
            SignInLayout::SecurityKeyCeremony => Some(CommitCeremony {
                new_key: new_key
                    .as_ref()
                    .map(|(credential_id, keypair)| NewSecurityKey {
                        credential_id: credential_id.clone(),
                        ek: keypair.encapsulation_key().clone(),
                    }),
            }),
        };
        // A key is only added in the ceremony layout, which carries it in `ceremony`.
        let new_key_ek = None;
        let transcript = management_transcript(
            cid,
            &self.begin,
            challenge,
            &key_binding(&new_key_ek, ceremony.as_ref()),
        );
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
            ceremony,
        };
        let committed = ClientCommitted {
            transcript,
            new_key: new_key.map(|(_, keypair)| keypair),
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
