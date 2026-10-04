//! What the server stores for an account that signs in with post-quantum factors: encapsulation
//! keys, never anything a guess could be checked against without the OPRF seed.

use super::kem::EncapsulationKey;
use super::policy;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::{FactorId, FactorKind, SignInCredential, SignInPolicy};
use serde::{Deserialize, Serialize};

/// Argon2id parameters for the password factor. The server chooses them and stores them with the
/// account, so they can be raised later; the client refuses any below [`KsfParams::FLOOR`].
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct KsfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl KsfParams {
    /// OWASP's minimum for Argon2id (19 MiB, 2 passes, 1 lane). A server cannot weaken a client's
    /// stretching below this.
    pub const FLOOR: Self = Self {
        mem_kib: 19 * 1024,
        iterations: 2,
        lanes: 1,
    };

    pub fn meets_floor(&self) -> bool {
        self.mem_kib >= Self::FLOOR.mem_kib
            && self.iterations >= Self::FLOOR.iterations
            && self.lanes >= Self::FLOOR.lanes
    }
}

/// One enrolled factor.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Factor {
    pub id: FactorId,
    pub kind: FactorKind,
    pub ek: EncapsulationKey,
    pub credential_id: Option<Vec<u8>>,
    pub label: String,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    /// Set once a recovery code has signed in. A consumed factor is never challenged again.
    pub consumed: bool,
}

impl Factor {
    pub fn usable(&self) -> bool {
        !self.consumed
    }
}

/// A new factor before the record gives it an id.
pub struct NewFactor {
    pub kind: FactorKind,
    pub ek: EncapsulationKey,
    pub credential_id: Option<Vec<u8>>,
    pub label: String,
}

/// An account's sign-in record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PqAuthRecord {
    pub policy: SignInPolicy,
    pub salt_user: [u8; 32],
    pub prf_eval_salt: [u8; 32],
    pub ksf: KsfParams,
    factors: Vec<Factor>,
    next_factor_id: FactorId,
}

impl PqAuthRecord {
    /// A record with the `Password` policy, its password factor and recovery codes.
    pub fn new(
        salt_user: [u8; 32],
        prf_eval_salt: [u8; 32],
        ksf: KsfParams,
        password_ek: EncapsulationKey,
        recovery_eks: Vec<EncapsulationKey>,
        now_ms: u64,
    ) -> Self {
        let mut record = Self {
            policy: SignInPolicy::Password,
            salt_user,
            prf_eval_salt,
            ksf,
            factors: Vec::new(),
            next_factor_id: 1,
        };
        let password = NewFactor {
            kind: FactorKind::Password,
            ek: password_ek,
            credential_id: None,
            label: String::from("Password"),
        };
        let _ = record.add(password, now_ms);
        record.replace_recovery_codes(recovery_eks, now_ms);
        record
    }

    pub fn factors(&self) -> &[Factor] {
        &self.factors
    }

    pub fn factor(&self, id: FactorId) -> Option<&Factor> {
        self.factors.iter().find(|f| f.id == id)
    }

    /// The usable factors of one kind, in enrolment order.
    pub fn usable(&self, kind: FactorKind) -> impl Iterator<Item = &Factor> {
        self.factors
            .iter()
            .filter(move |f| f.kind == kind && f.usable())
    }

    pub fn add(&mut self, factor: NewFactor, now_ms: u64) -> FactorId {
        let id = self.next_factor_id;
        self.next_factor_id += 1;
        self.factors.push(Factor {
            id,
            kind: factor.kind,
            ek: factor.ek,
            credential_id: factor.credential_id,
            label: factor.label,
            created_ms: now_ms,
            last_used_ms: None,
            consumed: false,
        });
        id
    }

    pub fn rename(&mut self, id: FactorId, label: String) -> Result<(), AccountError> {
        let factor = self.factors.iter_mut().find(|f| f.id == id);
        let factor = factor.ok_or_else(|| policy::refused("no such credential"))?;
        factor.label = label;
        Ok(())
    }

    /// Refused when the remaining factors could no longer satisfy the policy, which includes
    /// removing the last one. Recovery codes go only by regeneration.
    pub fn remove(&mut self, id: FactorId) -> Result<(), AccountError> {
        let index = self.factors.iter().position(|f| f.id == id);
        let index = index.ok_or_else(|| policy::refused("no such credential"))?;
        if self.factors[index].kind == FactorKind::RecoveryCode {
            return Err(policy::refused("recovery codes are replaced, not removed"));
        }
        let mut after = self.factors.clone();
        let _ = after.remove(index);
        if !policy::satisfiable(self.policy, &after) {
            return Err(policy::refused(
                "the sign-in policy would become unsatisfiable",
            ));
        }
        self.factors = after;
        Ok(())
    }

    pub fn set_policy(&mut self, policy: SignInPolicy) -> Result<(), AccountError> {
        if !policy::satisfiable(policy, &self.factors) {
            return Err(policy::refused("the account's factors cannot satisfy it"));
        }
        self.policy = policy;
        Ok(())
    }

    /// Replaces every recovery code, used or not.
    pub fn replace_recovery_codes(&mut self, eks: Vec<EncapsulationKey>, now_ms: u64) {
        self.factors.retain(|f| f.kind != FactorKind::RecoveryCode);
        for (index, ek) in eks.into_iter().enumerate() {
            let code = NewFactor {
                kind: FactorKind::RecoveryCode,
                ek,
                credential_id: None,
                label: format!("Recovery code {}", index + 1),
            };
            let _ = self.add(code, now_ms);
        }
    }

    /// Records a sign-in: `used` get `last_used_ms`, and a recovery code among them is consumed.
    pub fn record_use(&mut self, used: &[FactorId], now_ms: u64) -> Result<(), AccountError> {
        for id in used {
            let factor = self.factors.iter_mut().find(|f| f.id == *id && f.usable());
            let factor = factor.ok_or_else(|| error!(ErrorCode::PqSignInFailed))?;
            factor.last_used_ms = Some(now_ms);
            factor.consumed |= factor.kind == FactorKind::RecoveryCode;
        }
        Ok(())
    }

    pub fn credentials(&self) -> Vec<SignInCredential> {
        self.factors
            .iter()
            .map(|f| SignInCredential {
                id: f.id,
                kind: f.kind,
                label: f.label.clone(),
                credential_id: f.credential_id.clone(),
                created_ms: f.created_ms,
                last_used_ms: f.last_used_ms,
                consumed: f.consumed,
            })
            .collect()
    }
}
