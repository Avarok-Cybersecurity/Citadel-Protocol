//! An account's recovery credentials, and its password factor, which recovery may replace.

use super::{Factor, KsfParams, NewFactor, PqAuthRecord};
use crate::auth::pq::kem::EncapsulationKey;
use citadel_types::auth::FactorKind;

/// What an account recovers with: the legacy codes, or the phrase that replaces them.
pub enum RecoverySecret {
    Codes(Vec<EncapsulationKey>),
    Phrase(EncapsulationKey),
}

impl RecoverySecret {
    /// The keys it brings, in order.
    pub fn keys(&self) -> &[EncapsulationKey] {
        match self {
            Self::Codes(eks) => eks,
            Self::Phrase(ek) => std::slice::from_ref(ek),
        }
    }
}

impl PqAuthRecord {
    /// Replaces the account's recovery credentials, phrase and codes alike, used or not: an
    /// account has one recovery secret, and the one it had stops working here.
    pub fn replace_recovery(&mut self, secret: RecoverySecret, now_ms: u64) {
        self.factors.retain(|f| !is_recovery(f.kind));
        let labelled = match secret {
            RecoverySecret::Codes(eks) => eks
                .into_iter()
                .enumerate()
                .map(|(i, ek)| {
                    (
                        FactorKind::RecoveryCode,
                        ek,
                        format!("Recovery code {}", i + 1),
                    )
                })
                .collect(),
            RecoverySecret::Phrase(ek) => {
                vec![(
                    FactorKind::RecoveryPhrase,
                    ek,
                    String::from("Recovery phrase"),
                )]
            }
        };
        for (kind, ek, label) in labelled {
            let factor = NewFactor {
                kind,
                ek,
                credential_id: None,
                label,
            };
            let _ = self.add(factor, now_ms);
        }
    }

    /// Replaces the password factor, and the salt and parameters its seed is stretched with. The
    /// factor keeps its id, so a changed password is not told apart from an unchanged one by a
    /// challenge; an account without one (key-only) is given one.
    pub fn set_password(
        &mut self,
        ek: EncapsulationKey,
        salt_user: [u8; 32],
        ksf: KsfParams,
        now_ms: u64,
    ) {
        self.salt_user = salt_user;
        self.ksf = ksf;
        let existing = self
            .factors
            .iter_mut()
            .find(|f| f.kind == FactorKind::Password);
        match existing {
            Some(factor) => {
                factor.ek = ek;
                factor.created_ms = now_ms;
                factor.last_used_ms = None;
            }
            None => {
                let password = NewFactor {
                    kind: FactorKind::Password,
                    ek,
                    credential_id: None,
                    label: String::from("Password"),
                };
                let _ = self.add(password, now_ms);
            }
        }
    }

    /// The usable recovery factor, phrase or code, whose key has this fingerprint.
    pub fn recovery_factor(&self, fingerprint: &[u8; 32]) -> Option<&Factor> {
        self.factors
            .iter()
            .find(|f| is_recovery(f.kind) && f.usable() && f.ek.fingerprint() == *fingerprint)
    }
}

/// The kinds that recover an account rather than sign it in.
pub fn is_recovery(kind: FactorKind) -> bool {
    matches!(kind, FactorKind::RecoveryCode | FactorKind::RecoveryPhrase)
}
