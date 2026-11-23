//! The client's half: the device key it draws, and the credential it keeps.

use super::{PresentedResume, ResumeGrant, ResumeRequest, GRANT_VERSION};
use crate::auth::pq::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use rand::RngCore;
use zeroize::Zeroizing;

/// The seed of a device's resume key. Drawn for one credential and kept with it.
#[derive(Clone)]
pub struct DeviceKey(Box<Zeroizing<[u8; SEED_LEN]>>);

impl DeviceKey {
    /// A fresh key from the platform CSPRNG.
    pub fn generate() -> Self {
        let mut seed = Box::new(Zeroizing::new([0u8; SEED_LEN]));
        rand::thread_rng().fill_bytes(seed.as_mut().as_mut());
        Self(seed)
    }

    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self(Box::new(Zeroizing::new(seed)))
    }

    pub(crate) fn keypair(&self) -> Result<FactorKeypair, AccountError> {
        FactorKeypair::derive(&FactorSeed::new(**self.0))
    }

    /// What a full sign-in sends to ask for a credential bound to this key.
    pub fn request(&self, lifetime_s: u64) -> Result<ResumeRequest, AccountError> {
        Ok(ResumeRequest {
            device_ek: self.keypair()?.encapsulation_key().clone(),
            lifetime_s,
        })
    }
}

/// What a device keeps to sign in again: the server's grant and the key it names. Never printed
/// beyond its expiry.
#[derive(Clone)]
pub struct ResumeCredential {
    grant: Box<ResumeGrant>,
    device: DeviceKey,
}

impl std::fmt::Debug for ResumeCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResumeCredential(until {})", self.valid_until_utc())
    }
}

impl ResumeCredential {
    /// Keeps `grant` if it is the one this device asked for: its account, its key, a lifetime no
    /// longer than `request` asked. The MAC is the server's to check, not the client's.
    pub fn accept(
        grant: ResumeGrant,
        device: DeviceKey,
        cid: u64,
        request: &ResumeRequest,
    ) -> Result<Self, AccountError> {
        let body = &grant.body;
        let lifetime_ms = body.valid_until_utc.checked_sub(body.issued_at_utc);
        let asked_ms = request.lifetime_s.saturating_mul(1_000);
        let ours = body.version == GRANT_VERSION
            && body.cid == cid
            && body.device_fpr == request.device_ek.fingerprint()
            && device.keypair()?.encapsulation_key() == &request.device_ek
            && lifetime_ms.is_some_and(|ms| ms > 0 && ms <= asked_ms);
        match ours {
            true => Ok(Self {
                grant: Box::new(grant),
                device,
            }),
            false => Err(error!(ErrorCode::PqSignInMalformed, "a resume grant")),
        }
    }

    /// The same credential under a grant the server re-issued after this session changed the
    /// account's sign-in: nothing but the state it is bound to (and so its MAC) may differ.
    pub fn reissued(&self, grant: ResumeGrant) -> Result<Self, AccountError> {
        let (old, new) = (&self.grant.body, &grant.body);
        let same = old.version == new.version
            && old.cid == new.cid
            && old.issued_at_utc == new.issued_at_utc
            && old.valid_until_utc == new.valid_until_utc
            && old.device_fpr == new.device_fpr;
        match same {
            true => Ok(Self {
                grant: Box::new(grant),
                device: self.device.clone(),
            }),
            false => Err(error!(ErrorCode::PqSignInMalformed, "a re-issued grant")),
        }
    }

    /// Unix milliseconds, UTC, by the server's clock.
    pub fn valid_until_utc(&self) -> u64 {
        self.grant.body.valid_until_utc
    }

    /// Unix milliseconds, UTC, by the server's clock: what `now` was there when it was issued.
    pub fn issued_at_utc(&self) -> u64 {
        self.grant.body.issued_at_utc
    }

    pub fn cid(&self) -> u64 {
        self.grant.body.cid
    }

    /// Whether the credential is past its expiry at `now_utc` (Unix milliseconds).
    pub fn expired_at(&self, now_utc: u64) -> bool {
        now_utc >= self.valid_until_utc()
    }

    /// What a resume sends, refused here when the credential has already expired.
    pub fn present(&self, now_utc: u64) -> Result<(PresentedResume, FactorKeypair), AccountError> {
        if self.expired_at(now_utc) {
            return Err(error!(ErrorCode::ResumeCredentialExpired));
        }
        let keypair = self.device.keypair()?;
        let presented = PresentedResume {
            grant: *self.grant,
            device_ek: keypair.encapsulation_key().clone(),
        };
        Ok((presented, keypair))
    }
}
