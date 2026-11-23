//! Resume credentials: a full sign-in may leave the device able to sign in again, for a limited
//! time, without the account's factors being offered again.
//!
//! The device draws an ML-KEM-1024 keypair and asks for a lifetime. The server answers with a
//! [`ResumeGrant`]: a MAC, under a key only it can derive, over the account, the grant's times,
//! the account's sign-in state as it stood ([`crate::auth::pq::record::PqAuthRecord::resume_binding`])
//! and the fingerprint of the device's key. To resume, the device presents the grant and its key;
//! the server checks the MAC, the expiry and the binding from the grant and the account's record
//! alone, then challenges the device's key as it challenges any factor. The server stores nothing
//! for a grant and keeps no list of them.
//!
//! The client checks the expiry before it sends anything ([`ResumeCredential::expired_at`]). That
//! check saves a round trip and tells the application why; the server's is the one that counts.

mod client;
mod grant;
mod policy;

pub use client::{DeviceKey, ResumeCredential};
pub use grant::{ResumeGrant, ResumeGrantBody, GRANT_VERSION};
pub use policy::ResumePolicy;

use super::kem::EncapsulationKey;
use citadel_types::auth::FactorId;
use serde::{Deserialize, Serialize};

/// The factor id a resume challenge carries. An account's own factors count up from 1 and never
/// reach it.
pub const RESUME_FACTOR_ID: FactorId = FactorId::MAX;

/// C→S, with a full sign-in's proof: the device's key and the lifetime it asks for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ResumeRequest {
    pub device_ek: EncapsulationKey,
    /// Seconds. The server grants no more than its own maximum.
    pub lifetime_s: u64,
}

/// C→S, in place of the account's factors: the grant and the key it names.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PresentedResume {
    pub grant: ResumeGrant,
    pub device_ek: EncapsulationKey,
}

impl std::fmt::Debug for PresentedResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PresentedResume(..)")
    }
}
