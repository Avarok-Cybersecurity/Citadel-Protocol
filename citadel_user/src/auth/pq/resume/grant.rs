//! The grant: what the server authenticates, and the key it authenticates it under.

use crate::auth::pq::oprf::OprfSeed;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

/// The layout of [`ResumeGrantBody`] the MAC covers.
pub const GRANT_VERSION: u8 = 1;

/// HKDF label of the grant key. Nothing else derives from the seed under it.
const GRANT_KEY_LABEL: &[u8] = b"citadel/resume-grant/v1";
/// HKDF `info` of the grant key: it belongs to no username.
const GRANT_KEY_SCOPE: &str = "";
const GRANT_MAC_LABEL: &[u8] = b"citadel-resume-grant-mac-v1";

/// What a grant says. Times are Unix milliseconds, UTC, by the server's clock.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResumeGrantBody {
    pub version: u8,
    pub cid: u64,
    pub issued_at_utc: u64,
    pub valid_until_utc: u64,
    /// The account's sign-in state when the grant was issued.
    pub state_hash: [u8; 32],
    /// The fingerprint of the device's encapsulation key.
    pub device_fpr: [u8; 32],
}

/// A grant as it travels: its body and the server's MAC over it.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub struct ResumeGrant {
    pub body: ResumeGrantBody,
    pub mac: [u8; 32],
}

impl std::fmt::Debug for ResumeGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResumeGrant(until {})", self.body.valid_until_utc)
    }
}

/// `version ‖ cid ‖ issued_at ‖ valid_until_utc ‖ state_hash ‖ device_fpr`, fixed width.
fn mac_of(seed: &OprfSeed, body: &ResumeGrantBody) -> Hmac<Sha3_256> {
    let key = seed.derive::<32>(GRANT_KEY_LABEL, GRANT_KEY_SCOPE);
    let mut mac = <Hmac<Sha3_256> as Mac>::new_from_slice(key.as_ref())
        .expect("HMAC accepts a key of any length");
    mac.update(GRANT_MAC_LABEL);
    mac.update(&[body.version]);
    mac.update(&body.cid.to_be_bytes());
    mac.update(&body.issued_at_utc.to_be_bytes());
    mac.update(&body.valid_until_utc.to_be_bytes());
    mac.update(&body.state_hash);
    mac.update(&body.device_fpr);
    mac
}

impl ResumeGrant {
    /// The server's: `body` under this tenant's grant key.
    pub(crate) fn seal(seed: &OprfSeed, body: ResumeGrantBody) -> Self {
        let mac = mac_of(seed, &body).finalize().into_bytes().into();
        Self { body, mac }
    }

    /// Whether this tenant issued exactly this body. Constant time.
    pub(crate) fn authentic(&self, seed: &OprfSeed) -> bool {
        mac_of(seed, &self.body).verify_slice(&self.mac).is_ok()
    }
}
