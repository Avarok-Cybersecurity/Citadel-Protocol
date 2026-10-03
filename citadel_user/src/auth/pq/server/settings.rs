use crate::auth::pq::oprf::OprfSeed;
use crate::auth::pq::record::KsfParams;
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// What a server needs to offer post-quantum sign-in. A server without it keeps the legacy path
/// only: it answers a post-quantum registration with `Unsupported` and offers no upgrades.
#[derive(Clone, Debug)]
pub struct PqAuthServerSettings {
    oprf_seed: OprfSeed,
    ksf: KsfParams,
}

impl PqAuthServerSettings {
    /// `ksf` is what new password factors are stretched with; it must meet
    /// [`KsfParams::FLOOR`], because clients refuse anything weaker.
    pub fn new(oprf_seed: OprfSeed, ksf: KsfParams) -> Result<Self, AccountError> {
        if !ksf.meets_floor() {
            return Err(error!(
                ErrorCode::PqSignInUnavailable,
                "the Argon2id parameters are below the floor clients accept"
            ));
        }
        Ok(Self { oprf_seed, ksf })
    }

    pub fn oprf_seed(&self) -> &OprfSeed {
        &self.oprf_seed
    }

    pub fn ksf(&self) -> KsfParams {
        self.ksf
    }
}
