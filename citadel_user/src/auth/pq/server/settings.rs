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
    security_key_rp_id: Option<String>,
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
        Ok(Self {
            oprf_seed,
            ksf,
            security_key_rp_id: None,
        })
    }

    /// Enables security keys, scoped to the WebAuthn relying party `rp_id`: the domain the
    /// server's browser clients are served from (`example.com`). Native clients use it too, so one
    /// key signs in from both. As for any relying party, it is permanent: a key enrolled under one
    /// ID cannot sign in under another.
    pub fn with_security_key_rp_id(
        mut self,
        rp_id: impl Into<String>,
    ) -> Result<Self, AccountError> {
        let rp_id = rp_id.into();
        if !is_domain(&rp_id) {
            return Err(error!(
                ErrorCode::PqSignInUnavailable,
                "a security-key relying party ID is a bare domain, such as example.com"
            ));
        }
        self.security_key_rp_id = Some(rp_id);
        Ok(self)
    }

    pub fn oprf_seed(&self) -> &OprfSeed {
        &self.oprf_seed
    }

    pub fn ksf(&self) -> KsfParams {
        self.ksf
    }

    /// The relying party security keys are scoped to; `None` when this server has not enabled
    /// them.
    pub fn security_key_rp_id(&self) -> Option<&str> {
        self.security_key_rp_id.as_deref()
    }
}

/// A lowercase DNS name: what WebAuthn accepts as a relying party ID. No scheme, port or path,
/// and not an IP address.
fn is_domain(name: &str) -> bool {
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let top_level_is_numeric = name
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()));
    name.len() <= 253 && name.split('.').all(label_ok) && !top_level_is_numeric
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> PqAuthServerSettings {
        PqAuthServerSettings::new(OprfSeed::from_bytes([1u8; 32]), KsfParams::FLOOR).unwrap()
    }

    #[test]
    fn a_relying_party_id_is_a_bare_domain() {
        for rp_id in [
            "example.com",
            "login.example.co.uk",
            "localhost",
            "a-b.example",
        ] {
            let settings = settings().with_security_key_rp_id(rp_id).unwrap();
            assert_eq!(settings.security_key_rp_id(), Some(rp_id));
        }
        for rp_id in [
            "",
            "https://example.com",
            "example.com:443",
            "example.com/login",
            "Example.com",
            "127.0.0.1",
            "-example.com",
            "example..com",
        ] {
            assert!(
                settings().with_security_key_rp_id(rp_id).is_err(),
                "{rp_id:?} is not a relying party ID"
            );
        }
        assert_eq!(settings().security_key_rp_id(), None);
    }
}
