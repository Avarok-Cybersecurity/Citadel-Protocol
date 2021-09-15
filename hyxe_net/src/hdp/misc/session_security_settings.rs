use hyxe_crypt::drill::SecurityLevel;
use crate::hdp::hdp_server::SecrecyMode;
use serde::{Serialize, Deserialize};
use ez_pqcrypto::algorithm_dictionary::CryptoParameters;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Default)]
pub struct SessionSecuritySettings {
    pub(crate) security_level: SecurityLevel,
    pub(crate) secrecy_mode: SecrecyMode,
    pub(crate) crypto_params: CryptoParameters
}

#[derive(Default)]
pub struct SessionSecuritySettingsBuilder {
    security_level: Option<SecurityLevel>,
    secrecy_mode: Option<SecrecyMode>,
    crypto_params: Option<CryptoParameters>
}

impl SessionSecuritySettingsBuilder {
    /// Default: LOW
    pub fn with_security_level(mut self, security_level: SecurityLevel) -> Self {
        self.security_level = Some(security_level);
        self
    }

    /// Default: BEST_EFFORT
    pub fn with_secrecy_mode(mut self, secrecy_mode: SecrecyMode) -> Self {
        self.secrecy_mode = Some(secrecy_mode);
        self
    }

    /// Default: Firesaber + AES_GCM_256_SIV
    pub fn with_crypto_params(mut self, params: impl Into<CryptoParameters>) -> Self {
        self.crypto_params = Some(params.into());
        self
    }

    pub fn build(self) -> SessionSecuritySettings {
        SessionSecuritySettings {
            security_level: self.security_level.unwrap_or(SecurityLevel::LOW),
            secrecy_mode: self.secrecy_mode.unwrap_or(SecrecyMode::BestEffort),
            crypto_params: self.crypto_params.unwrap_or_default()
        }
    }
}