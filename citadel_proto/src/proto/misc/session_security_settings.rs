//! Session Security Settings
//!
//! This module defines the security configuration options for Citadel Protocol sessions.
//! It provides settings for encryption, authentication, and other security-related
//! parameters that control how sessions operate.
//!
//! # Features
//!
//! - Encryption configuration
//! - Authentication settings
//! - Key management options
//! - Security level control
//! - Protocol version settings
//!
//! # Important Notes
//!
//! - Settings affect session security
//! - Some options require specific features
//! - Default settings are secure
//! - Settings are immutable after session start
//!
//! # Related Components
//!
//! - `session.rs`: Session management
//! - `underlying_proto.rs`: Protocol implementation
//! - `node.rs`: Node configuration
//! - `error.rs`: Error handling

use citadel_types::crypto::{CryptoParameters, SecrecyMode, SecurityLevel};
use citadel_types::proto::SessionSecuritySettings;

#[derive(Default)]
pub struct SessionSecuritySettingsBuilder {
    security_level: Option<SecurityLevel>,
    secrecy_mode: Option<SecrecyMode>,
    crypto_params: Option<CryptoParameters>,
}

impl SessionSecuritySettingsBuilder {
    /// Sets the maximum security level for the session, allowing the use of multi-layered encryption on a per-message basis as well as increased difficulty in breaking the recursive chain key (default: low)
    /// ```
    /// use citadel_proto::prelude::SessionSecuritySettingsBuilder;
    /// use citadel_crypt::entropy_bank::SecurityLevel;
    /// SessionSecuritySettingsBuilder::default()
    /// .with_security_level(SecurityLevel::Standard)
    /// .build();
    /// ```
    pub fn with_security_level(mut self, security_level: SecurityLevel) -> Self {
        self.security_level = Some(security_level);
        self
    }

    /// Sets the session secrecy mode. If Perfect is selected, then each message is guaranteed to use only a single symmetric key for encryption (best for high-security protocols that do not need high throughput)
    /// If BestEffort is selected, the protocol will attempt to re-key the system at the earliest opportunity, and will not enqueue packets if a re-key has not yet completed (best for high-throughput applications)
    /// If high relatively throughput is desired, but additional security is needed, consider coupling BestEffort mode with a higher security level for multi-layered cryptography
    /// ```
    /// use citadel_proto::prelude::{SessionSecuritySettingsBuilder, SecrecyMode};
    /// SessionSecuritySettingsBuilder::default()
    /// .with_secrecy_mode(SecrecyMode::BestEffort)
    /// .build();
    /// ```
    pub fn with_secrecy_mode(mut self, secrecy_mode: SecrecyMode) -> Self {
        self.secrecy_mode = Some(secrecy_mode);
        self
    }

    /// Default: Firesaber + AES_GCM_256_SIV
    /// ```
    /// use citadel_proto::prelude::SessionSecuritySettingsBuilder;
    /// use citadel_pqcrypto::algorithm_dictionary::{EncryptionAlgorithm, KemAlgorithm};
    /// SessionSecuritySettingsBuilder::default()
    /// .with_crypto_params(EncryptionAlgorithm::AES_GCM_256_SIV + KemAlgorithm::Kyber)
    /// .build();
    /// ```
    pub fn with_crypto_params(mut self, params: impl Into<CryptoParameters>) -> Self {
        self.crypto_params = Some(params.into());
        self
    }

    /// Constructs the [`SessionSecuritySettings`]
    pub fn build(self) -> Result<SessionSecuritySettings, anyhow::Error> {
        let settings = SessionSecuritySettings {
            security_level: self.security_level.unwrap_or(SecurityLevel::Standard),
            secrecy_mode: self.secrecy_mode.unwrap_or(SecrecyMode::BestEffort),
            crypto_params: self.crypto_params.unwrap_or_default(),
        };

        citadel_types::utils::validate_crypto_params(&settings.crypto_params)?;
        Ok(settings)
    }
}
