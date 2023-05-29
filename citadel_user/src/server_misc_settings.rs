use crate::credentials::CredentialRequirements;

/// Miscellaneous settings for a node serving connections
#[derive(Clone)]
pub struct ServerMiscSettings {
    /// If enabled, allows inbound connections to use no credentials when logging-in
    pub allow_passwordless: bool,
    /// Enforces specific requirements on credentials
    pub credential_requirements: CredentialRequirements,
}

impl Default for ServerMiscSettings {
    fn default() -> Self {
        Self {
            allow_passwordless: true,
            credential_requirements: Default::default(),
        }
    }
}
