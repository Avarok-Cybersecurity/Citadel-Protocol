/// Miscellaneous settings for a node serving connections
#[derive(Clone)]
pub struct ServerMiscSettings {
    /// If enabled, allows inbound connections to use no credentials when logging-in
    pub allow_passwordless: bool,
}

impl Default for ServerMiscSettings {
    fn default() -> Self {
        Self {
            allow_passwordless: true,
        }
    }
}
