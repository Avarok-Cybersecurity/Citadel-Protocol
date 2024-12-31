//! Credential Proposal and Validation
//!
//! This module handles the creation, validation, and processing of user credentials
//! in the Citadel Protocol, supporting both password-based and passwordless authentication.
//!
//! # Features
//!
//! * **Credential Management**
//!   - Password hashing with Argon2id
//!   - Username sanitization
//!   - Full name handling
//!   - Passwordless mode support
//!
//! * **Security Features**
//!   - Secure password transformation
//!   - Random salt generation
//!   - Configurable Argon2 parameters
//!   - Memory-safe credential handling
//!
//! * **Validation**
//!   - Server-side validation
//!   - Credential comparison
//!   - Username uniqueness
//!   - Format sanitization
//!
//! # Important Notes
//!
//! * Passwords are pre-hashed with SHA-3 before Argon2
//! * All strings are trimmed and sanitized
//! * Registration generates secure random secrets
//! * Credentials are zeroed after use
//! * Server validates all client credentials
//!
//! # Related Components
//!
//! * `DeclaredAuthenticationMode` - Final auth state
//! * `ServerMiscSettings` - Server validation rules
//! * `ArgonContainerType` - Password hashing
//! * `AccountManager` - Uses proposed credentials

use crate::auth::DeclaredAuthenticationMode;
use crate::misc::AccountError;
use crate::server_misc_settings::ServerMiscSettings;
use bstr::ByteSlice;
use citadel_crypt::argon::argon_container::{
    ArgonContainerType, ArgonSettings, ArgonStatus, AsyncArgon, ServerArgonContainer,
};
use citadel_types::crypto::SecBuffer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Digest;

/// When creating credentials, this is required
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum ProposedCredentials {
    /// Denotes that credentials will be used
    Enabled {
        /// Username of the client
        username: String,
        /// Password (hashed)
        password_hashed: SecBuffer,
        /// Full name or alternative moniker
        full_name: String,
        /// Only existent if the new_register constructor is called. Serialization of this field is skipped since this is only used for clientside
        #[serde(skip)]
        clientside_only_registration_settings: Option<ArgonSettings>,
    },

    /// Denotes that credentials will not be used (passwordless)
    Disabled { username: String },
}

// Clientside impls
impl ProposedCredentials {
    /// Generates the proper connect credentials. Does NOT trim the password (if trimming is needed, make sure the password is already trimmed before calling this function).
    pub async fn new_connect<T: Into<String> + Send, R: Into<String> + Send>(
        full_name: T,
        username: R,
        password_raw: SecBuffer,
        settings: ArgonSettings,
    ) -> Result<Self, AccountError> {
        let (username, full_name, password_hashed) =
            Self::sanitize_and_prepare(username, full_name, password_raw.as_ref(), false);

        let password_hashed = Self::argon_hash(password_hashed, settings).await?;
        Ok(Self::Enabled {
            username,
            password_hashed,
            full_name,
            clientside_only_registration_settings: None,
        })
    }

    /// Generates an empty skeleton for authless mode
    pub fn transient<T: Into<String>>(username: T) -> Self {
        Self::Disabled {
            username: username.into(),
        }
    }

    /// Generates the proper registration credentials. Trims the username, password, and full name, removing any whitespace from the ends. Should only be called client-side
    ///
    /// 'Whitespace' is defined according to the terms of the Unicode Derived Core Property White_Space.
    pub async fn new_register<T: Into<String> + Send, R: Into<String> + Send>(
        full_name: T,
        username: R,
        password_unhashed: SecBuffer,
    ) -> Result<Self, AccountError> {
        let (username, full_name, password_unhashed) =
            Self::sanitize_and_prepare(username, full_name, password_unhashed.as_ref(), true);

        // the secret will be stored in the settings which is stored in the CNAC locally clientside
        let secret = &mut [0u8; 32];
        {
            let mut rng = rand::thread_rng();
            rng.fill_bytes(secret);
        }

        let settings = ArgonSettings::new_defaults_with_static_secret(
            full_name.clone().into_bytes(),
            secret.to_vec(),
        );
        let password_hashed = Self::argon_hash(password_unhashed, settings.clone()).await?;
        Ok(Self::Enabled {
            username,
            password_hashed,
            full_name,
            clientside_only_registration_settings: Some(settings),
        })
    }

    async fn argon_hash(
        password_unhashed: SecBuffer,
        settings: ArgonSettings,
    ) -> Result<SecBuffer, AccountError> {
        match AsyncArgon::hash(
            Self::password_transform(password_unhashed),
            settings.clone(),
        )
        .await
        .map_err(|err| AccountError::Generic(err.to_string()))?
        {
            ArgonStatus::HashSuccess(ret) => Ok(ret),
            other => Err(AccountError::Generic(format!(
                "Unable to hash input password: {other:?}",
            ))),
        }
    }

    fn sanitize_and_prepare<T: Into<String> + Send, R: Into<String> + Send>(
        username: T,
        full_name: R,
        maybe_hashed_password: &[u8],
        do_password_trim: bool,
    ) -> (String, String, SecBuffer) {
        let username = username.into();
        let full_name = full_name.into();

        let username = username.trim();
        let password = if do_password_trim {
            maybe_hashed_password.trim()
        } else {
            maybe_hashed_password
        };
        let full_name = full_name.trim();

        (username.to_string(), full_name.to_string(), password.into())
    }

    /// Gets all the internal values
    pub fn decompose(self) -> (String, SecBuffer, String, Option<ArgonSettings>) {
        match self {
            Self::Enabled {
                username,
                password_hashed,
                full_name,
                clientside_only_registration_settings,
            } => (
                username,
                password_hashed,
                full_name,
                clientside_only_registration_settings,
            ),
            Self::Disabled { username } => (username, SecBuffer::empty(), String::new(), None),
        }
    }

    /// SHA's the password before input into argon
    pub fn password_transform<T: AsRef<[u8]>>(password_raw: T) -> SecBuffer {
        let mut digest = sha3::Sha3_256::default();
        digest.update(password_raw.as_ref());
        digest.finalize().to_vec().into()
    }

    pub(crate) fn into_auth_store(self) -> DeclaredAuthenticationMode {
        match self {
            Self::Disabled { username } => DeclaredAuthenticationMode::Transient {
                username,
                full_name: "authless.client".to_string(),
            },
            Self::Enabled {
                username,
                full_name,
                clientside_only_registration_settings,
                ..
            } => DeclaredAuthenticationMode::Argon {
                username,
                full_name,
                argon: ArgonContainerType::Client(
                    clientside_only_registration_settings
                        .unwrap_or_default()
                        .into(),
                ),
            },
        }
    }

    /// Returns true if passwordless
    pub fn is_passwordless(&self) -> bool {
        matches!(self, Self::Disabled { .. })
    }

    /// Returns the username or uuid of the client
    pub fn username(&self) -> &str {
        match self {
            ProposedCredentials::Enabled { username, .. }
            | ProposedCredentials::Disabled { username } => username.as_str(),
        }
    }
}

// Serverside impls
impl ProposedCredentials {
    /// Called when the server registers the client-provided credentials
    pub async fn derive_server_container(
        self,
        server_argon_settings: &ArgonSettings,
        server_misc_settings: &ServerMiscSettings,
    ) -> Result<DeclaredAuthenticationMode, AccountError> {
        match self {
            Self::Disabled { .. } => {
                if server_misc_settings.allow_passwordless {
                    Ok(self.into_auth_store())
                } else {
                    Err(AccountError::msg(
                        "This node does not support passwordless connections",
                    ))
                }
            }

            Self::Enabled {
                username,
                password_hashed,
                full_name,
                ..
            } => {
                let settings =
                    server_argon_settings.derive_new_with_custom_ad(username.clone().into_bytes());

                match AsyncArgon::hash(password_hashed, settings.clone())
                    .await
                    .map_err(|err| AccountError::Generic(err.to_string()))?
                {
                    ArgonStatus::HashSuccess(hash_x2) => Ok(DeclaredAuthenticationMode::Argon {
                        username,
                        full_name,
                        argon: ArgonContainerType::Server(ServerArgonContainer::new(
                            settings, hash_x2,
                        )),
                    }),

                    _ => Err(AccountError::Generic("Unable to hash password".to_string())),
                }
            }
        }
    }

    /// Validates the credentials
    pub async fn validate_credentials(
        self,
        argon_container: ArgonContainerType,
    ) -> Result<(), AccountError> {
        if self.is_passwordless() {
            return Ok(());
        }

        let password_hashed = self.decompose().1;

        match argon_container {
            ArgonContainerType::Server(server_container) => {
                match AsyncArgon::verify(password_hashed, server_container)
                    .await
                    .map_err(|err| AccountError::Generic(err.to_string()))?
                {
                    ArgonStatus::VerificationSuccess => Ok(()),

                    ArgonStatus::VerificationFailed(None) => {
                        log::warn!(target: "citadel", "Invalid password specified ...");
                        Err(AccountError::InvalidPassword)
                    }

                    ArgonStatus::VerificationFailed(Some(err)) => {
                        log::error!(target: "citadel", "Password verification failed: {}", &err);
                        Err(AccountError::Generic(err))
                    }

                    _ => Err(AccountError::InvalidPassword),
                }
            }

            _ => Err(AccountError::Generic(
                "Account does not have password loaded; account is personal".to_string(),
            )),
        }
    }

    /// Compares usernames for equality
    pub fn compare_username(&self, other: &[u8]) -> bool {
        match self {
            Self::Disabled { username } | Self::Enabled { username, .. } => {
                username.as_bytes() == other
            }
        }
    }
}
