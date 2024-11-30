//! # Credential Management
//!
//! This module provides functionality for managing and validating user credentials
//! in the Citadel Protocol. It enforces consistent requirements for usernames,
//! passwords, and full names across the system.
//!
//! ## Features
//!
//! * **Credential Validation**
//!   - Username format and length checks
//!   - Password complexity requirements
//!   - Full name format validation
//!
//! * **Configurable Requirements**
//!   - Customizable length limits
//!   - Default security policies
//!   - Format restrictions
//!
//! * **Security Constraints**
//!   - No spaces in usernames (use periods)
//!   - No spaces in passwords
//!   - Length boundaries for all fields
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_user::credentials::CredentialRequirements;
//!
//! fn validate_credentials() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create default requirements
//!     let requirements = CredentialRequirements::default();
//!     
//!     // Validate credentials
//!     requirements.check(
//!         "john.doe",
//!         Some("secure_pass123"),
//!         "John Doe"
//!     )?;
//!     
//!     // Create custom requirements
//!     let custom_requirements = CredentialRequirements {
//!         min_password_length: 10,
//!         max_password_length: 20,
//!         min_username_length: 5,
//!         max_username_length: 30,
//!         min_name_length: 3,
//!         max_name_length: 50,
//!     };
//!     
//!     // Validate with custom requirements
//!     custom_requirements.check(
//!         "alice.smith",
//!         Some("very_secure_pass"),
//!         "Alice Smith"
//!     )?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Default length requirements:
//!   - Username: 3-37 characters
//!   - Password: 7-17 characters
//!   - Full Name: 2-77 characters
//!
//! * Validation rules:
//!   - Usernames must not contain spaces (use periods)
//!   - Passwords must not contain spaces
//!   - Full names can contain spaces
//!   - All fields have minimum and maximum lengths
//!
//! * Validation only checks format, not availability
//!
//! ## Related Components
//!
//! * `AccountManager` - Uses credentials for account creation
//! * `ProposedCredentials` - Credential proposal handling
//! * `ClientNetworkAccount` - Account credential storage
//! * `AccountError` - Credential validation errors
//!

use crate::misc::AccountError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
/// Represents the requirements for user credentials.
pub struct CredentialRequirements {
    /// The minimum length of a password.
    pub min_password_length: u8,
    /// The maximum length of a password.
    pub max_password_length: u8,
    /// The minimum length of a username.
    pub min_username_length: u8,
    /// The maximum length of a username.
    pub max_username_length: u8,
    /// The minimum length of a full name.
    pub min_name_length: u8,
    /// The maximum length of a full name.
    pub max_name_length: u8,
}

impl Default for CredentialRequirements {
    /// Returns the default `CredentialRequirements` instance.
    fn default() -> Self {
        Self {
            min_password_length: MIN_PASSWORD_LENGTH,
            max_password_length: MAX_PASSWORD_LENGTH,
            min_username_length: MIN_USERNAME_LENGTH,
            max_username_length: MAX_USERNAME_LENGTH,
            min_name_length: MIN_NAME_LENGTH,
            max_name_length: MAX_NAME_LENGTH,
        }
    }
}

impl CredentialRequirements {
    /// Checks if the provided credentials meet the requirements.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to check.
    /// * `password` - The password to check (optional).
    /// * `full_name` - The full name to check.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the credentials are valid.
    /// * `Err(AccountError)` if the credentials are invalid.
    pub fn check<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(
        &self,
        username: T,
        password: Option<R>,
        full_name: V,
    ) -> Result<(), AccountError> {
        let username = username.as_ref();
        let full_name = full_name.as_ref();

        if username.len() < self.min_username_length as _
            || username.len() > self.max_username_length as _
        {
            return Err(AccountError::Generic(format!(
                "Username must be between {} and {} characters",
                self.min_username_length, self.max_username_length
            )));
        }

        if username.contains(' ') {
            return Err(AccountError::Generic(
                "Username cannot contain spaces. Use a period instead".to_string(),
            ));
        }

        if let Some(password) = password.as_ref() {
            let password = password.as_ref();
            if password.len() < self.min_password_length as _
                || password.len() > self.max_password_length as _
            {
                return Err(AccountError::Generic(format!(
                    "Password must be between {} and {} characters",
                    self.min_password_length, self.max_password_length
                )));
            }

            if password.contains(' ') {
                return Err(AccountError::Generic(
                    "Password cannot contain spaces".to_string(),
                ));
            }
        }

        if full_name.len() < self.min_name_length as _
            || full_name.len() > self.max_name_length as _
        {
            return Err(AccountError::Generic(format!(
                "Full name must be between {} and {} characters",
                self.min_name_length, self.max_name_length
            )));
        }

        Ok(())
    }
}

/// The minimum length of a password.
pub const MIN_PASSWORD_LENGTH: u8 = 7;

/// The maximum length of a password.
pub const MAX_PASSWORD_LENGTH: u8 = 17;

/// The minimum length of a username.
pub const MIN_USERNAME_LENGTH: u8 = 3;

/// The maximum length of a username.
pub const MAX_USERNAME_LENGTH: u8 = 37;

/// The minimum length of a full name.
pub const MIN_NAME_LENGTH: u8 = 2;

/// The maximum length of a full name.
pub const MAX_NAME_LENGTH: u8 = 77;
