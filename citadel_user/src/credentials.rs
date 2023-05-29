use crate::misc::AccountError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialRequirements {
    pub min_password_length: u8,
    pub max_password_length: u8,
    pub min_username_length: u8,
    pub max_username_length: u8,
    pub min_name_length: u8,
    pub max_name_length: u8,
}

impl Default for CredentialRequirements {
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
    /// Used to determine if the desired credentials have a valid format, length, etc. This alone DOES NOT imply whether or not the
    /// credentials are available
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

///
pub const MIN_PASSWORD_LENGTH: u8 = 7;
///
pub const MAX_PASSWORD_LENGTH: u8 = 17;

///
pub const MIN_USERNAME_LENGTH: u8 = 3;
///
pub const MAX_USERNAME_LENGTH: u8 = 37;

///
pub const MIN_NAME_LENGTH: u8 = 2;
///
pub const MAX_NAME_LENGTH: u8 = 77;
