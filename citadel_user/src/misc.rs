use chrono::Utc;

/// Default Error type for this crate
#[derive(Debug)]
pub enum AccountError {
    /// Input/Output error. Used for possibly failed Serialization/Deserialization of underlying datatypes
    IoError(String),
    /// The client already exists
    ClientExists(u64),
    /// The client does not exist
    ClientNonExists(u64),
    /// The server exists
    ServerExists(u64),
    /// The server does not exist
    ServerNonExists(u64),
    /// Invalid username
    InvalidUsername,
    /// Invalid password
    InvalidPassword,
    /// The server is not engaged
    Disengaged(u64),
    /// Generic error
    Generic(String),
}

impl AccountError {
    pub(crate) fn msg<T: Into<String>>(msg: T) -> Self {
        Self::Generic(msg.into())
    }

    /// Consumes self and returns the underlying error message
    pub fn into_string(self) -> String {
        match self {
            AccountError::IoError(e) => e,
            AccountError::Generic(e) => e,
            AccountError::InvalidUsername => "Invalid username".to_string(),
            AccountError::InvalidPassword => "Invalid password".to_string(),
            AccountError::ClientExists(cid) => format!("Client {cid} already exists"),
            AccountError::ClientNonExists(cid) => format!("Client {cid} does not exist"),
            AccountError::ServerExists(cid) => format!("Server {cid} already exists"),
            AccountError::ServerNonExists(cid) => format!("Server {cid} does not exist"),
            AccountError::Disengaged(cid) => format!("Server {cid} is not engaged"),
        }
    }
}

impl<T: ToString> From<T> for AccountError {
    fn from(err: T) -> Self {
        AccountError::Generic(err.to_string())
    }
}

///
pub const MIN_PASSWORD_LENGTH: usize = 7;
///
pub const MAX_PASSWORD_LENGTH: usize = 17;

///
pub const MIN_USERNAME_LENGTH: usize = 3;
///
pub const MAX_USERNAME_LENGTH: usize = 37;

///
pub const MIN_NAME_LENGTH: usize = 2;
///
pub const MAX_NAME_LENGTH: usize = 77;

/// Used to determine if the desired credentials have a valid format, length, etc. This alone DOES NOT imply whether or not the
/// credentials are available
pub fn check_credential_formatting<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(
    username: T,
    password: Option<R>,
    full_name: V,
) -> Result<(), AccountError> {
    let username = username.as_ref();
    let full_name = full_name.as_ref();

    if username.len() < MIN_USERNAME_LENGTH || username.len() > MAX_USERNAME_LENGTH {
        return Err(AccountError::Generic(format!(
            "Username must be between {} and {} characters",
            MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH
        )));
    }

    if username.contains(' ') {
        return Err(AccountError::Generic(
            "Username cannot contain spaces. Use a period instead".to_string(),
        ));
    }

    if let Some(password) = password.as_ref() {
        let password = password.as_ref();
        if password.len() < MIN_PASSWORD_LENGTH || password.len() > MAX_PASSWORD_LENGTH {
            return Err(AccountError::Generic(format!(
                "Password must be between {} and {} characters",
                MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
            )));
        }

        if password.contains(' ') {
            return Err(AccountError::Generic(
                "Password cannot contain spaces".to_string(),
            ));
        }
    }

    if full_name.len() < MIN_NAME_LENGTH || full_name.len() > MAX_NAME_LENGTH {
        return Err(AccountError::Generic(format!(
            "Full name must be between {} and {} characters",
            MIN_NAME_LENGTH, MAX_NAME_LENGTH
        )));
    }

    Ok(())
}

/// For passing metadata from a cnac
#[derive(Debug)]
pub struct CNACMetadata {
    /// Client ID
    pub cid: u64,
    /// Username
    pub username: String,
    /// Full name
    pub full_name: String,
    /// Whether CNAC is personal
    pub is_personal: bool,
    /// Date created
    pub creation_date: String,
}

impl PartialEq for CNACMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.cid == other.cid
            && self.username == other.username
            && self.full_name == other.full_name
            && self.is_personal == other.is_personal
    }
}

#[allow(missing_docs)]
#[cfg(all(feature = "sql", not(coverage)))]
pub mod base64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.collect_str(&base64::encode(value))
    }

    pub fn deserialize<'de, D>(value: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        base64::decode(
            String::deserialize(value).map_err(|_| serde::de::Error::custom("Deser err"))?,
        )
        .map_err(|_| serde::de::Error::custom("Deser err"))
    }
}

/// Returns the present timestamp in ISO 8601 format
pub fn get_present_formatted_timestamp() -> String {
    Utc::now().to_rfc3339()
}
