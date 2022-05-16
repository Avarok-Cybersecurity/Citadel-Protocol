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
            AccountError::ClientExists(cid) => format!("Client {} already exists", cid),
            AccountError::ClientNonExists(cid) => format!("Client {} does not exist", cid),
            AccountError::ServerExists(cid) => format!("Server {} already exists", cid),
            AccountError::ServerNonExists(cid) => format!("Server {} does not exist", cid),
            AccountError::Disengaged(cid) => format!("Server {} is not engaged", cid)
        }
    }
}

/// Meant for easy mapping of an optional type into a result type
pub trait EmptyOptional<T> {
    /// Maps the empty value to an error type
    fn map_empty_err(self) -> Result<T, AccountError>;
    /// Maps the empty value to an error type with a custom message
    fn map_empty_err_ctx<R: Into<String>>(self, msg: R) -> Result<T, AccountError>;
}

impl<T> EmptyOptional<T> for Option<T> {
    fn map_empty_err(self) -> Result<T, AccountError> {
        self.map_empty_err_ctx("empty error")
    }

    fn map_empty_err_ctx<R: Into<String>>(self, msg: R) -> Result<T, AccountError> {
        self.ok_or_else(|| AccountError::msg(msg))
    }
}

impl<T: ToString> From<T> for AccountError {
    fn from(err: T) -> Self {
        AccountError::Generic(err.to_string())
    }
}

const MIN_PASSWORD_LENGTH: usize = 7;
const MAX_PASSWORD_LENGTH: usize = 17;

const MIN_USERNAME_LENGTH: usize = 3;
///
pub const MAX_USERNAME_LENGTH: usize = 37;

const MIN_NAME_LENGTH: usize = 2;
const MAX_NAME_LENGTH: usize = 77;

const ASCII_ONLY: bool = false;

/// Used to determine if the desired credentials have a valid format, length, etc. This alone DOES NOT imply whether or not the
/// credentials are available
pub fn check_credential_formatting<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(username: T, password: Option<R>, full_name: V) -> Result<(), AccountError> {
    let username = username.as_ref();
    let full_name = full_name.as_ref();
    
    if ASCII_ONLY {
        if !username.is_ascii() {
            return Err(AccountError::Generic("Username contains non-ascii characters".to_string()));
        }

        if let Some(password) = password.as_ref() {
            if !password.as_ref().is_ascii() {
                return Err(AccountError::Generic("Password contains non-ascii characters".to_string()));
            }
        }

        if !full_name.is_ascii() {
            return Err(AccountError::Generic("Full name contains non-ascii characters".to_string()));
        }
    }

    if username.len() < MIN_USERNAME_LENGTH || username.len() > MAX_USERNAME_LENGTH {
        return Err(AccountError::Generic(format!("Username must be between {} and {} characters", MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)));
    }

    if username.contains(' ') {
        return Err(AccountError::Generic("Username cannot contain spaces. Use a period instead".to_string()));
    }

    if let Some(password) = password.as_ref() {
        let password = password.as_ref();
        if password.len() < MIN_PASSWORD_LENGTH || password.len() > MAX_PASSWORD_LENGTH {
            return Err(AccountError::Generic(format!("Password must be between {} and {} characters", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)));
        }

        if password.contains(' ') {
            return Err(AccountError::Generic("Password cannot contain spaces".to_string()));
        }
    }

    if full_name.len() < MIN_NAME_LENGTH || full_name.len() > MAX_NAME_LENGTH {
        return Err(AccountError::Generic(format!("Full name must be between {} and {} characters", MIN_NAME_LENGTH, MAX_NAME_LENGTH)));
    }

    Ok(())
}

/// For convenience ser/de
pub mod constructor_map {
    use std::collections::HashMap;
    use hyxe_crypt::hyper_ratchet::{Ratchet, HyperRatchet};
    use hyxe_crypt::hyper_ratchet::constructor::ConstructorType;
    use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
    use std::ops::{Deref, DerefMut};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use serde::ser::SerializeMap;

    /// A no-serialization container (except for FCM, since we need to preserve them)
    pub struct ConstructorMap<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
        inner: HashMap<u64, ConstructorType<R, Fcm>>
    }

    impl<R: Ratchet, Fcm: Ratchet> ConstructorMap<R, Fcm> {
        /// Creates an empty hashmap. No allocation occurs
        pub fn new() -> Self {
            Self { inner: HashMap::with_capacity(0) }
        }
    }

    impl<R: Ratchet, Fcm: Ratchet> Default for ConstructorMap<R, Fcm> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<R: Ratchet, Fcm: Ratchet> Deref for ConstructorMap<R, Fcm> {
        type Target = HashMap<u64, ConstructorType<R, Fcm>>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<R: Ratchet, Fcm: Ratchet> DerefMut for ConstructorMap<R, Fcm> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl<R: Ratchet, Fcm: Ratchet> Serialize for ConstructorMap<R, Fcm> {
        fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {
            let map = serializer.serialize_map(Some(0))?;
            map.end()
        }
    }

    impl<'de, R: Ratchet, Fcm: Ratchet> Deserialize<'de> for ConstructorMap<R, Fcm> {
        fn deserialize<D>(_deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
            D: Deserializer<'de> {
            Ok(ConstructorMap::default())
        }
    }
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
    pub creation_date: String
}

