/// Default Error type for this crate
#[derive(Debug)]
pub enum AccountError<T: ToString> {
    /// Input/Output error. Used for possibly failed Serialization/Deserialization of underlying datatypes
    IoError(T),
    /// The [NetworkMap] does not have a valid configuration
    NetworkMapLoad(T),
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
    Generic(T),
}

impl<T: ToString> AccountError<T> {
    /// Consumes self and returns the underlying error message
    pub fn to_string(self) -> String {
        match self {
            AccountError::IoError(e) => e.to_string(),
            AccountError::Generic(e) => e.to_string(),
            AccountError::InvalidUsername => "Invalid username".to_string(),
            AccountError::InvalidPassword => "Invalid password".to_string(),
            AccountError::NetworkMapLoad(e) => e.to_string(),
            AccountError::ClientExists(cid) => format!("Client {} already exists", cid),
            AccountError::ClientNonExists(cid) => format!("Client {} does not exist", cid),
            AccountError::ServerExists(cid) => format!("Server {} already exists", cid),
            AccountError::ServerNonExists(cid) => format!("Server {} does not exist", cid),
            AccountError::Disengaged(cid) => format!("Server {} is not engaged", cid)
        }
    }
}

impl<T: ToString> From<T> for AccountError<String> {
    fn from(err: T) -> Self {
        AccountError::Generic(err.to_string())
    }
}

const MIN_PASSWORD_LENGTH: usize = 7;
const MAX_PASSWORD_LENGTH: usize = 17;

const MIN_USERNAME_LENGTH: usize = 7;
const MAX_USERNAME_LENGTH: usize = 17;

const MIN_NAME_LENGTH: usize = 2;
const MAX_NAME_LENGTH: usize = 77;

const ASCII_ONLY: bool = false;

/// Used to determine if the desired credentials have a valid format, length, etc. This alone DOES NOT imply whether or not the
/// credentials are available
pub fn check_credential_formatting<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(username: &T, password: Option<&R>, full_name: &V) -> Result<(), AccountError<String>> {
    let username = username.as_ref();
    let full_name = full_name.as_ref();
    
    if ASCII_ONLY {
        if !username.is_ascii() {
            return Err(AccountError::Generic("Username contains non-ascii characters".to_string()));
        }

        if let Some(password) = password {
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

    if let Some(password) = password {
        let password = password.as_ref();
        if password.len() < MIN_PASSWORD_LENGTH || password.len() > MAX_PASSWORD_LENGTH {
            return Err(AccountError::Generic(format!("Password must be between {} and {} characters", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)));
        }
    }

    if full_name.len() < MIN_NAME_LENGTH || full_name.len() > MAX_NAME_LENGTH {
        return Err(AccountError::Generic(format!("Full name must be between {} and {} characters", MIN_NAME_LENGTH, MAX_NAME_LENGTH)));
    }

    Ok(())
}

/*
use future_parking_lot::rwlock::FutureRawRwLock;
use future_parking_lot::parking_lot::lock_api::{RwLockReadGuard, RwLockWriteGuard};
use future_parking_lot::parking_lot::RawRwLock;
use std::ops::{Deref, DerefMut};

/// Makes awaiting thread-safe
pub struct FutureRwLockWriteGuard<'a, T> {
    inner: RwLockWriteGuard<'a, FutureRawRwLock<RawRwLock>, T>
}

unsafe impl<'a, T> Send for FutureRwLockWriteGuard<'a, T> {}

impl<'a, T> FutureRwLockWriteGuard<'a, T> {
    /// Wraps
    pub fn wrap(inner: RwLockWriteGuard<'a, FutureRawRwLock<RawRwLock>, T>) -> Self {
        Self { inner }
    }
}

impl<'a, T> Deref for FutureRwLockWriteGuard<'a, T> {
    type Target = RwLockWriteGuard<'a, FutureRawRwLock<RawRwLock>, T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T> DerefMut for FutureRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Makes awaiting thread-safe
pub struct FutureRwLockReadGuard<'a, T> {
    inner: RwLockReadGuard<'a, FutureRawRwLock<RawRwLock>, T>
}

unsafe impl<'a, T> Send for FutureRwLockReadGuard<'a, T> {}

impl<'a, T> FutureRwLockReadGuard<'a, T> {
    /// Wraps
    pub fn wrap(inner: RwLockReadGuard<'a, FutureRawRwLock<RawRwLock>, T>) -> Self {
        Self { inner }
    }
}

impl<'a, T> Deref for FutureRwLockReadGuard<'a, T> {
    type Target = RwLockReadGuard<'a, FutureRawRwLock<RawRwLock>, T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T> DerefMut for FutureRwLockReadGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
*/