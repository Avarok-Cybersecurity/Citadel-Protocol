use std::error::Error;
use std::fmt::{Display, Debug};
use std::fmt::Formatter;
use tokio::sync::mpsc::error::SendError;
use hyxe_user::misc::AccountError;
use hyxe_crypt::misc::CryptError;

/// The basic error type for this crate
pub enum NetworkError {
    /// Thrown when the underlying socket fails
    SocketError(String),
    /// Timeout occured for cid self.0
    Timeout(u64),
    /// A bad packet
    InvalidPacket(&'static str),
    /// Occurs when the requested packet size is over the maximum
    InvalidPacketSize(usize),
    /// A bad external request
    InvalidRequest(&'static str),
    ///
    InternalError(&'static str),
    /// For a converted error
    Generic(String),
    ///
    ProperShutdown
}

impl Error for NetworkError {}

impl Debug for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_msg())
    }
}

impl NetworkError {
    fn to_msg(&self) -> String {
        match self {
            NetworkError::SocketError(err) => {
                err.to_string()
            }

            NetworkError::Generic(err) => {
                err.to_string()
            }
            NetworkError::Timeout(val) => {
                format!("Timeout at {}", val)
            }
            NetworkError::InternalError(err) => {
                format!("{}", *err)
            }
            NetworkError::InvalidPacketSize(size) => {
                format!("Excess packet size requested: {}", *size)
            }
            NetworkError::InvalidRequest(err) => {
                format!("{}", *err)
            }
            NetworkError::InvalidPacket(err) => {
                format!("{}", *err)
            }
            NetworkError::ProperShutdown => {
                format!("Proper shutdown called")
            }
        }
    }

    pub fn into_string(self) -> String {
        match self {
            NetworkError::SocketError(err) => {
                err
            }

            NetworkError::Generic(err) => {
                err
            }
            NetworkError::Timeout(val) => {
                format!("Timeout at {}", val)
            }
            NetworkError::InternalError(err) => {
                format!("{}", err)
            }
            NetworkError::InvalidPacketSize(size) => {
                format!("Excess packet size requested: {}", size)
            }
            NetworkError::InvalidRequest(err) => {
                format!("{}", err)
            }
            NetworkError::InvalidPacket(err) => {
                format!("{}", err)
            }
            NetworkError::ProperShutdown => {
                format!("{:?}", NetworkError::ProperShutdown)
            }
        }
    }

    pub fn msg<T: Into<String>>(msg: T) -> Self {
        Self::Generic(msg.into())
    }
}

impl Display for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for NetworkError {
    fn from(err: SendError<T>) -> Self {
        NetworkError::Generic(err.to_string())
    }
}

impl From<AccountError> for NetworkError {
    fn from(err: AccountError) -> Self {
        NetworkError::Generic(err.into_string())
    }
}

impl From<anyhow::Error> for NetworkError {
    fn from(err: anyhow::Error) -> Self {
        NetworkError::Generic(err.to_string())
    }
}

impl From<CryptError> for NetworkError {
    fn from(err: CryptError) -> Self {
        Self::Generic(err.into_string())
    }
}

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        NetworkError::Generic(err.to_string())
    }
}