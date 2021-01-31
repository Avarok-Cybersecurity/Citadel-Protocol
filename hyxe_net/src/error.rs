use std::error::Error;
use std::fmt::{Display, Debug};
use std::fmt::Formatter;
use tokio::sync::mpsc::error::SendError;

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
    InvalidExternalRequest(&'static str),
    ///
    InternalError(&'static str),
    /// For a converted error
    Generic(String)
}

impl Error for NetworkError {}

impl Debug for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg())
    }
}

impl NetworkError {
    fn msg(&self) -> String {
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
            NetworkError::InvalidExternalRequest(err) => {
                format!("{}", *err)
            }
            NetworkError::InvalidPacket(err) => {
                format!("{}", *err)
            }
        }
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