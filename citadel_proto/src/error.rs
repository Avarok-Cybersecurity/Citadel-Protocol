use crate::prelude::NodeRequest;
use citadel_crypt::misc::CryptError;
use citadel_io::tokio::sync::mpsc::error::SendError;
use citadel_user::misc::AccountError;
use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Debug, Display};

/// The basic error type for this crate
pub enum NetworkError {
    /// Thrown when the underlying socket fails
    SocketError(String),
    /// Timeout occurred for cid self.0
    Timeout(u64),
    /// A bad packet
    InvalidPacket(&'static str),
    /// Occurs when the requested packet size is over the maximum
    InvalidPacketSize(usize),
    /// A bad external request
    InvalidRequest(&'static str),
    InternalError(&'static str),
    /// For a converted error
    Generic(String),
    /// for remote send errors
    NodeRemoteSendError {
        request: Box<NodeRequest>,
        reason: String,
    },
    ProperShutdown,
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
            NetworkError::SocketError(err) => err.to_string(),

            NetworkError::Generic(err) => err.to_string(),
            NetworkError::Timeout(val) => {
                format!("Timeout at {val}")
            }
            NetworkError::InternalError(err) => (*err).to_string(),
            NetworkError::InvalidPacketSize(size) => {
                format!("Excess packet size requested: {}", *size)
            }
            NetworkError::InvalidRequest(err) => (*err).to_string(),
            NetworkError::InvalidPacket(err) => (*err).to_string(),
            NetworkError::ProperShutdown => "Proper shutdown called".to_string(),
            NetworkError::NodeRemoteSendError { reason, .. } => reason.clone(),
        }
    }

    pub fn into_string(self) -> String {
        match self {
            NetworkError::SocketError(err) => err,

            NetworkError::Generic(err) => err,
            NetworkError::Timeout(val) => {
                format!("Timeout at {val}")
            }
            NetworkError::InternalError(err) => err.to_string(),
            NetworkError::InvalidPacketSize(size) => {
                format!("Excess packet size requested: {size}")
            }
            NetworkError::InvalidRequest(err) => err.to_string(),
            NetworkError::InvalidPacket(err) => err.to_string(),
            NetworkError::NodeRemoteSendError { reason, .. } => reason,
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

impl<T> From<citadel_io::tokio::sync::mpsc::error::SendError<T>> for NetworkError {
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
