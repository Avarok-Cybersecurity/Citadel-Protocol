use std::error::Error;

/// The basic error type for this crate
#[derive(Debug)]
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

impl ToString for NetworkError {
    fn to_string(&self) -> String {
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

impl<T: Error> From<T> for NetworkError {
    fn from(err: T) -> Self {
        NetworkError::Generic(err.to_string())
    }
}