//! Error types for the Citadel Nexus abstraction layer

use std::fmt;

/// The main error type for Citadel Nexus operations
#[derive(Debug)]
pub enum NexusError {
    /// Network I/O error
    Io(std::io::Error),
    
    /// Connection error
    Connection(String),
    
    /// NAT traversal error
    NatTraversal(String),
    
    /// Platform-specific error
    Platform(String),
    
    /// Configuration error
    Configuration(String),
    
    /// Timeout error
    Timeout,
    
    /// Operation would block (non-blocking I/O)
    WouldBlock,
    
    /// Not supported on this platform
    NotSupported(String),
    
    /// Serialization/deserialization error
    Serialization(String),
    
    /// WebRTC-specific error (WASM only)
    #[cfg(target_family = "wasm")]
    WebRTC(String),
    
    /// Generic error with message
    Other(String),
}

impl fmt::Display for NexusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Connection(msg) => write!(f, "Connection error: {}", msg),
            Self::NatTraversal(msg) => write!(f, "NAT traversal error: {}", msg),
            Self::Platform(msg) => write!(f, "Platform error: {}", msg),
            Self::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::WouldBlock => write!(f, "Operation would block"),
            Self::NotSupported(op) => write!(f, "Operation '{}' not supported on this platform", op),
            Self::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            #[cfg(target_family = "wasm")]
            Self::WebRTC(msg) => write!(f, "WebRTC error: {}", msg),
            Self::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for NexusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for NexusError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<NexusError> for std::io::Error {
    fn from(error: NexusError) -> Self {
        match error {
            NexusError::Io(io_error) => io_error,
            other => std::io::Error::new(std::io::ErrorKind::Other, other),
        }
    }
}

impl From<anyhow::Error> for NexusError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error.to_string())
    }
}

/// Result type alias for Citadel Nexus operations
pub type NexusResult<T> = Result<T, NexusError>;