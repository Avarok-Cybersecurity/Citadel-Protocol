use crate::packet::ReferenceIdentifier;
use std::convert::From;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Kiss code, reason of a Kiss-o'-Death reply.
///
/// Kiss code provides an information about why SNTP sent a Kiss-o'-Death packet, i.e. why the
/// request is rejected by the server. This enum is generally a 1-to-1 mapping for SNTP RFC kiss
/// codes, see RFC 4330 section 8.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KissCode {
    /// Unknown code
    Unknown,
    /// The association belongs to a anycast server
    AssociationBelongsToAnycastServer,
    /// The association belongs to a broadcast server
    AssociationBelongsToBroadcastServer,
    /// The association belongs to a manycast server
    AssociationBelongsToManycastServer,
    /// Server authentication failed
    ServerAuthenticationFailed,
    /// Autokey sequence failed
    AutokeySequenceFailed,
    /// Cryptographic authentication or identification failed
    CryptographicAuthenticationFailed,
    /// Access denied by remote server
    AccessDenied,
    /// Lost peer in symmetric mode
    LostPeer,
    /// The association has not yet synchronized for the first time
    AssociationNotYetSynchronized,
    /// No key found.  Either the key was never installed or is not trusted
    NoKeyFound,
    /// Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold
    RateExceeded,
    /// Somebody is tinkering with the association from a remote host running ntpdc.
    /// Not to worry unless some rascal has stolen your keys
    TinkeringWithAssociation,
    /// A step change in system time has occurred, but the association has not yet resynchronized
    StepChange,
}

impl KissCode {
    pub(crate) fn new(reference_identifier: &ReferenceIdentifier) -> KissCode {
        if let ReferenceIdentifier::ASCII(s) = reference_identifier {
            match s.as_str() {
                "ACST" => KissCode::AssociationBelongsToAnycastServer,
                "AUTH" => KissCode::ServerAuthenticationFailed,
                "AUTO" => KissCode::AutokeySequenceFailed,
                "BCST" => KissCode::AssociationBelongsToBroadcastServer,
                "CRYP" => KissCode::CryptographicAuthenticationFailed,
                "DENY" => KissCode::AccessDenied,
                "DROP" => KissCode::LostPeer,
                "RSTR" => KissCode::AccessDenied,
                "INIT" => KissCode::AssociationNotYetSynchronized,
                "MCST" => KissCode::AssociationBelongsToManycastServer,
                "NKEY" => KissCode::NoKeyFound,
                "RATE" => KissCode::RateExceeded,
                "RMOT" => KissCode::TinkeringWithAssociation,
                "STEP" => KissCode::StepChange,
                _ => KissCode::Unknown,
            }
        } else {
            KissCode::Unknown
        }
    }
}

impl Display for KissCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
      KissCode::Unknown => write!(f, "Unknown"),
      KissCode::AssociationBelongsToAnycastServer => {
        write!(f, "The association belongs to a anycast server")
      }
      KissCode::AssociationBelongsToBroadcastServer => {
        write!(f, "The association belongs to a broadcast server")
      }
      KissCode::AssociationBelongsToManycastServer => {
        write!(f, "The association belongs to a manycast server")
      }
      KissCode::ServerAuthenticationFailed => write!(f, "Server authentication failed"),
      KissCode::AutokeySequenceFailed => write!(f, "Autokey sequence failed"),
      KissCode::CryptographicAuthenticationFailed => {
        write!(f, "Cryptographic authentication or identification failed")
      }
      KissCode::AccessDenied => write!(f, "Access denied by remote server"),
      KissCode::LostPeer => write!(f, "Lost peer in symmetric mode"),
      KissCode::AssociationNotYetSynchronized => write!(
        f,
        "The association has not yet synchronized for the first time"
      ),
      KissCode::NoKeyFound => write!(
        f,
        "No key found.  Either the key was never installed or is not trusted"
      ),
      KissCode::RateExceeded => write!(f, "Rate exceeded.  The server has temporarily denied access because the client exceeded the rate threshold"),
      KissCode::TinkeringWithAssociation => write!(f, "Somebody is tinkering with the association from a remote host"),
      KissCode::StepChange => write!(f, " step change in system time has occurred, but the association has not yet resynchronized"),
    }
    }
}

/// A detailed information about SNTP protocol related errors.
///
/// This is a more detailed description of the error and can be used by clients which needs a more
/// elaborate information about the reason of the failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    /// Server reply packet is too short
    PacketIsTooShort,
    /// Server reply packet has unsupported version
    InvalidPacketVersion,
    /// Server reply packet contains invalid leap indicator
    InvalidLeapIndicator,
    /// Server reply packet contains invalid mode
    InvalidMode,
    /// Server reply contains invalid originate timestamp
    InvalidOriginateTimestamp,
    /// Server reply contains invalid transmit timestamp
    InvalidTransmitTimestamp,
    /// Server reply contains invalid reference identifier
    InvalidReferenceIdentifier,
    /// Kiss-o'-Death packet received. KoD indicates that the server rejected the request and generally
    /// means that the client should stop sending request to the server.
    KissODeath(KissCode),
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::PacketIsTooShort => write!(f, "Server reply packet is too short"),
            ProtocolError::InvalidPacketVersion => {
                write!(f, "Server reply packet has unsupported version")
            }
            ProtocolError::InvalidLeapIndicator => {
                write!(f, "Server reply packet contains invalid leap indicator")
            }
            ProtocolError::InvalidMode => write!(f, "Server reply packet contains invalid mode"),
            ProtocolError::InvalidOriginateTimestamp => {
                write!(f, "Server reply contains invalid originate timestamp")
            }
            ProtocolError::InvalidTransmitTimestamp => {
                write!(f, "Server reply contains invalid transmit timestamp")
            }
            ProtocolError::InvalidReferenceIdentifier => {
                write!(f, "Server reply contains invalid reference identifier")
            }
            ProtocolError::KissODeath(code) => {
                write!(f, "Kiss-o'-Death packet received: {}", code.to_string())
            }
        }
    }
}

/// Synchronization error
///
/// Returned when synchronization fails.
#[derive(Debug)]
pub enum SynchroniztationError {
    /// An I/O error occured during the query, like socket error, timeout, etc...
    IOError(std::io::Error),
    /// SNTP protocol specific error
    ProtocolError(ProtocolError),
}

impl Error for SynchroniztationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SynchroniztationError::IOError(io_error) => Some(io_error),
            SynchroniztationError::ProtocolError(protocol_error) => Some(protocol_error),
        }
    }
}

impl Display for SynchroniztationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SynchroniztationError::IOError(io_error) => {
                write!(f, "Input/output error: {}", io_error.to_string())
            }
            SynchroniztationError::ProtocolError(protocol_error) => {
                write!(f, "Protocol error: {}", protocol_error.to_string())
            }
        }
    }
}

impl From<std::io::Error> for SynchroniztationError {
    fn from(io_error: std::io::Error) -> SynchroniztationError {
        SynchroniztationError::IOError(io_error)
    }
}

impl From<ProtocolError> for SynchroniztationError {
    fn from(protocol_error: ProtocolError) -> SynchroniztationError {
        SynchroniztationError::ProtocolError(protocol_error)
    }
}
