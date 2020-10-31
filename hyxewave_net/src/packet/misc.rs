use std::error::Error;
use std::fmt::{Display, Formatter};
use std::option::NoneError;
use hyxe_crypt::prelude::CryptError;

/// Default Error type for this crate
pub enum StageError {
    /// An error involving stage 0
    Stage0(String),
    /// An error involving stage 1
    Stage1(String),
    /// Generic error
    Generic(String)
}

impl StageError {

    /// returns a stage error
    pub fn throw<U, T: ToString>(input: T) -> Result<U, Self> {
        Err(StageError::Generic(input.to_string()))
    }

    /// Returns the underlying error message
    pub fn to_string(&self) -> &String {
        match self {
            StageError::Generic(e) => e,
            StageError::PacketVerificationError => e
        }
    }
}

/// The error type for connections and the processes associated therewith
pub enum ConnectError {
    /// Generic
    Generic(String),
    /// Stream is signalled to shut-down
    Shutdown,
    /// Stream is signalled to restart
    Restart,
    /// The connection is not engaged
    SystemNotEngaged,
    /// The tubing already exists. Used during the registration process
    TubingAlreadyExists,
    /// Port is not active
    PortNotActive,
    /// Invalid IP parsed
    InvalidIP,
    /// The CNAC is not loaded
    CNACNotLoaded,
    /// If the bridge is not opened, yet, an attempt is made to send data across it, this error is returned
    BridgeClosed,
    /// The router was unable to perform a clean packet translation
    BadRoute,
    /// The route already exists
    RouteExists,
    /// Bad TLS configuration
    InvalidTlsConfiguration,
    /// Invalid registration occured
    InvalidRegistration,
    /// A registration is already occuring for the given IP
    ConcurrentRegistrationExecuting,
    /// The expectancy already exists
    ExpectancyExists,
    /// Drill needed to decrypt the data does not exist
    DrillAbsent,
    /// Out of bounds
    OutOfBoundsError,
    /// No value available
    None,
    /// A timeout has occurred. This is used especially with expectancies'
    Timeout
}

impl Error for ConnectError {}
impl Error for StageError {}

impl Display for StageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Debug for StageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_string())
    }
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Debug for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_string())
    }
}

impl From<ConnectError> for () {
    fn from(_: ConnectError) -> Self {
        ()
    }
}

impl std::convert::From<std::option::NoneError> for ConnectError {
    fn from(_: NoneError) -> Self {
        ConnectError::None
    }
}

impl std::convert::From<hyxe_crypt::misc::CryptError<std::string::String>> for ConnectError {
    fn from(err: CryptError<String>) -> Self {
        ConnectError::Generic(err.to_string())
    }
}

