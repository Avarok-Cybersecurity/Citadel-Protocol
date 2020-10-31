//! This submodule is dedicated for extending an asynchronous event loop to the server which listens on the 2nd auxiliary port.
//! All signal which are received thereon must necessarily be 1-1 with other server ports for global synchronicity on the
//! HyperWAN (especially) and the HyperWAN. The signal types are listed under crate::packet::flags. The rules for those signals
//! are listed under crate::packet::definitions.
//!
//! The [Server] type, when ran, will run a registration event loop which can be .awaited under this module's registration_server
//! subroutine. If the server admin wants the registration server to not be active, and is satisfied with their HyperLAN or
//! HyperWAN setup, then this can be disabled in the server.hfg file under USER_HOME/.HyxeWave/server/. For enterprise setups, this
//! is especially recommended to prevent any unwanted visitors.
//!
//! Developer notes: The client wishing to register must be given a CID that does NOT collide with any other CID on the network.
pub const REGISTRATION_PORT: u16 = 25021;

use hyxe_fs::env::HYXE_SERVER_DIR;

/// The password used to validate the P12_IDENTITY certificate
pub const P12_PASSWORD: &str = "Xayiu4tvx5dzh4ha!!!0821";

lazy_static! {
    /// The default registration-port certificate. Stored within the %HYXE_HOME%/Server/ directory
    pub static ref P12_IDENTITY: String = format!("{}{}", HYXE_SERVER_DIR.to_string(), "certificate.p12");
}

/// The subroutines for handling a registration signal
pub mod registration_handler;

/// Allows tracking of the registration phase
pub mod registration_process;

/// This is for ensuring that the logic flows correctly
pub enum RegistrationStage {
    /// Tubing has been injected and is ready for external communications
    Stage0Complete,
    /// The first packet has been received, and the server has sent a notification with a nonce to the client
    /// that the request has been accepted; however, the server is now busy generating the f(0) drill, and as
    /// such, must await. The client is expected to create an expectancy for the transmission of the f(0) object
    Stage1Complete,
    /// This occurs once the client has sent an acknowledgement packet that it has received the f(0) drill. The server
    /// now creates an entry within the server [NetworkMap], followed by an entry within the server [AccountManager].
    /// Thereafter, the two are locally synchronized with the filesystem, and a REGISTRATION_SUCCESS is sent outbound.
    Stage2Complete
}

/// The registration process demands client -> server communication with object-data transfers for movement of the f(0) [DrillUpdateObject].
/// As such, an object expectancy is involved