use crate::connection::temporary_bridge::TemporaryBridge;
use hyxe_user::prelude::ClientNetworkAccount;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use crate::packet::misc::ConnectError;
use std::pin::Pin;
use crate::packet::definitions::registration::{STAGE0_SERVER, STAGE0_CLIENT_PENDING};
use hyxe_user::misc::check_credential_formatting;
use crate::routing::PacketRoute;
use crate::connection::network_map::NetworkMap;

/// The [RegistrationHandler] needs a container for tracking changes during the registration phase
pub(crate) struct RegistrationProcess {
    pub(crate) bridge: TemporaryBridge,
    pub(crate) generated_cnac: Option<ClientNetworkAccount>,
    /// Since this is a heap-pinned structure, we need to control any possible data races as mutable pointers are created
    pub(crate) semaphore: AtomicBool,
    pub(crate) local_is_client: bool,
    pub(crate) adjacent_is_hyperlan: Option<bool>,
    pub(crate) init_time: Instant,
    pub(crate) last_finished_state: u8
}

impl RegistrationProcess {
    /// Creates a heap-pinned [RegistrationProcess]. Whether the local is a client or not, tubing is needed.
    ///
    /// For clients: If the tubing leads directly to a server which needs to be registered to, indicate this
    /// by selecting `true` for `local_is_client` and `Some(true)` for `adjacent_is_hyperlan`.
    ///
    /// For servers: You received tubing in response to a connecting client. However, since this is stage0_server,
    /// you do not yet know if the client intends to register to you or to register *through* you and towards
    /// a HyperWAN server. You will not know this intention until the first packet arrives
    pub fn new(bridge: TemporaryBridge, local_is_client: bool, adjacent_is_hyperlan: Option<bool>) -> Pin<Box<Self>> {
        let last_finished_state = {
            if local_is_client {
                STAGE0_CLIENT_PENDING
            } else {
                STAGE0_SERVER
            }
        };

        Box::pin(Self {
            bridge,
            generated_cnac: None,
            semaphore: AtomicBool::new(false),
            local_is_client,
            adjacent_is_hyperlan,
            init_time: Instant::now(),
            last_finished_state
        })
    }

    /// Sends a stage zero client signal. This will panic if executed while in an invalid state
    pub fn send_stage0_client_signal<T: AsRef<[str]>, R: AsRef<str>, V: AsRef<str>>(&mut self, is_hyperlan: bool, username: &T, password: &R, full_name: &V, network_map: &NetworkMap) -> Result<(), ConnectError> {
        debug_assert_eq!(self.last_finished_state, STAGE0_CLIENT_PENDING);

        match check_credential_formatting(username, password, full_name) {
            Err(err) => return Err(ConnectError::Generic(err.to_string())),
            _ => {}
        }

        let network_map = network_map.read();

        let route = {
            if is_hyperlan {
                // In this case, the tubing provided within `self` points directly to the node of interest (i.e., a HyperLAN server)
                match PacketRoute::new_hyperlan_client_to_hyperlan_server()
            } else {
                // ... otherwise, the tubing within `self` points to the HyperLAN server which mediates the connection process
                // with a HyperWAN server
            }
        };
    }
}