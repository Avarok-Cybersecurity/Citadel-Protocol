use crate::connection::server::SERVER_UP;
use crate::connection::server_bridge_handler::ServerBridgeHandler;
use std::pin::Pin;
use crate::packet::misc::ConnectError;
use crate::connection::network_map::NetworkMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Enables client-like subroutines for interfacing with the [ServerBridgeHandler]
#[derive(Copy, Clone)]
pub struct ClientHandle<'cxn, 'driver: 'cxn, 'server: 'driver> {
    ptr: *const ServerBridgeHandler<'cxn, 'driver, 'server>
}

unsafe impl<'cxn, 'driver: 'cxn, 'server: 'driver> Send for ClientHandle<'cxn, 'driver, 'server> {}
unsafe impl<'cxn, 'driver: 'cxn, 'server: 'driver> Sync for ClientHandle<'cxn, 'driver, 'server> {}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> ClientHandle<'cxn, 'driver, 'server> {
    /// This is safe so long as:
    /// [1] The pin contract is followed, and;
    /// [2] The pointee continues to exist* for at least the duration of the [ClientHandle], and;
    /// [3] Only accesses to concurrent hashmap are made within the [ServerBridgeHandler]
    ///
    /// [*] By checking [SERVER_UP] before each subroutine call, we can ensure that the Server exists
    /// while making a function call
    ///
    /// Additional notes: It is expected that calls to this are made only after the [Server] is running
    pub unsafe fn new(ptr: &Pin<Box<ServerBridgeHandler>>) -> Self {
        Self { ptr: &*ptr as *const ServerBridgeHandler }
    }

    /// Connects to a server that may be either in a HyperLAN network or a HyperWAN network.
    /// `server_name`: This can be the superficial name, ip address, or nid. The type is autodetected
    ///
    /// You may only call this if you know you are already registered to the server to which you wish to connect
    pub async fn connect_to_server<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(&self, server_name: &T, username: &R, password: &V) -> Result<(), ConnectError> {
        let cid = self.determine_cid(server_name)?;
    }

    /// Returns a reference to a [NetworkMap]
    pub fn get_network_map(&self) -> Result<&NetworkMap, ConnectError> {
        Ok(&self.deref_ptr()?.network_map)
    }

    fn determine_cid<T: AsRef<str>>(&self, server_name: &T) -> Result<u64, ConnectError> {
        let ptr = self.deref_ptr()?;
        let name = server_name.as_ref();
        let network_map = self.get_network_map()?;

        if let Ok(addr) = IpAddr::from_str(name) {
            network_map.read().get
        }




    }

    fn deref_ptr(&self) -> Result<&ServerBridgeHandler, ConnectError> {
        if !*SERVER_UP.read() {
            return Err(ConnectError::Generic("Server down".to_string()))
        }

        unsafe { Ok(&*self.ptr) }
    }
}