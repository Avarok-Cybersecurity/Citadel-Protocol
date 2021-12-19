use hyxe_user::prelude::NetworkAccount;
use crate::connection::connection::ConnectionHandle;
use hyxe_service::prelude::Service;
use hyxe_user::client_account::ClientNetworkAccount;
use std::any::Any;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use crate::connection::stream_wrappers::old::RawInboundItem;
use parking_lot::RwLock;
use std::sync::Arc;
use std::marker::PhantomData;
use crate::connection::bridge_handler::{BridgeHandler, BridgeState};
use hyxe_crypt::prelude::SecurityLevel;
use tokio::sync::mpsc::UnboundedSender;
use std::ops::{Deref, DerefMut};
use crate::connection::server::Server;
use std::mem::MaybeUninit;
use hyxe_netdata::packet::StageDriverPacket;
use vec_map::VecMap;
use std::collections::HashMap;
use std::pin::Pin;
use crate::packet::inbound::stage_driver::StageDriverHandle;
use crate::packet::definitions::{PREFER_IPV6, LOCAL_BIND_ADDR, PORT_START, PORT_END, DEFAULT_NETWORK_STACK_PROTOCOL, DEFAULT_ENCODING_SCHEME, DEFAULT_IP_VERSION, DEFAULT_AUXILIARY_PORTS};
use hyxe_netdata::connection::IpVersion;
use std::str::FromStr;
use crate::connection::server_bridge_handler::ServerBridgeHandler;

/// This is the passable handle for the [SessionInner] type. One exists on the [SessionManager] level, as well as the [ServerBridgeHandler] level
pub struct Session<'cxn, 'driver: 'cxn, 'server: 'driver> {
    inner: Arc<RwLock<SessionInner<'cxn, 'driver, 'server>>>
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> Session<'cxn, 'driver, 'server> {
    /// Creates a new session for a client-based connection. Dedicated server nodes have zero of these type, whereas multimodal nodes can have multiple clients appended to the server connection.
    ///
    /// The caller should be the higher-level [SessionManager], because it has the capacity to load the network accounts needed. Further:
    /// `peer_cnac`: This should have the NAC loaded with the proper non-local (i.e., global) IP address information
    pub fn new(bridge_handler: BridgeHandler<'cxn, 'driver>, stage_driver_handle: StageDriverHandle) -> Option<Self> {
        debug_assert!(bridge_handler.connection_client.is_some());
        let peer_cnac = bridge_handler.connection_client.unwrap();
        //local_bind_addr: &'cxn str, ip_version: IpVersion, peer_addr: &'cxn str, port_range: Range<u16>, protocol: ProtocolConfig, encoding_scheme: EncodingConfig, local_nac: NetworkAccount, cnac: ClientNetworkAccount
        let peer_addr = peer_cnac.get_node_data()?.get_addr(PREFER_IPV6)?;
        let nac = peer_cnac.get_nac()?;
        let ip_version = if peer_addr.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };

        let bind_addr = IpAddr::from_str(LOCAL_BIND_ADDR).unwrap();
        let sess = SessionInner::new(peer_cnac.clone(), nac.clone(), bridge_handler, stage_driver_handle);
        Some(Self { inner: Arc::new(RwLock::new(sess)) })
    }
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> Clone for Session<'cxn, 'driver, 'server> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

/// A session is granted upon a connection request. It is stored within the [Server] type, and is interfaced-upon
/// by the Server's [BridgeHandler] for purposes of network communication.
pub struct SessionInner<'cxn, 'driver: 'cxn, 'server: 'driver> {
    /// The `client` should be equal on both server and client endpoints
    pub client: ClientNetworkAccount,
    /// While the `cid` must remain equal, the `remote_nac` is always going to be the opposite node. If this session belongs to a server,
    /// then this field is the local NAC
    pub adjacent_peer: NetworkAccount,
    /// This is the I/O interface for network coms
    bridge_handler: BridgeHandler<'cxn, 'driver>,
    /// An atomically-backed handle to the stage driver
    stage_driver_handle: StageDriverHandle<'cxn, 'driver, 'server>,
    /// Basic services receive packets. This is for the high-level API especially
    basic_services: HashMap<u64, Service<'cxn, StageDriverPacket>>,
    /// Special services are for non-basic service types (e.g., SAAQ service) or services that work in the outbound
    /// direction as opposed to the inbound direction
    special_services: Vec<Service<'cxn, Box<dyn Any>>>
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> SessionInner<'cxn, 'driver, 'server> {
    /// Creates a new session
    /// `connection_handle`: in the case of a server type of session, this 
    pub fn new(client: ClientNetworkAccount, adjacent_peer: NetworkAccount, bridge_handler: BridgeHandler<'cxn, 'driver>, stage_driver_handle: StageDriverHandle) -> Self {
        let special_services = Self::create_special_services();
        //let bridge_handler = BridgeHandler { handle: connection_handle, stage_driver_handle, connection_client: client, adjacent_node: adjacent_peer.clone(), state: BridgeState::CLOSED };
        Self { client, adjacent_peer, bridge_handler, stage_driver_handle, basic_services: VecMap::new(), special_services }
    }

    fn create_special_services() -> Vec<Service<'cxn, Box<dyn Any>>> {
        Vec::new()
    }

    /// Returns both the ipv4 and ipv6 addresses
    pub fn get_peer_addr(&self) -> (Option<&IpAddr>, Option<&IpAddr>) {
        let read = self.remote_peer.read();
        (read.global_ipv4.as_ref(), read.global_ipv6.as_ref())
    }

    /// Returns the CID.
    pub fn get_cid(&self) -> Option<u64> {
        match self.client.as_ref() {
            Some(client) => {
                Some(client.read().cid)
            },

            _ => None
        }
    }

    /// Returns whether or not this [Session] is a server type.

}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> Deref for Session<'cxn, 'driver, 'server> {
    type Target = SessionInner<'cxn, 'driver, 'server>;

    fn deref(&self) -> &Self::Target {
        &self.inner.read()
    }
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> DerefMut for Session<'cxn, 'driver, 'server> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.write()
    }
}