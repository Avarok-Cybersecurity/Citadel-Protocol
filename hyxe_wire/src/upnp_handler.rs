use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use igd::aio::Gateway;
use igd::{SearchOptions, PortMappingProtocol};
use tokio::time::Duration;
use crate::ip_addr::get_local_ip;
use crate::error::FirewallError;
use std::str::FromStr;
use std::fmt::Formatter;

pub struct UPnPHandler {
    local_ip_address: Ipv4Addr,
    gateway: Gateway
}

impl UPnPHandler {
    /// Creates a new device capable of opening holes in the NAT
    ///
    /// `timeout`: If None, uses the default (10 seconds)
    pub async fn new(timeout: Option<Duration>) -> Result<Self, FirewallError> {
        let options = SearchOptions {
            timeout,
            ..Default::default()
        };

        let local_ip_address = get_local_ip().await.ok_or_else(||FirewallError::LocalIPAddrFail)?;

        if local_ip_address.is_ipv6() {
            return Err(FirewallError::UPNP("Detected LAN IPv6. Not yet implemented".to_string()))
        }

        let local_ip_address = Ipv4Addr::from_str(local_ip_address.to_string().as_str()).or_else(|_| Err(FirewallError::LocalIPAddrFail))?;

        igd::aio::search_gateway(options).await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
            .and_then(|gateway| {
                let this = Self {local_ip_address, gateway};
                Ok(this)
            })
    }

    pub async fn get_external_ip(&self) -> Result<Ipv4Addr, FirewallError> {
        self.gateway.get_external_ip().await.map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    pub fn get_default_gateway(&self) -> &SocketAddrV4 {
        &self.gateway.addr
    }

    pub fn get_local_ip(&self) -> &Ipv4Addr {
        &self.local_ip_address
    }

    /// `remote_peer`: If None, then ALL traffic inbound to the external port is forwarded to the local port on 0.0.0.0
    /// `lease_duration`: in seconds. If none, infinite time (must manually remove)
    pub async fn open_firewall_port<T: AsRef<str>>(&self, protocol: PortMappingProtocol, lease_duration: Option<u32>, firewall_rule_name: T, _remote_peer: Option<IpAddr>, external_port: u16, local_port: u16) -> Result<(), FirewallError>{
        self.gateway.add_port(protocol, external_port, SocketAddrV4::new(self.local_ip_address, local_port), lease_duration.unwrap_or(0), firewall_rule_name.as_ref()).await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    /// `remote_peer`: If None, then ALL traffic inbound to the external port is forwarded to the local port on 0.0.0.0
    /// `lease_duration`: in seconds. If none, infinite time (must manually remove)
    pub async fn open_any_firewall_port<T: AsRef<str>>(&self, protocol: PortMappingProtocol, lease_duration: Option<u32>, firewall_rule_name: T, _remote_peer: Option<IpAddr>, local_port: u16) -> Result<u16, FirewallError>{
        self.gateway.add_any_port(protocol, SocketAddrV4::new(self.local_ip_address, local_port), lease_duration.unwrap_or(0), firewall_rule_name.as_ref()).await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    pub async fn close_firewall_port(&self, port_mapping_protocol: PortMappingProtocol, _remote_peer: Option<IpAddr>, external_port: u16) -> Result<(), FirewallError> {
        self.gateway.remove_port(port_mapping_protocol, external_port).await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }
}

impl std::fmt::Display for UPnPHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Default Gateway: {}\nLocal IP Address: {}\n", self.get_default_gateway(), self.get_local_ip())
    }
}