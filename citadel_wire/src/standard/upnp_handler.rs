//! UPnP Port Mapping and Gateway Management
//!
//! This module provides Universal Plug and Play (UPnP) functionality for automatic
//! port forwarding and NAT traversal. It handles discovery of Internet Gateway
//! Devices and manages port mappings for both TCP and UDP protocols.
//!
//! # Features
//!
//! - Automatic gateway discovery and configuration
//! - Port mapping for TCP and UDP protocols
//! - External IP address discovery
//! - Configurable lease durations for port mappings
//! - Support for targeted and any-port forwarding
//! - Automatic local IP detection
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::upnp_handler::UPnPHandler;
//! use igd::PortMappingProtocol;
//! use std::time::Duration;
//!
//! async fn setup_port_forwarding() -> Result<(), citadel_wire::error::FirewallError> {
//!     // Create UPnP handler with 5 second timeout
//!     let upnp = UPnPHandler::new(Some(Duration::from_secs(5))).await?;
//!     
//!     // Forward external port 8080 to local port 3000
//!     upnp.open_firewall_port(
//!         PortMappingProtocol::TCP,
//!         Some(3600),  // 1 hour lease
//!         "my-service",
//!         None,
//!         8080,
//!         3000
//!     ).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Requires UPnP-enabled router/gateway
//! - Port mappings may expire if lease duration set
//! - External ports may be already in use
//! - Gateway discovery has configurable timeout
//! - Only supports IPv4 addresses currently
//!
//! # Related Components
//!
//! - [`crate::standard::nat_identification`] - NAT behavior analysis
//! - [`crate::udp_traversal`] - Alternative NAT traversal
//! - [`crate::standard::socket_helpers`] - Socket utilities
//! - [`crate::error::FirewallError`] - Error handling
//!

use crate::error::FirewallError;
use citadel_io::tokio::time::Duration;
use igd::aio::Gateway;
use igd::{PortMappingProtocol, SearchOptions};
use std::fmt::Formatter;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

pub struct UPnPHandler {
    local_ip_address: Ipv4Addr,
    gateway: Gateway,
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

        let local_ip_address = async_ip::get_internal_ip(false)
            .await
            .ok_or(FirewallError::LocalIPAddrFail)?;

        if local_ip_address.is_ipv6() {
            return Err(FirewallError::UPNP(
                "Detected LAN IPv6. Not yet implemented".to_string(),
            ));
        }

        let local_ip_address = Ipv4Addr::from_str(local_ip_address.to_string().as_str())
            .map_err(|_| FirewallError::LocalIPAddrFail)?;

        igd::aio::search_gateway(options)
            .await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
            .map(|gateway| Self {
                local_ip_address,
                gateway,
            })
    }

    pub async fn get_external_ip(&self) -> Result<Ipv4Addr, FirewallError> {
        self.gateway
            .get_external_ip()
            .await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    pub fn get_default_gateway(&self) -> &SocketAddrV4 {
        &self.gateway.addr
    }

    pub fn get_local_ip(&self) -> &Ipv4Addr {
        &self.local_ip_address
    }

    /// `remote_peer`: If None, then ALL traffic inbound to the external port is forwarded to the local port on 0.0.0.0
    /// `lease_duration`: in seconds. If none, infinite time (must manually remove)
    pub async fn open_firewall_port<T: AsRef<str>>(
        &self,
        protocol: PortMappingProtocol,
        lease_duration: Option<u32>,
        firewall_rule_name: T,
        _remote_peer: Option<IpAddr>,
        external_port: u16,
        local_port: u16,
    ) -> Result<(), FirewallError> {
        self.gateway
            .add_port(
                protocol,
                external_port,
                SocketAddrV4::new(self.local_ip_address, local_port),
                lease_duration.unwrap_or(0),
                firewall_rule_name.as_ref(),
            )
            .await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    /// `remote_peer`: If None, then ALL traffic inbound to the external port is forwarded to the local port on 0.0.0.0
    /// `lease_duration`: in seconds. If none, infinite time (must manually remove)
    pub async fn open_any_firewall_port<T: AsRef<str>>(
        &self,
        protocol: PortMappingProtocol,
        lease_duration: Option<u32>,
        firewall_rule_name: T,
        _remote_peer: Option<IpAddr>,
        local_port: u16,
    ) -> Result<u16, FirewallError> {
        self.gateway
            .add_any_port(
                protocol,
                SocketAddrV4::new(self.local_ip_address, local_port),
                lease_duration.unwrap_or(0),
                firewall_rule_name.as_ref(),
            )
            .await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }

    pub async fn close_firewall_port(
        &self,
        port_mapping_protocol: PortMappingProtocol,
        _remote_peer: Option<IpAddr>,
        external_port: u16,
    ) -> Result<(), FirewallError> {
        self.gateway
            .remove_port(port_mapping_protocol, external_port)
            .await
            .map_err(|err| FirewallError::UPNP(err.to_string()))
    }
}

impl std::fmt::Display for UPnPHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Default Gateway: {}\nLocal IP Address: {}\n",
            self.get_default_gateway(),
            self.get_local_ip()
        )
    }
}
