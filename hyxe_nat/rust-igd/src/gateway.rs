use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4, IpAddr};

use attohttpc;

use crate::common::{self, messages, parsing, parsing::RequestResult};
use crate::errors::{self, AddAnyPortError, AddPortError, GetExternalIpError, RemovePortError, RequestError};
use crate::PortMappingProtocol;

/// This structure represents a gateway found by the search functions.
#[derive(Clone, Debug)]
pub struct Gateway {
    /// Socket address of the gateway
    pub addr: SocketAddrV4,
    /// Root url of the device
    pub root_url: String,
    /// Control url of the device
    pub control_url: String,
    /// Url to get schema data from
    pub control_schema_url: String,
    /// Control schema for all actions
    pub control_schema: HashMap<String, Vec<String>>,
}

impl Gateway {
    fn perform_request(&self, header: &str, body: &str, ok: &str) -> RequestResult {
        let url = format!("http://{}{}", self.addr, self.control_url);

        let response = attohttpc::post(&url)
            .header("SOAPAction", header)
            .header("Content-Type", "text/xml")
            .text(body)
            .send()?;

        parsing::parse_response(response.text()?, ok)
    }

    /// Get the external IP address of the gateway.
    pub fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
        parsing::parse_get_external_ip_response(self.perform_request(
            messages::GET_EXTERNAL_IP_HEADER,
            &messages::format_get_external_ip_message(),
            "GetExternalIPAddressResponse",
        ))
    }

    /// Get an external socket address with our external ip and any port. This is a convenience
    /// function that calls `get_external_ip` followed by `add_any_port`
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external address that was mapped on success. Otherwise an error.
    pub fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<SocketAddrV4, AddAnyPortError> {
        let ip = self.get_external_ip()?;
        let port = self.add_any_port(protocol, remote_peer, local_addr, lease_duration, description)?;
        Ok(SocketAddrV4::new(ip, port))
    }

    /// Add a port mapping.with any external port.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external port that was mapped on success. Otherwise an error.
    pub fn add_any_port(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        // This function first attempts to call AddAnyPortMapping on the IGD with a random port
        // number. If that fails due to the method being unknown it attempts to call AddPortMapping
        // instead with a random port number. If that fails due to ConflictInMappingEntry it retrys
        // with another port up to a maximum of 20 times. If it fails due to SamePortValuesRequired
        // it retrys once with the same port values.

        if local_addr.port() == 0 {
            return Err(AddAnyPortError::InternalPortZeroInvalid);
        }

        let schema = self.control_schema.get("AddAnyPortMapping");
        if let Some(schema) = schema {
            let external_port = common::random_port();

            parsing::parse_add_any_port_mapping_response(self.perform_request(
                messages::ADD_ANY_PORT_MAPPING_HEADER,
                &messages::format_add_any_port_mapping_message(
                    schema,
                    remote_peer,
                    protocol,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                ),
                "AddAnyPortMappingResponse",
            ))
        } else {
            self.retry_add_random_port_mapping(protocol, remote_peer, local_addr, lease_duration, description)
        }
    }

    fn retry_add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        const ATTEMPTS: usize = 20;

        for _ in 0..ATTEMPTS {
            if let Ok(port) = self.add_random_port_mapping(protocol, remote_peer, local_addr, lease_duration, &description) {
                return Ok(port);
            }
        }

        Err(AddAnyPortError::NoPortsAvailable)
    }

    fn add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        let external_port = common::random_port();

        if let Err(err) = self.add_port_mapping(protocol, remote_peer, external_port, local_addr, lease_duration, &description) {
            match parsing::convert_add_random_port_mapping_error(err) {
                Some(err) => return Err(err),
                None => return self.add_same_port_mapping(protocol, remote_peer, local_addr, lease_duration, description),
            }
        }

        Ok(external_port)
    }

    fn add_same_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        match self.add_port_mapping(protocol, remote_peer, local_addr.port(), local_addr, lease_duration, description) {
            Ok(_) => Ok(local_addr.port()),
            Err(e) => Err(parsing::convert_add_same_port_mapping_error(e)),
        }
    }

    fn add_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), RequestError> {
        self.perform_request(
            messages::ADD_PORT_MAPPING_HEADER,
            &messages::format_add_port_mapping_message(
                self.control_schema
                    .get("AddPortMapping")
                    .ok_or(RequestError::UnsupportedAction("AddPortMapping".to_string()))?,
                protocol,
                remote_peer,
                external_port,
                local_addr,
                lease_duration,
                description,
            ),
            "AddPortMappingResponse",
        )?;

        Ok(())
    }

    /// Add a port mapping.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    pub fn add_port(
        &self,
        protocol: PortMappingProtocol,
        remote_peer: Option<IpAddr>,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError> {
        if external_port == 0 {
            return Err(AddPortError::ExternalPortZeroInvalid);
        }
        if local_addr.port() == 0 {
            return Err(AddPortError::InternalPortZeroInvalid);
        }

        self.add_port_mapping(protocol, remote_peer, external_port, local_addr, lease_duration, description)
            .map_err(|err| parsing::convert_add_port_error(err))
    }

    /// Remove a port mapping.
    pub fn remove_port(&self, protocol: PortMappingProtocol, remote_peer: Option<IpAddr>, external_port: u16) -> Result<(), RemovePortError> {
        parsing::parse_delete_port_mapping_response(
            self.perform_request(
                messages::DELETE_PORT_MAPPING_HEADER,
                &messages::format_delete_port_message(
                    self.control_schema
                        .get("DeletePortMapping")
                        .ok_or(RemovePortError::RequestError(RequestError::UnsupportedAction(
                            "DeletePortMapping".to_string(),
                        )))?,
                    protocol,
                    remote_peer,
                    external_port,
                ),
                "DeletePortMappingResponse",
            ),
        )
    }

    /// Get one port mapping entry
    ///
    /// Gets one port mapping entry by its index.
    /// Not all existing port mappings might be visible to this client.
    /// If the index is out of bound, GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid will be returned
    pub fn get_generic_port_mapping_entry(
        &self,
        index: u32,
    ) -> Result<parsing::PortMappingEntry, errors::GetGenericPortMappingEntryError> {
        parsing::parse_get_generic_port_mapping_entry(self.perform_request(
            messages::GET_GENERIC_PORT_MAPPING_ENTRY,
            &messages::formate_get_generic_port_mapping_entry_message(index),
            "GetGenericPortMappingEntryResponse",
        ))
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "http://{}{}", self.addr, self.control_url)
    }
}
