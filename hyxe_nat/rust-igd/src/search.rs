use std::collections::HashMap;
use std::net::{SocketAddrV4, UdpSocket};
use std::str;

use crate::common::{messages, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::gateway::Gateway;

/// Search gateway, using the given `SearchOptions`.
///
/// The default `SearchOptions` should suffice in most cases.
/// It can be created with `Default::default()` or `SearchOptions::default()`.
///
/// # Example
/// ```no_run
/// use igd::{search_gateway, SearchOptions, Result};
///
/// fn main() -> Result {
///     let gateway = search_gateway(Default::default())?;
///     let ip = gateway.get_external_ip()?;
///     println!("External IP address: {}", ip);
///     Ok(())
/// }
/// ```
pub fn search_gateway(options: SearchOptions) -> Result<Gateway, SearchError> {
    let socket = UdpSocket::bind(options.bind_addr)?;
    socket.set_read_timeout(options.timeout)?;

    socket.send_to(messages::SEARCH_REQUEST.as_bytes(), options.broadcast_address)?;

    loop {
        let mut buf = [0u8; 1500];
        let (read, _) = socket.recv_from(&mut buf)?;
        let text = str::from_utf8(&buf[..read])?;

        let (addr, root_url) = parsing::parse_search_result(text)?;

        let (control_schema_url, control_url) = match get_control_urls(&addr, &root_url) {
            Ok(o) => o,
            Err(..) => continue,
        };

        let control_schema = match get_schemas(&addr, &control_schema_url) {
            Ok(o) => o,
            Err(..) => continue,
        };

        return Ok(Gateway {
            addr,
            root_url,
            control_url,
            control_schema_url,
            control_schema,
        });
    }
}

fn get_control_urls(addr: &SocketAddrV4, root_url: &String) -> Result<(String, String), SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), root_url);
    let response = attohttpc::get(&url).send()?;
    parsing::parse_control_urls(&response.bytes()?[..])
}

fn get_schemas(addr: &SocketAddrV4, control_schema_url: &String) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let url = format!("http://{}:{}{}", addr.ip(), addr.port(), control_schema_url);
    let response = attohttpc::get(&url).send()?;
    parsing::parse_schemas(&response.bytes()?[..])
}
