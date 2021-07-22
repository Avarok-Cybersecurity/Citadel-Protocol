//! An asynchronous client used to obtain one's global Ipv6 or Ipv4 address
#![deny(
missing_docs,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_features,
unused_results,
warnings
)]

use std::net::{IpAddr, SocketAddr};
use reqwest::Client;
use std::str::FromStr;

const URL_V6: &str = "https://api64.ipify.org";
const URL_V4: &str = "https://api.ipify.org";

/// Asynchronously gets the IP address of this node. If `prefer_ipv6` is true, then the client will
/// attempt to get the IP address; however, if the client is using an IPv4 address, that will be returned
/// instead.
///
/// If a reqwest client is supplied, this function will use that client to get the information. None by default.
pub async fn get_ip(client: Option<Client>, ipv6: bool) -> Result<IpAddr, IpRetrieveError> {
    let client = client.unwrap_or_else(|| { Client::new() });

    let addr = if ipv6 { URL_V6 } else { URL_V4 };
    let resp = client.get(addr).send().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    let text = resp.text().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    IpAddr::from_str(text.as_str()).map_err(|err| IpRetrieveError::Error(err.to_string()))
}

/// Gets the internal IP address using DNS
pub async fn get_internal_ip(ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        get_internal_ipv6().await
    } else {
        get_internal_ipv4().await
    }
}

async fn get_internal_ipv4() -> Option<IpAddr> {
    let socket = tokio::net::UdpSocket::bind(addr("0.0.0.0:0")?).await.ok()?;
    socket.connect(addr("8.8.8.8:80")?).await.ok()?;
    socket.local_addr().ok().map(|sck| sck.ip())
}

async fn get_internal_ipv6() -> Option<IpAddr> {
    let socket = tokio::net::UdpSocket::bind(addr("[::]:0")?).await.ok()?;
    socket.connect(addr("[2001:4860:4860::8888]:80")?).await.ok()?;
    socket.local_addr().ok().map(|sck| sck.ip())
}

fn addr(addr: &str) -> Option<SocketAddr> {
    SocketAddr::from_str(addr).ok()
}

/// The default error type for this crate
#[derive(Debug)]
pub enum IpRetrieveError {
    /// Generic wrapper
    Error(String)
}

impl ToString for IpRetrieveError {
    fn to_string(&self) -> String {
        match self {
            IpRetrieveError::Error(err) => err.to_string()
        }
    }
}