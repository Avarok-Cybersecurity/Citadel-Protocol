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

use std::net::IpAddr;
use reqwest::Client;
use std::str::FromStr;

const IPV4_URL: &str = "https://api.ipify.org";
const IPV6_URL: &str = "https://api6.ipify.org";

/// Asynchronously gets the IP address of this node. If `prefer_ipv6` is true, then the client will
/// attempt to get the IP address; however, if the client is using an IPv4 address, that will be returned
/// instead.
///
/// If a reqwest client is supplied, this function will use that client to get the information. None by default.
pub async fn get_ip(prefer_ipv6: bool, client: Option<Client>) -> Result<IpAddr, IpRetrieveError> {
    let client = client.unwrap_or_else(|| { Client::new() });
    let url = if prefer_ipv6 {
        IPV6_URL
    } else {
        IPV4_URL
    };

    let resp = client.get(url).send().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    let text = resp.text().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    IpAddr::from_str(text.as_str()).map_err(|err| IpRetrieveError::Error(err.to_string()))
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