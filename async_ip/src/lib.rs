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
use serde::{Serialize, Deserialize};

// use http since it's 2-3x faster
const URL_V6: &str = "http://api64.ipify.org";
const URL_V4: &str = "http://api.ipify.org";

const URL_V6_1: &str = "http://ident.me";
const URL_V4_1: &str = "http://v4.ident.me";

const URL_V6_2: &str = "http://v4v6.ipv6-test.com/api/myip.php";
const URL_V4_2: &str = "http://v4.ipv6-test.com/api/myip.php";


#[derive(Serialize, Deserialize, Debug, Clone)]
/// All the ip addr info for this node
pub struct IpAddressInfo {
    /// internal addr
    pub internal_ipv4: IpAddr,
    /// external v4 addr
    pub external_ipv4: IpAddr,
    /// external v6 addr
    pub external_ipv6: Option<IpAddr>
}

impl IpAddressInfo {
    /// Returns localhost addr
    pub fn localhost() -> Self {
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        Self {
            internal_ipv4: localhost,
            external_ipv4: localhost,
            external_ipv6: None
        }
    }
}

/// Gets IP info concurrently using default multiple internal sources
pub async fn get_all_multi_concurrent(client: Option<Client>) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_multi_concurrent_from(client, &[URL_V4, URL_V4_1, URL_V4_2], &[URL_V6, URL_V6_1, URL_V6_2]).await
}

/// Uses multiple url addrs to obtain the information
pub async fn get_all_multi_concurrent_from(client: Option<Client>, v4_addrs: &[&str], v6_addrs: &[&str]) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = &client.unwrap_or_else(get_default_client);
    let internal_ipv4_future = get_internal_ip(false);
    let external_ipv4_future = futures::future::select_ok(v4_addrs.iter().map(|addr| Box::pin(get_ip_from(Some(client.clone()), false, addr, ""))).collect::<Vec<_>>());
    let external_ipv6_future = futures::future::select_ok(v6_addrs.iter().map(|addr| Box::pin(get_ip_from(Some(client.clone()), true, "", addr))).collect::<Vec<_>>());

    let (res0, res1, res2) = tokio::join!(internal_ipv4_future, external_ipv4_future, external_ipv6_future);
    let internal_ipv4 = res0.ok_or_else(||IpRetrieveError::Error("Could not obtain internal IPv4".to_string()))?;
    let (external_ipv4, _) = res1?;
    let external_ipv6 = res2.ok().map(|r| r.0);

    Ok(IpAddressInfo { internal_ipv4, external_ipv4, external_ipv6 })
}

/// Returns all possible IPs for this node
pub async fn get_all(client: Option<Client>) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_from(client, URL_V4, URL_V6).await
}

/// Gets IP info concurrenlty using custom multiple internal sources
pub async fn get_all_from(client: Option<Client>, v4_addr: &str, v6_addr: &str) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = client.unwrap_or_else(get_default_client);
    let internal_ipv4_future = get_internal_ip(false);
    let external_ipv4_future = get_ip_from(Some(client.clone()), false, v4_addr, v6_addr);
    let external_ipv6_future = get_ip_from(Some(client), true, v4_addr, v6_addr);
    let (res0, res1, res2) = tokio::join!(internal_ipv4_future, external_ipv4_future, external_ipv6_future);
    let internal_ipv4 = res0.ok_or_else(||IpRetrieveError::Error("Could not obtain internal IPv4".to_string()))?;
    let external_ipv4 = res1?;
    let external_ipv6 = res2.ok();

    Ok(IpAddressInfo { internal_ipv4, external_ipv4, external_ipv6 })
}

/// Asynchronously gets the IP address of this node. If `prefer_ipv6` is true, then the client will
/// attempt to get the IP address; however, if the client is using an IPv4 address, that will be returned
/// instead.
///
/// If a reqwest client is supplied, this function will use that client to get the information. None by default.
pub async fn get_ip_from(client: Option<Client>, ipv6: bool, v4_addr: &str, v6_addr: &str) -> Result<IpAddr, IpRetrieveError> {
    let client = client.unwrap_or_else(get_default_client);

    let addr = if ipv6 { v6_addr } else { v4_addr };
    let resp = client.get(addr).send().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    let text = resp.text().await.map_err(|err| IpRetrieveError::Error(err.to_string()))?;
    IpAddr::from_str(text.as_str()).map_err(|err| IpRetrieveError::Error(err.to_string()))
        .and_then(|res| {
            if ipv6 && res.is_ipv4() {
                Err(IpRetrieveError::Error("This node does not have an ipv6 addr".to_string()))
            } else {
                Ok(res)
            }
        })
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

fn get_default_client() -> Client {
    Client::builder().tcp_nodelay(true).build().unwrap()
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