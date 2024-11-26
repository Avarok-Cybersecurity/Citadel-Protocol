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

use async_trait::async_trait;
use auto_impl::auto_impl;
#[cfg(not(target_family = "wasm"))]
use reqwest::Client;
use std::fmt::Formatter;
use std::net::IpAddr;
#[cfg(not(target_family = "wasm"))]
use std::net::SocketAddr;
use std::str::FromStr;

// use http since it's 2-3x faster
const URL_V6: &str = "http://api64.ipify.org";
//const URL_V4: &str = "http://api.ipify.org";

const URL_V6_1: &str = "http://ident.me";
//const URL_V4_1: &str = "http://v4.ident.me";

const URL_V6_2: &str = "http://v4v6.ipv6-test.com/api/myip.php";
//const URL_V4_2: &str = "http://v4.ipv6-test.com/api/myip.php";

#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
/// All the ip addr info for this node
pub struct IpAddressInfo {
    /// internal addr
    pub internal_ip: IpAddr,
    /// external v6 addr
    pub external_ipv6: Option<IpAddr>,
}

impl IpAddressInfo {
    /// Returns localhost addr
    pub fn localhost() -> Self {
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        Self {
            internal_ip: localhost,
            external_ipv6: None,
        }
    }
}

/// Gets IP info concurrently using default multiple internal sources
pub async fn get_all_multi_concurrent<T: AsyncHttpGetClient>(
    client: Option<T>,
) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_multi_concurrent_from(client, &[URL_V6, URL_V6_1, URL_V6_2]).await
}

/// Uses multiple url addrs to obtain the information
pub async fn get_all_multi_concurrent_from<T: AsyncHttpGetClient>(
    client: Option<T>,
    v6_addrs: &[&str],
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = client.map(|client| Box::new(client) as Box<dyn AsyncHttpGetClient>);
    let client = &client.unwrap_or_else(|| Box::new(get_default_client()));
    let internal_ipv4_future = get_internal_ip(false);
    let external_ipv6_future = futures::future::select_ok(
        v6_addrs
            .iter()
            .map(|addr| Box::pin(get_ip_from(Some(client), addr)))
            .collect::<Vec<_>>(),
    );

    let (res0, res2) = citadel_io::tokio::join!(internal_ipv4_future, external_ipv6_future);
    let internal_ipv4 =
        res0.ok_or_else(|| IpRetrieveError::Error("Could not obtain internal IPv4".to_string()))?;
    let external_ipv6 = res2.ok().map(|r| r.0);

    Ok(IpAddressInfo {
        internal_ip: internal_ipv4,
        external_ipv6,
    })
}

/// Returns all possible IPs for this node
pub async fn get_all<T: AsyncHttpGetClient>(
    client: Option<T>,
) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_from(client, URL_V6).await
}

/// Gets IP info concurrently using custom multiple internal sources
pub async fn get_all_from<T: AsyncHttpGetClient>(
    client: Option<T>,
    v6_addr: &str,
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = client
        .map(|client| Box::new(client) as Box<dyn AsyncHttpGetClient>)
        .unwrap_or_else(|| Box::new(get_default_client()));
    let internal_ipv4_future = get_internal_ip(false);
    let external_ipv6_future = get_ip_from(Some(client), v6_addr);
    let (res0, res2) = citadel_io::tokio::join!(internal_ipv4_future, external_ipv6_future);
    let internal_ipv4 =
        res0.ok_or_else(|| IpRetrieveError::Error("Could not obtain internal IPv4".to_string()))?;
    let external_ipv6 = res2.ok();

    Ok(IpAddressInfo {
        internal_ip: internal_ipv4,
        external_ipv6,
    })
}

/// Asynchronously gets the IP address of this node. If `prefer_ipv6` is true, then the client will
/// attempt to get the IP address; however, if the client is using an IPv4 address, that will be returned
/// instead.
///
/// If a reqwest client is supplied, this function will use that client to get the information. None by default.
pub async fn get_ip_from<T: AsyncHttpGetClient>(
    client: Option<T>,
    addr: &str,
) -> Result<IpAddr, IpRetrieveError> {
    let client = client
        .map(|client| Box::new(client) as Box<dyn AsyncHttpGetClient>)
        .unwrap_or_else(|| Box::new(get_default_client()));

    let text = client.get(addr).await?;
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

#[cfg(not(target_family = "wasm"))]
/// Returns the internal ipv4 address of this node
pub async fn get_internal_ipv4() -> Option<IpAddr> {
    let socket = citadel_io::tokio::net::UdpSocket::bind(addr("0.0.0.0:0")?)
        .await
        .ok()?;
    socket.connect(addr("8.8.8.8:80")?).await.ok()?;
    socket.local_addr().ok().map(|sck| sck.ip())
}

#[cfg(target_family = "wasm")]
async fn get_internal_ipv4() -> Option<IpAddr> {
    None
}

#[cfg(not(target_family = "wasm"))]
async fn get_internal_ipv6() -> Option<IpAddr> {
    let socket = citadel_io::tokio::net::UdpSocket::bind(addr("[::]:0")?)
        .await
        .ok()?;
    socket
        .connect(addr("[2001:4860:4860::8888]:80")?)
        .await
        .ok()?;
    socket.local_addr().ok().map(|sck| sck.ip())
}

#[cfg(target_family = "wasm")]
async fn get_internal_ipv6() -> Option<IpAddr> {
    None
}

#[cfg(not(target_family = "wasm"))]
fn addr(addr: &str) -> Option<SocketAddr> {
    SocketAddr::from_str(addr).ok()
}

#[cfg(not(target_family = "wasm"))]
fn get_default_client() -> Client {
    Client::builder().tcp_nodelay(true).build().unwrap()
}
#[cfg(target_family = "wasm")]
fn get_default_client() -> UreqClient {
    UreqClient
}

/// The default error type for this crate
#[derive(Debug)]
pub enum IpRetrieveError {
    /// Generic wrapper
    Error(String),
}

impl std::fmt::Display for IpRetrieveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpRetrieveError::Error(err) => write!(f, "{}", err),
        }
    }
}

#[async_trait]
#[auto_impl(Box, &)]
/// An async http client
pub trait AsyncHttpGetClient: Send + Sync {
    /// Async Get
    async fn get(&self, addr: &str) -> Result<String, IpRetrieveError>;
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl AsyncHttpGetClient for Client {
    async fn get(&self, addr: &str) -> Result<String, IpRetrieveError> {
        let resp = self
            .get(addr)
            .send()
            .await
            .map_err(|err| IpRetrieveError::Error(err.to_string()))?;

        resp.text()
            .await
            .map_err(|err| IpRetrieveError::Error(err.to_string()))
    }
}

#[async_trait]
impl AsyncHttpGetClient for () {
    async fn get(&self, _addr: &str) -> Result<String, IpRetrieveError> {
        unimplemented!("Stub implementation for AsyncHttpGetClient")
    }
}

#[cfg(target_family = "wasm")]
/// Ureq client
pub struct UreqClient;

#[cfg(target_family = "wasm")]
#[async_trait]
impl AsyncHttpGetClient for UreqClient {
    async fn get(&self, addr: &str) -> Result<String, IpRetrieveError> {
        let addr = addr.to_string();
        citadel_io::tokio::task::spawn_blocking(move || {
            ureq::get(&addr)
                .call()
                .map_err(|err| IpRetrieveError::Error(err.to_string()))?
                .into_string()
                .map_err(|err| IpRetrieveError::Error(err.to_string()))
        })
        .await
        .map_err(|err| IpRetrieveError::Error(err.to_string()))?
    }
}
