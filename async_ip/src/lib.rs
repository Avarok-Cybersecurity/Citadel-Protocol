//! # Async IP Resolution
//!
//! A lightweight, asynchronous client for obtaining global IPv4 and IPv6 addresses.
//! This crate provides reliable IP address resolution using multiple fallback services
//! and concurrent requests for improved reliability.
//!
//! ## Features
//!
//! - Async IP address resolution
//! - Support for both IPv4 and IPv6
//! - Multiple fallback services
//! - Concurrent resolution for improved reliability
//! - Internal IP address detection
//! - WebAssembly support
//! - Custom HTTP client support
//!
//! ## Usage
//!
//! ```rust,no_run
//! use async_ip::get_all;
//! use citadel_io::tokio;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), async_ip::IpRetrieveError> {
//!     // Get both internal and external IP addresses
//!     use reqwest::Client;
//! let ip_info = get_all::<Client>(None).await?;
//!     println!("External IPv6: {:?}", ip_info.external_ipv6);
//!     println!("Internal IPv4: {:?}", ip_info.internal_ip);
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Usage
//!
//! ```rust,no_run
//! use async_ip::{get_all_multi_concurrent, get_default_client};
//! use citadel_io::tokio;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), async_ip::IpRetrieveError> {
//!     // Use multiple services concurrently with a custom client
//!     let client = get_default_client();
//!     let ip_info = get_all_multi_concurrent(Some(client)).await?;
//!     println!("External IPs: {:?}", ip_info);
//!     Ok(())
//! }
//! ```
//!
//! ## WebAssembly Support
//!
//! When compiled with the `wasm` target, this crate uses a lightweight HTTP client
//! suitable for WebAssembly environments. The functionality remains the same, but
//! some features (like internal IP detection) may be limited.
//!
//! ## Error Handling
//!
//! The crate uses a custom `IpRetrieveError` type that wraps various error
//! conditions that may occur during IP resolution, including network errors
//! and parsing failures.

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

use std::fmt::Formatter;
use std::net::IpAddr;
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
pub async fn get_all_multi_concurrent(
    client: Option<reqwest::Client>,
) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_multi_concurrent_from(client, &[URL_V6, URL_V6_1, URL_V6_2]).await
}

/// Uses multiple url addrs to obtain the information
pub async fn get_all_multi_concurrent_from(
    client: Option<reqwest::Client>,
    v6_addrs: &[&str],
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = &client.unwrap_or_else(get_default_client);
    let internal_ipv4_future = get_internal_ip(false);
    let external_ipv6_future = futures::future::select_ok(
        v6_addrs
            .iter()
            .map(|addr| Box::pin(get_ip_from(Some(client.clone()), addr)))
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
pub async fn get_all(client: Option<reqwest::Client>) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_from(client, URL_V6).await
}

/// Gets IP info concurrently using custom multiple internal sources
pub async fn get_all_from(
    client: Option<reqwest::Client>,
    v6_addr: &str,
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = client.unwrap_or_else(get_default_client);
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
pub async fn get_ip_from(
    client: Option<reqwest::Client>,
    addr: &str,
) -> Result<IpAddr, IpRetrieveError> {
    let client = client.unwrap_or_else(|| get_default_client());

    let resp = client
        .get(addr)
        .send()
        .await
        .map_err(|err| IpRetrieveError::Error(err.to_string()))?;

    let text = resp
        .text()
        .await
        .map_err(|err| IpRetrieveError::Error(err.to_string()))?;

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

/// Returns the internal ipv4 address of this node
pub async fn get_internal_ipv4() -> Option<IpAddr> {
    let socket = citadel_io::tokio::net::UdpSocket::bind(addr("0.0.0.0:0")?)
        .await
        .ok()?;
    socket.connect(addr("8.8.8.8:80")?).await.ok()?;
    socket.local_addr().ok().map(|sck| sck.ip())
}

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

fn addr(addr: &str) -> Option<std::net::SocketAddr> {
    std::net::SocketAddr::from_str(addr).ok()
}

/// Returns a default client
pub fn get_default_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
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
