use std::collections::HashMap;
use std::net::SocketAddr;

use futures::prelude::*;
use hyper::Client;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::aio::Gateway;
use crate::common::{messages, parsing, SearchOptions};
use crate::errors::SearchError;

const MAX_RESPONSE_SIZE: usize = 1500;

/// Search for a gateway with the provided options
pub async fn search_gateway(options: SearchOptions) -> Result<Gateway, SearchError> {
    // Create socket for future calls
    let mut socket = UdpSocket::bind(&options.bind_addr).await?;

    send_search_request(&mut socket, options.broadcast_address).await?;

    let search_response = receive_search_response(&mut socket);

    // Receive search response, optionally with a timeout
    let (response_body, from) = match options.timeout {
        Some(t) => timeout(t, search_response).await?,
        None => search_response.await,
    }?;

    let (addr, root_url) = handle_broadcast_resp(&from, &response_body)?;

    let (control_schema_url, control_url) = get_control_urls(&addr, &root_url).await?;
    let control_schema = get_control_schemas(&addr, &control_schema_url).await?;

    let addr = match addr {
        SocketAddr::V4(a) => Ok(a),
        _ => {
            warn!("unsupported IPv6 gateway response from addr: {}", addr);
            Err(SearchError::InvalidResponse)
        }
    }?;

    Ok(Gateway {
        addr,
        root_url,
        control_url,
        control_schema_url,
        control_schema,
    })
}

// Create a new search
async fn send_search_request(socket: &mut UdpSocket, addr: SocketAddr) -> Result<(), SearchError> {
    debug!(
        "sending broadcast request to: {} on interface: {:?}",
        addr,
        socket.local_addr()
    );
    socket
        .send_to(messages::SEARCH_REQUEST.as_bytes(), &addr)
        .map_ok(|_| ())
        .map_err(|e| SearchError::from(e))
        .await
}

async fn receive_search_response(socket: &mut UdpSocket) -> Result<(Vec<u8>, SocketAddr), SearchError> {
    let mut buff = [0u8; MAX_RESPONSE_SIZE];
    let (n, from) = socket.recv_from(&mut buff).map_err(|e| SearchError::from(e)).await?;
    debug!("received broadcast response from: {}", from);
    Ok((buff[..n].to_vec(), from))
}

// Handle a UDP response message
fn handle_broadcast_resp(from: &SocketAddr, data: &[u8]) -> Result<(SocketAddr, String), SearchError> {
    debug!("handling broadcast response from: {}", from);

    // Convert response to text
    let text = std::str::from_utf8(&data).map_err(|e| SearchError::from(e))?;

    // Parse socket address and path
    let (addr, root_url) = parsing::parse_search_result(text)?;

    Ok((SocketAddr::V4(addr), root_url))
}

async fn get_control_urls(addr: &SocketAddr, path: &String) -> Result<(String, String), SearchError> {
    let uri = match format!("http://{}{}", addr, path).parse() {
        Ok(uri) => uri,
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control url from: {}", uri);
    let client = Client::new();
    let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
        .map_err(|e| SearchError::from(e))
        .await?;

    debug!("handling control response from: {}", addr);
    let c = std::io::Cursor::new(&resp);
    parsing::parse_control_urls(c)
}

async fn get_control_schemas(
    addr: &SocketAddr,
    control_schema_url: &String,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let uri = match format!("http://{}{}", addr, control_schema_url).parse() {
        Ok(uri) => uri,
        Err(err) => return Err(SearchError::from(err)),
    };

    debug!("requesting control schema from: {}", uri);
    let client = Client::new();
    let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
        .map_err(|e| SearchError::from(e))
        .await?;

    debug!("handling schema response from: {}", addr);
    let c = std::io::Cursor::new(&resp);
    parsing::parse_schemas(c)
}
