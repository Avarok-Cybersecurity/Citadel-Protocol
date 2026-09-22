//! Native client dial of a Citadel server by WebSocket URL (`ws://` / `wss://`).

use std::io;
use std::sync::Arc;

use citadel_wire::exports::tokio_rustls::rustls::pki_types;
use citadel_wire::tls::client_config_to_tls_connector;

use crate::constants::TCP_CONN_TIMEOUT;
use crate::proto::misc::native_io::NativeClientConfig;
use crate::proto::misc::native_websocket::{WebSocketByteStream, WsTransport};
use crate::proto::misc::net::GenericNetworkStream;
use crate::proto::packet_processor::includes::Duration;
use crate::proto::peer::p2p_conn_handler::generic_error;

/// Connect to a Citadel server reached by a WebSocket URL.
///
/// No `FirstPacket` is read: the server's WebSocket listener sends none (the HTTP upgrade is the
/// negotiation), which is also what the wasm client does. For `wss://` the TLS handshake presents
/// the URL's host as SNI and verifies the edge's certificate with the node's client config — the
/// native roots by default, or the accept-any verifier under `insecure_skip_cert_verification`.
/// There is no downgrade: nothing the server sends can switch verification off.
pub async fn c2s_connect_endpoint(
    timeout: Option<Duration>,
    endpoint: &citadel_io::WebSocketEndpoint,
    client_config: &NativeClientConfig,
) -> io::Result<GenericNetworkStream> {
    citadel_io::time::timeout(
        timeout.unwrap_or(TCP_CONN_TIMEOUT),
        dial_endpoint(endpoint, client_config),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out connecting to {endpoint}"),
        )
    })?
}

async fn dial_endpoint(
    endpoint: &citadel_io::WebSocketEndpoint,
    client_config: &NativeClientConfig,
) -> io::Result<GenericNetworkStream> {
    let host = endpoint.host();
    log::trace!(target: "citadel", "C2S WebSocket connect to {endpoint}");
    let tcp = citadel_io::tokio::net::TcpStream::connect((host.as_str(), endpoint.port())).await?;
    tcp.set_nodelay(true)?;
    let peer_addr = tcp.peer_addr()?;
    let local_addr = tcp.local_addr()?;

    let transport = if endpoint.is_secure() {
        // The edge speaks HTTP; offer only HTTP/1.1, the one version a WebSocket upgrade runs on.
        let mut tls_config = (*client_config.config).clone();
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = pki_types::ServerName::try_from(host.clone())
            .map_err(|err| generic_error(format!("invalid TLS server name {host:?}: {err}")))?;
        let tls = client_config_to_tls_connector(Arc::new(tls_config))
            .connect(server_name, tcp)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err))?;
        WsTransport::ClientTls(Box::new(tls))
    } else {
        WsTransport::Plain(tcp)
    };

    let (ws, _response) = tokio_tungstenite::client_async(endpoint.as_str(), transport)
        .await
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("WebSocket upgrade to {endpoint} failed: {err}"),
            )
        })?;
    Ok(GenericNetworkStream::WebSocket(Box::new(
        WebSocketByteStream::new(ws, peer_addr, local_addr),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use citadel_io::tokio::net::TcpListener;
    use citadel_io::WebSocketEndpoint;
    use futures::{SinkExt, StreamExt};
    use std::sync::Mutex;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    /// What the server saw of the client's handshake.
    #[derive(Default, Debug)]
    struct Seen {
        sni: Option<String>,
        host: Option<String>,
        path: Option<String>,
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        citadel_io::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// A TLS-terminating WebSocket echo server with a self-signed certificate, standing in for an
    /// HTTP edge. It echoes one binary frame.
    async fn wss_echo_server() -> (
        u16,
        citadel_io::tokio::task::JoinHandle<Result<Seen, String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = citadel_wire::tls::create_server_self_signed_config()
            .unwrap()
            .tls_acceptor;
        let handle = citadel_io::tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
            let seen = Arc::new(Mutex::new(Seen {
                sni: tls.get_ref().1.server_name().map(str::to_string),
                ..Default::default()
            }));
            let seen_in_handshake = seen.clone();
            #[allow(clippy::result_large_err)] // tungstenite's callback signature, not ours
            let mut ws =
                tokio_tungstenite::accept_hdr_async(tls, move |req: &Request, resp: Response| {
                    let mut seen = seen_in_handshake.lock().unwrap();
                    seen.host = req
                        .headers()
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .map(str::to_string);
                    seen.path = Some(req.uri().path().to_string());
                    Ok(resp)
                })
                .await
                .map_err(|e| e.to_string())?;
            let frame = ws
                .next()
                .await
                .ok_or("no frame")?
                .map_err(|e| e.to_string())?;
            ws.send(frame).await.map_err(|e| e.to_string())?;
            let seen = std::mem::take(&mut *seen.lock().unwrap());
            Ok(seen)
        });
        (port, handle)
    }

    #[test]
    fn wss_presents_the_url_host_as_sni_and_host_header() {
        run(async {
            let (port, server) = wss_echo_server().await;
            let endpoint =
                WebSocketEndpoint::parse(&format!("wss://localhost:{port}/acme")).unwrap();
            let skip_verify = NativeClientConfig::new(Arc::new(
                citadel_wire::quic::insecure::rustls_client_config(),
            ));

            let mut stream = c2s_connect_endpoint(None, &endpoint, &skip_verify)
                .await
                .expect("wss dial with verification skipped");
            assert!(matches!(stream, GenericNetworkStream::WebSocket(..)));
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = [0u8; 4];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"ping");

            let seen = server.await.unwrap().expect("server side");
            assert_eq!(seen.sni.as_deref(), Some("localhost"));
            assert_eq!(seen.host, Some(format!("localhost:{port}")));
            assert_eq!(seen.path.as_deref(), Some("/acme"));
        });
    }

    #[test]
    fn wss_verifies_the_edge_certificate_unless_told_not_to() {
        run(async {
            let (port, server) = wss_echo_server().await;
            let endpoint =
                WebSocketEndpoint::parse(&format!("wss://localhost:{port}/acme")).unwrap();
            let native_roots = citadel_wire::tls::load_native_certs_async().await.unwrap();
            let verifying = NativeClientConfig::new(Arc::new(
                citadel_wire::tls::create_rustls_client_config(&native_roots).unwrap(),
            ));

            let refused = c2s_connect_endpoint(None, &endpoint, &verifying).await;
            assert!(
                refused.is_err(),
                "a self-signed edge must be refused under the native roots"
            );
            assert!(server.await.unwrap().is_err());
        });
    }
}
