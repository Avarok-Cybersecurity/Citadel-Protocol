//! The client ↔ TURN-server leg: UDP datagrams, or TCP / TLS byte streams re-framed into whole
//! STUN / ChannelData messages (RFC 8656 §12.5). Both directions are pumped by background tasks so
//! the allocation logic sees one datagram-shaped interface whatever the transport.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use citadel_io::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use citadel_io::tokio::net::{TcpStream, UdpSocket};
use citadel_io::tokio::sync::mpsc;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use super::codec::stream_frame_len;
use super::config::{TurnTransport, TurnUrl};
use crate::udp_traversal::abort_on_drop::AbortOnDrop;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Frames buffered between the socket and the allocation driver, per direction.
pub(crate) const LINK_QUEUE_FRAMES: usize = 2048;
/// Largest frame the server can send: STUN/ChannelData length fields are 16-bit.
const MAX_FRAME: usize = 4 + u16::MAX as usize + 3;

/// One connected client ↔ server leg. Dropping it closes the connection.
pub(crate) struct Link {
    pub out: mpsc::Sender<Vec<u8>>,
    pub server_addr: SocketAddr,
    pub local_addr: SocketAddr,
    /// TCP/TLS: ChannelData must be padded to 4 bytes and a lost request is never retransmitted.
    pub is_stream: bool,
    _tasks: [AbortOnDrop<()>; 2],
}

/// Frames received from the server, in order.
pub(crate) type LinkInbound = mpsc::Receiver<Vec<u8>>;

/// `tls` is the root-verifying client config used for `turns:` URLs; SNI is the URL host.
pub(crate) async fn connect(
    url: &TurnUrl,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> io::Result<(Link, LinkInbound)> {
    let server_addr = resolve(url).await?;
    let timeout = |e| io::Error::new(io::ErrorKind::TimedOut, format!("TURN connect: {e}"));
    match url.transport {
        TurnTransport::Udp => {
            let bind: SocketAddr = if server_addr.is_ipv4() {
                "0.0.0.0:0".parse().expect("static")
            } else {
                "[::]:0".parse().expect("static")
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            socket.connect(server_addr).await?;
            let local_addr = socket.local_addr()?;
            let (out, out_rx) = mpsc::channel(LINK_QUEUE_FRAMES);
            let (in_tx, inbound) = mpsc::channel(LINK_QUEUE_FRAMES);
            let tasks = [
                AbortOnDrop::spawn(udp_writer(socket.clone(), out_rx)),
                AbortOnDrop::spawn(udp_reader(socket, in_tx)),
            ];
            let link = Link {
                out,
                server_addr,
                local_addr,
                is_stream: false,
                _tasks: tasks,
            };
            Ok((link, inbound))
        }
        TurnTransport::Tcp | TurnTransport::Tls => {
            let tcp =
                citadel_io::tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr))
                    .await
                    .map_err(timeout)??;
            tcp.set_nodelay(true)?;
            let local_addr = tcp.local_addr()?;
            if url.transport == TurnTransport::Tcp {
                return Ok(stream_link(tcp, server_addr, local_addr));
            }
            let tls = tls.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "turns: URL requires a TLS client config",
                )
            })?;
            let name = ServerName::try_from(url.host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let stream = citadel_io::tokio::time::timeout(
                CONNECT_TIMEOUT,
                TlsConnector::from(tls).connect(name, tcp),
            )
            .await
            .map_err(timeout)??;
            Ok(stream_link(stream, server_addr, local_addr))
        }
    }
}

async fn resolve(url: &TurnUrl) -> io::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = citadel_io::tokio::net::lookup_host((url.host.as_str(), url.port))
        .await?
        .collect();
    // Prefer IPv4 for the client leg: it is the family every TURN deployment serves.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TURN host did not resolve"))
}

fn stream_link<S: AsyncRead + AsyncWrite + Send + 'static>(
    stream: S,
    server_addr: SocketAddr,
    local_addr: SocketAddr,
) -> (Link, LinkInbound) {
    let (reader, writer) = citadel_io::tokio::io::split(stream);
    let (out, out_rx) = mpsc::channel(LINK_QUEUE_FRAMES);
    let (in_tx, inbound) = mpsc::channel(LINK_QUEUE_FRAMES);
    let link = Link {
        out,
        server_addr,
        local_addr,
        is_stream: true,
        _tasks: [
            AbortOnDrop::spawn(stream_writer(writer, out_rx)),
            AbortOnDrop::spawn(stream_reader(reader, in_tx)),
        ],
    };
    (link, inbound)
}

async fn udp_writer(socket: Arc<UdpSocket>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if let Err(err) = socket.send(&frame).await {
            log::trace!(target: "citadel", "TURN UDP send failed: {err}");
        }
    }
}

async fn udp_reader(socket: Arc<UdpSocket>, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
            }
            // ICMP port-unreachable surfaces as ConnectionRefused on a connected UDP socket; the
            // allocation driver's timeouts decide whether the server is gone.
            Err(err) => log::trace!(target: "citadel", "TURN UDP recv error: {err}"),
        }
    }
}

async fn stream_writer<W: AsyncWrite>(writer: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut writer = std::pin::pin!(writer);
    while let Some(frame) = rx.recv().await {
        if let Err(err) = writer.write_all(&frame).await {
            log::warn!(target: "citadel", "TURN stream write failed: {err}");
            return;
        }
    }
}

async fn stream_reader<R: AsyncRead>(reader: R, tx: mpsc::Sender<Vec<u8>>) {
    let mut reader = std::pin::pin!(reader);
    loop {
        let mut header = [0u8; 4];
        if let Err(err) = reader.read_exact(&mut header).await {
            log::trace!(target: "citadel", "TURN stream closed: {err}");
            return;
        }
        let len = match stream_frame_len(header) {
            Ok(len) => len,
            Err(err) => {
                log::warn!(target: "citadel", "TURN stream: {err}");
                return;
            }
        };
        let mut frame = vec![0u8; len];
        frame[..4].copy_from_slice(&header);
        if let Err(err) = reader.read_exact(&mut frame[4..]).await {
            log::trace!(target: "citadel", "TURN stream closed mid-frame: {err}");
            return;
        }
        if tx.send(frame).await.is_err() {
            return;
        }
    }
}
