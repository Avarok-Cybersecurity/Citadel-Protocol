//! A TURN allocation (RFC 8656): Allocate with long-term credentials, then CreatePermission,
//! ChannelBind and relayed send/receive, with renewals running in the background.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use citadel_io::tokio::sync::mpsc;
use stun::attributes::{ATTR_NONCE, ATTR_REALM, ATTR_XORMAPPED_ADDRESS, ATTR_XOR_RELAYED_ADDRESS};

use super::codec::{self, Attr, LongTermAuth};
use super::config::{TurnServerCredential, TurnTransport};
use super::driver::{self, Shared};
use super::transaction::{invalid, request, transact, turn_error};
use super::transport::{self, LINK_QUEUE_FRAMES};
use crate::udp_traversal::abort_on_drop::AbortOnDrop;

/// A live relayed-transport address on a TURN server. Dropping it releases the allocation.
pub struct TurnAllocation {
    shared: Arc<Shared>,
    relayed_addr: SocketAddr,
    mapped_addr: SocketAddr,
    server_addr: SocketAddr,
    transport: TurnTransport,
    data_rx: citadel_io::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    tasks: Option<(transport::Link, AbortOnDrop<()>, AbortOnDrop<()>)>,
}

impl std::fmt::Debug for TurnAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnAllocation")
            .field("relayed_addr", &self.relayed_addr)
            .field("server_addr", &self.server_addr)
            .field("transport", &self.transport)
            .finish()
    }
}

impl TurnAllocation {
    /// Connects to `server` and allocates a UDP relay. `tls` must be `Some` for `turns:` URLs.
    pub async fn allocate(
        server: &TurnServerCredential,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> io::Result<Self> {
        let (link, inbound) = transport::connect(&server.url, tls).await?;
        let shared = Arc::new(Shared::new(link.out.clone(), link.is_stream));
        let (data_tx, data_rx) = mpsc::channel(LINK_QUEUE_FRAMES);
        let demux = AbortOnDrop::spawn(driver::demultiplex(shared.clone(), inbound, data_tx));

        // RFC 8656 §7.2: the first Allocate is unauthenticated; its 401 carries REALM and NONCE.
        let alloc_attrs = [Attr::RequestedTransportUdp];
        let first = request(&shared, codec::METHOD_ALLOCATE, &alloc_attrs, None).await?;
        let response = if first.typ.class == codec::CLASS_SUCCESS_RESPONSE {
            first
        } else {
            let (code, reason) = codec::error_code(&first).unwrap_or((0, String::new()));
            let (Some(realm), Some(nonce)) = (
                codec::text(&first, ATTR_REALM),
                codec::text(&first, ATTR_NONCE),
            ) else {
                return Err(turn_error("Allocate", code, &reason));
            };
            *shared.auth.lock() = Some(LongTermAuth::new(
                &server.username,
                &server.credential,
                realm,
                nonce,
            ));
            transact(&shared, codec::METHOD_ALLOCATE, &alloc_attrs).await?
        };
        let relayed_addr = codec::xor_address(&response, ATTR_XOR_RELAYED_ADDRESS)
            .ok_or_else(|| invalid("Allocate success without XOR-RELAYED-ADDRESS"))?;
        let mapped_addr = codec::xor_address(&response, ATTR_XORMAPPED_ADDRESS)
            .ok_or_else(|| invalid("Allocate success without XOR-MAPPED-ADDRESS"))?;
        let lifetime = codec::lifetime(&response)
            .ok_or_else(|| invalid("Allocate success without LIFETIME"))?;
        let maint_shared = shared.clone();
        let maintenance = AbortOnDrop::spawn(driver::maintain(
            shared.clone(),
            lifetime,
            move |method, attrs| {
                let shared = maint_shared.clone();
                async move { transact(&shared, method, &attrs).await }
            },
        ));
        log::info!(target: "citadel", "TURN allocation {relayed_addr} on {} via {:?} (lifetime {lifetime:?})", link.server_addr, server.url.transport);
        Ok(Self {
            shared,
            relayed_addr,
            mapped_addr,
            server_addr: link.server_addr,
            transport: server.url.transport,
            data_rx: citadel_io::Mutex::new(data_rx),
            tasks: Some((link, demux, maintenance)),
        })
    }

    /// The address peers send to; the server forwards what arrives from permitted IPs.
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    /// This client's address as the TURN server sees it (server-reflexive).
    pub fn mapped_addr(&self) -> SocketAddr {
        self.mapped_addr
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// The local end of the client ↔ server leg.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.tasks.as_ref().map(|(link, ..)| link.local_addr)
    }

    pub fn transport(&self) -> TurnTransport {
        self.transport
    }

    pub fn is_alive(&self) -> bool {
        self.shared.alive.load(Ordering::SeqCst)
    }

    /// Relayed datagrams shed because they were not consumed fast enough.
    pub fn dropped_inbound(&self) -> u64 {
        self.shared.dropped_inbound.load(Ordering::Relaxed)
    }

    /// Installs permissions (IP-only, RFC 8656 §9) so the server forwards traffic from `ips`.
    pub async fn create_permissions(&self, ips: &[IpAddr]) -> io::Result<()> {
        if ips.is_empty() {
            return Err(invalid("CreatePermission needs at least one peer address"));
        }
        let attrs = driver::permission_attrs(ips);
        transact(&self.shared, codec::METHOD_CREATE_PERMISSION, &attrs).await?;
        self.shared
            .peers
            .write()
            .permitted
            .extend(ips.iter().copied());
        Ok(())
    }

    /// Binds a channel to `peer` (also installing its permission); later datagrams to and from
    /// it use the 4-byte ChannelData framing. Idempotent per peer.
    pub async fn bind_channel(&self, peer: SocketAddr) -> io::Result<u16> {
        let channel = {
            let mut peers = self.shared.peers.write();
            if let Some(n) = peers.by_addr.get(&peer) {
                return Ok(*n);
            }
            if peers.next_channel > codec::CHANNEL_MAX {
                return Err(invalid("TURN channel numbers exhausted"));
            }
            peers.next_channel += 1;
            peers.next_channel - 1
        };
        // Inbound mapping first: the peer's first ChannelData may overtake the success response.
        self.shared.peers.write().by_channel.insert(channel, peer);
        let attrs = [Attr::ChannelNumber(channel), Attr::XorPeerAddress(peer)];
        if let Err(err) = transact(&self.shared, codec::METHOD_CHANNEL_BIND, &attrs).await {
            self.shared.peers.write().by_channel.remove(&channel);
            return Err(err);
        }
        let mut peers = self.shared.peers.write();
        peers.by_addr.insert(peer, channel);
        peers.permitted.insert(peer.ip());
        Ok(channel)
    }

    /// Relays `payload` to `peer` without blocking: ChannelData when a channel is bound, else a
    /// Send indication. A full outbound queue sheds the datagram, as a congested socket would.
    pub fn send_to(&self, peer: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let frame = {
            let peers = self.shared.peers.read();
            if let Some(channel) = peers.by_addr.get(&peer) {
                codec::encode_channel_data(*channel, payload, self.shared.is_stream)?
            } else if peers.permitted.contains(&peer.ip()) {
                codec::build(
                    codec::METHOD_SEND,
                    codec::CLASS_INDICATION,
                    driver::new_transaction(),
                    &[Attr::XorPeerAddress(peer), Attr::Data(payload.to_vec())],
                    None,
                    false,
                )?
                .raw
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("no TURN permission for {peer}"),
                ));
            }
        };
        match self.shared.out.try_send(frame) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TURN link closed",
            )),
        }
    }

    /// Polls for the next relayed datagram (source peer, payload).
    pub fn poll_recv_from(&self, cx: &mut Context<'_>) -> Poll<io::Result<(SocketAddr, Vec<u8>)>> {
        match self.data_rx.lock().poll_recv(cx) {
            Poll::Ready(Some(d)) => Poll::Ready(Ok(d)),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TURN allocation closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn try_recv_from(&self) -> Option<(SocketAddr, Vec<u8>)> {
        self.data_rx.lock().try_recv().ok()
    }

    pub async fn recv_from(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
        std::future::poll_fn(|cx| self.poll_recv_from(cx)).await
    }
}

impl Drop for TurnAllocation {
    /// Releases the allocation (Refresh with LIFETIME 0, RFC 8656 §8) instead of leaving it to
    /// expire on the server, then tears the link down.
    fn drop(&mut self) {
        let Some(tasks) = self.tasks.take() else {
            return;
        };
        let shared = self.shared.clone();
        if let Ok(rt) = citadel_io::tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let attrs = [Attr::Lifetime(Duration::ZERO)];
                let release = transact(&shared, codec::METHOD_REFRESH, &attrs);
                let _ = citadel_io::tokio::time::timeout(Duration::from_secs(2), release).await;
                drop(tasks);
            });
        }
    }
}
