//! Shared allocation state and the two background loops that keep an allocation alive: the
//! inbound demultiplexer (responses → waiting requests, ChannelData / Data indications → the
//! relayed-datagram queue) and the maintenance timer (Refresh, CreatePermission, ChannelBind
//! renewal before their RFC 8656 lifetimes lapse).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use citadel_io::tokio::sync::{mpsc, oneshot};
use stun::attributes::ATTR_XOR_PEER_ADDRESS;
use stun::message::Message;

use super::codec::{self, Attr, Inbound, LongTermAuth, TransactionId};

/// RFC 8656 §9: permissions last 300 s; renew with margin.
const PERMISSION_REFRESH: Duration = Duration::from_secs(240);
/// RFC 8656 §12: channel bindings last 600 s; renew with margin.
const CHANNEL_REFRESH: Duration = Duration::from_secs(480);
/// Refreshing an allocation this early before expiry tolerates a lost request on UDP.
const MIN_ALLOCATION_REFRESH: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct PeerTable {
    pub by_addr: HashMap<SocketAddr, u16>,
    pub by_channel: HashMap<u16, SocketAddr>,
    pub permitted: HashSet<IpAddr>,
    pub next_channel: u16,
}

pub(crate) struct Shared {
    pub out: mpsc::Sender<Vec<u8>>,
    pub is_stream: bool,
    pub pending: citadel_io::Mutex<HashMap<[u8; 12], oneshot::Sender<Message>>>,
    pub auth: citadel_io::Mutex<Option<LongTermAuth>>,
    pub peers: citadel_io::RwLock<PeerTable>,
    pub alive: AtomicBool,
    /// Relayed datagrams dropped because the consumer fell behind (UDP semantics: shed, never block).
    pub dropped_inbound: AtomicU64,
}

impl Shared {
    pub fn new(out: mpsc::Sender<Vec<u8>>, is_stream: bool) -> Self {
        Self {
            out,
            is_stream,
            pending: citadel_io::Mutex::new(HashMap::new()),
            auth: citadel_io::Mutex::new(None),
            peers: citadel_io::RwLock::new(PeerTable {
                next_channel: codec::CHANNEL_MIN,
                ..Default::default()
            }),
            alive: AtomicBool::new(true),
            dropped_inbound: AtomicU64::new(0),
        }
    }
}

/// Routes every frame the server sends until the link closes.
pub(crate) async fn demultiplex(
    shared: Arc<Shared>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) {
    while let Some(frame) = inbound.recv().await {
        let delivered = match codec::classify(&frame) {
            Ok(Inbound::ChannelData { channel, payload }) => {
                let peer = shared.peers.read().by_channel.get(&channel).copied();
                peer.map(|peer| (peer, payload.to_vec()))
            }
            Ok(Inbound::Stun) => on_stun(&shared, &frame),
            Err(err) => {
                log::trace!(target: "citadel", "TURN: dropping undecodable frame: {err}");
                None
            }
        };
        if let Some(datagram) = delivered {
            if data_tx.try_send(datagram).is_err() {
                shared.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    log::warn!(target: "citadel", "TURN: link to server closed");
    shared.alive.store(false, Ordering::SeqCst);
    // Dropping every waiter fails their requests immediately instead of at their timeouts.
    shared.pending.lock().clear();
}

fn on_stun(shared: &Shared, frame: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    let m = codec::parse(frame).ok()?;
    if codec::check_fingerprint_if_present(&m).is_err() {
        log::trace!(target: "citadel", "TURN: dropping message with a bad FINGERPRINT");
        return None;
    }
    let class = m.typ.class;
    if class == codec::CLASS_SUCCESS_RESPONSE || class == codec::CLASS_ERROR_RESPONSE {
        if let Some(waiter) = shared.pending.lock().remove(&m.transaction_id.0) {
            let _ = waiter.send(m);
        }
        return None;
    }
    if class == codec::CLASS_INDICATION && m.typ.method == codec::METHOD_DATA {
        let peer = codec::xor_address(&m, ATTR_XOR_PEER_ADDRESS)?;
        return Some((peer, codec::data(&m)?));
    }
    None
}

pub(crate) fn allocation_refresh_period(lifetime: Duration) -> Duration {
    (lifetime / 2).max(MIN_ALLOCATION_REFRESH)
}

/// Periodic renewals. Each is an authenticated transaction; failures are logged and retried at
/// the next period (a lapsed allocation surfaces to the user as a dead QUIC path).
pub(crate) async fn maintain<F, Fut>(shared: Arc<Shared>, lifetime: Duration, transact: F)
where
    F: Fn(codec::Method, Vec<Attr>) -> Fut,
    Fut: std::future::Future<Output = io::Result<Message>>,
{
    let mut alloc = citadel_io::tokio::time::interval(allocation_refresh_period(lifetime));
    let mut perms = citadel_io::tokio::time::interval(PERMISSION_REFRESH);
    let mut chans = citadel_io::tokio::time::interval(CHANNEL_REFRESH);
    // The first tick of a tokio interval is immediate; everything was just installed.
    alloc.tick().await;
    perms.tick().await;
    chans.tick().await;
    while shared.alive.load(Ordering::SeqCst) {
        let work: Vec<(codec::Method, Vec<Attr>)> = citadel_io::tokio::select! {
            _ = alloc.tick() => vec![(codec::METHOD_REFRESH, vec![Attr::Lifetime(lifetime)])],
            _ = perms.tick() => {
                let ips: Vec<IpAddr> = shared.peers.read().permitted.iter().copied().collect();
                if ips.is_empty() { vec![] } else {
                    vec![(codec::METHOD_CREATE_PERMISSION, permission_attrs(&ips))]
                }
            }
            _ = chans.tick() => shared.peers.read().by_channel.iter()
                .map(|(n, peer)| (codec::METHOD_CHANNEL_BIND,
                    vec![Attr::ChannelNumber(*n), Attr::XorPeerAddress(*peer)]))
                .collect(),
        };
        for (method, attrs) in work {
            if let Err(err) = transact(method, attrs).await {
                log::warn!(target: "citadel", "TURN renewal ({method}) failed: {err}");
            }
        }
    }
}

pub(crate) fn permission_attrs(ips: &[IpAddr]) -> Vec<Attr> {
    ips.iter()
        .map(|ip| Attr::XorPeerAddress(SocketAddr::new(*ip, 0)))
        .collect()
}

pub(crate) fn new_transaction() -> TransactionId {
    TransactionId::new()
}
