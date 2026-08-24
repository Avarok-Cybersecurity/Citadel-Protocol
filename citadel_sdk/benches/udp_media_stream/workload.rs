//! Transport-agnostic workload shared by every arm of the `udp_media_stream` bench: fragment
//! layout, pacing, and the receiver-side statistics (loss / reorder / one-way latency).

use bytes::{BufMut, BytesMut};
use citadel_io::tokio;
use futures::{Stream, StreamExt};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fragment layout: `[u64 BE send-nanos since epoch | u64 BE sequence | filler]`.
pub const STAMP_LEN: usize = 16;

/// Receiver gives up once the sender has finished and nothing arrived for this long. 1 s is far
/// above any loopback delivery delay, so a timeout here means the packets are genuinely lost.
pub const RECV_IDLE: Duration = Duration::from_secs(1);

/// One sender/receiver run. `epoch` is shared by both sides (same process) so one-way latency is
/// `recv_instant - send_instant` with no clock sync needed.
#[derive(Clone, Copy)]
pub struct Params {
    pub frags: usize,
    pub frag_bytes: usize,
    pub rate_pps: usize,
    pub epoch: Instant,
}

impl Params {
    pub fn fragment(&self, seq: u64) -> BytesMut {
        let mut b = BytesMut::with_capacity(self.frag_bytes);
        b.put_u64(self.epoch.elapsed().as_nanos() as u64);
        b.put_u64(seq);
        b.put_bytes(0xAB, self.frag_bytes - STAMP_LEN);
        b
    }
}

#[derive(Clone, Debug)]
pub struct ArmResult {
    pub name: &'static str,
    pub sent: usize,
    pub received: usize,
    pub loss_pct: f64,
    pub reorder_pct: f64,
    pub pps: f64,
    pub mbps: f64,
    pub p50_us: f64,
    pub p99_us: f64,
}

/// A unidirectional datagram sink. `send` must never block the caller indefinitely on loss — a
/// full buffer is the transport's drop policy and shows up as loss in the result.
pub trait DatagramTx {
    fn send(&mut self, pkt: BytesMut) -> impl Future<Output = Result<(), String>> + Send;
}

/// Paces `send` to `rate_pps` when non-zero (sleeps when >1 ms ahead of schedule, yields otherwise
/// — tokio's timer granularity is ~1 ms, far coarser than the inter-packet gap at media rates).
pub async fn run_sender<S: DatagramTx>(
    p: Params,
    tx: &mut S,
    done: Arc<AtomicBool>,
) -> Result<usize, String> {
    let t0 = Instant::now();
    for seq in 0..p.frags {
        if p.rate_pps > 0 {
            let due = t0 + Duration::from_secs_f64(seq as f64 / p.rate_pps as f64);
            loop {
                let now = Instant::now();
                if now >= due {
                    break;
                }
                if due - now > Duration::from_millis(1) {
                    tokio::time::sleep_until(due.into()).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        }
        tx.send(p.fragment(seq as u64)).await?;
    }
    done.store(true, Ordering::SeqCst);
    Ok(p.frags)
}

/// Drains `rx` until every fragment arrived or the sender is done and `RECV_IDLE` passes idle.
pub async fn run_receiver<B: AsRef<[u8]>>(
    name: &'static str,
    p: Params,
    mut rx: impl Stream<Item = B> + Unpin,
    sender_done: Arc<AtomicBool>,
) -> ArmResult {
    let mut lat_ns: Vec<u64> = Vec::with_capacity(p.frags);
    let mut max_seq: Option<u64> = None;
    let mut reordered = 0usize;
    let mut first: Option<Instant> = None;
    let mut last = Instant::now();
    while lat_ns.len() < p.frags {
        let pkt = match tokio::time::timeout(RECV_IDLE, rx.next()).await {
            Ok(Some(pkt)) => pkt,
            Ok(None) => break,
            Err(_) if sender_done.load(Ordering::SeqCst) => break,
            Err(_) => continue,
        };
        let bytes = pkt.as_ref();
        assert_eq!(bytes.len(), p.frag_bytes, "[{name}] fragment size mismatch");
        let now = Instant::now();
        first.get_or_insert(now);
        last = now;
        let sent = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let seq = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let recv = p.epoch.elapsed().as_nanos() as u64;
        lat_ns.push(recv.saturating_sub(sent));
        match max_seq {
            Some(m) if seq < m => reordered += 1,
            Some(m) if seq > m => max_seq = Some(seq),
            Some(_) => {}
            None => max_seq = Some(seq),
        }
    }
    summarize(name, p, lat_ns, reordered, first, last)
}

fn summarize(
    name: &'static str,
    p: Params,
    mut lat_ns: Vec<u64>,
    reordered: usize,
    first: Option<Instant>,
    last: Instant,
) -> ArmResult {
    let received = lat_ns.len();
    let elapsed = first.map(|f| (last - f).as_secs_f64()).unwrap_or(0.0);
    let rate = |n: f64| if elapsed > 0.0 { n / elapsed } else { 0.0 };
    lat_ns.sort_unstable();
    let pct = |q: f64| -> f64 {
        if lat_ns.is_empty() {
            return 0.0;
        }
        let i = ((q * (lat_ns.len() as f64 - 1.0)).round() as usize).min(lat_ns.len() - 1);
        lat_ns[i] as f64 / 1e3
    };
    let frac = |n: usize, d: usize| {
        if d > 0 {
            100.0 * n as f64 / d as f64
        } else {
            0.0
        }
    };
    ArmResult {
        name,
        sent: p.frags,
        received,
        loss_pct: frac(p.frags - received, p.frags),
        reorder_pct: frac(reordered, received),
        pps: rate(received as f64),
        mbps: rate((received * p.frag_bytes) as f64) / 1e6,
        p50_us: pct(0.50),
        p99_us: pct(0.99),
    }
}
